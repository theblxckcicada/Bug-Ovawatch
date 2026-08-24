"""
scan_engine.py — deterministic phase orchestration for ShadowGrid scans.

Design goals:
  - A phase is not allowed to start until the previous phase has fully drained.
  - Every selected tool reaches a terminal state: done, error, or skipped.
  - Phase hand-off artifacts are written before dependent phases start.
  - Progress is emitted over SSE and persisted on the Scan object so reconnects
    can replay recent state instead of leaving the frontend blind.
"""
from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from models import Scan, ScanProgress, ScanStatus, ToolCategory, ToolResult
from storage.base import BaseStorage
from tools.registry import get_tool
from tool_secrets import apply_tool_api_keys
from scope import scan_workspace, scope_fingerprint
from config import settings
from inventory import build_inventory

logger = logging.getLogger(__name__)

# scan_id → asyncio.Queue of SSE event dicts
_progress_queues: dict[str, asyncio.Queue] = {}

# scan_id → {(domain, tool): ToolResult} reused from a prior scan when resuming.
_reuse_maps: dict[str, dict[tuple[str, str], ToolResult]] = {}

# Global cap across every concurrently running assessment. This prevents several
# scans from each launching a full phase worth of expensive network tools.
_tool_semaphore = asyncio.Semaphore(max(1, settings.max_concurrent_tool_groups))

PHASES: list[dict[str, object]] = [
    {"index": 1, "name": "Asset Discovery", "tools": ["whois", "asnmap", "shodan", "email_finder"]},
    {"index": 2, "name": "Subdomain Enumeration", "tools": ["crtsh", "assetfinder", "subfinder", "amass", "shuffledns"]},
    {"index": 3, "name": "DNS Resolution", "tools": ["dnsx", "dns_records", "zone_transfer"]},
    {"index": 4, "name": "HTTP, TLS & Port Validation", "tools": ["httpx", "tlsx", "naabu"]},
    {"index": 5, "name": "URL Discovery", "tools": ["waybackurls", "gau", "katana", "urlfinder", "ffuf"]},
    {"index": 6, "name": "Vulnerability Scan, Takeovers, Screenshots, Dorks & AI", "tools": ["google_dorks", "nuclei", "cve_check", "subdomain_takeover", "wpscan", "gowitness", "whatweb", "wafw00f", "secret_exposure", "web_posture", "ai_analysis"]},
]

SUBDOMAIN_FILES = (
    "crtsh.txt",
    "assetfinder.txt",
    "subfinder.txt",
    "amass.txt",
    "shuffledns.txt",
)

DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)


def get_progress_queue(scan_id: str) -> asyncio.Queue:
    if scan_id not in _progress_queues:
        _progress_queues[scan_id] = asyncio.Queue(maxsize=1000)
    return _progress_queues[scan_id]


def drop_progress_queue(scan_id: str) -> None:
    _progress_queues.pop(scan_id, None)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _selected_tools(scan: Scan, phase: dict[str, object]) -> list[str]:
    requested = set(scan.tools or [])
    return [t for t in phase["tools"] if t in requested]  # type: ignore[index]


async def _emit(
    scan: Scan,
    storage: BaseStorage,
    tool: str,
    status: str,
    message: str = "",
    count: int = 0,
    *,
    domain: str = "",
    phase: str = "",
    phase_index: int = 0,
    phase_total: int = len(PHASES),
    completed_tools: int = 0,
    total_tools: int = 0,
    overall_completed_tools: int = 0,
    overall_total_tools: int = 0,
    persist: bool = True,
) -> None:
    """Emit one progress event to SSE and persist it on the Scan record."""
    event = {
        "tool": tool,
        "status": status,
        "message": message,
        "count": count,
        "ts": _now_iso(),
        "domain": domain,
        "phase": phase,
        "phase_index": phase_index,
        "phase_total": phase_total,
        "completed_tools": completed_tools,
        "total_tools": total_tools,
        "overall_completed_tools": overall_completed_tools,
        "overall_total_tools": overall_total_tools,
    }

    q = get_progress_queue(scan.id)
    try:
        q.put_nowait(event)
    except asyncio.QueueFull:
        # Drop the oldest event and keep the newest state flowing.
        try:
            _ = q.get_nowait()
            q.put_nowait(event)
        except Exception:
            pass

    if persist:
        try:
            scan.progress.append(ScanProgress(**event))
            # Keep JSON scan metadata bounded for long multi-domain scans.
            if len(scan.progress) > 1000:
                scan.progress = scan.progress[-1000:]
            await storage.save_scan(scan)
        except Exception:
            logger.exception("Could not persist progress event")

    logger.info("[%s] %s: %s — %s", scan.id, tool, status, message)


async def _scan_cancelled(scan: Scan, storage: BaseStorage) -> bool:
    latest = await storage.get_scan(scan.id)
    return bool(latest and latest.status == ScanStatus.CANCELLED)


async def _build_reuse_map(scan: Scan, storage: BaseStorage) -> dict[tuple[str, str], ToolResult]:
    """Map (domain, tool) → prior successful ToolResult from the project's most recent
    earlier scan, so a resumed scan can continue instead of repeating finished work."""
    reuse: dict[tuple[str, str], ToolResult] = {}
    try:
        prior_scans = [
            s for s in await storage.list_scans(scan.project_id)
            if s.id != scan.id
            and s.status == ScanStatus.COMPLETED
            and s.scope_hash
            and s.scope_hash == scan.scope_hash
        ]
        prior_scans.sort(key=lambda s: s.created_at, reverse=True)
        # Walk newest → oldest; first non-empty result for a (domain, tool) wins.
        if prior_scans:
            previous = prior_scans[0]
            for result in await storage.list_results(previous.id):
                if not result.error:
                    reuse[(result.domain, result.tool)] = result

            if previous.workspace and scan.workspace:
                output_root = Path(storage.output_dir).resolve()
                source = (output_root / previous.workspace).resolve()
                destination = (output_root / scan.workspace).resolve()
                if source.exists() and output_root in source.parents:
                    shutil.copytree(source, destination, dirs_exist_ok=True)
    except Exception:
        logger.exception("Could not build reuse map for scan %s", scan.id)
    return reuse


def _extract_host(value: str) -> str:
    value = (value or "").strip().lower().lstrip("*.")
    if not value:
        return ""

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    else:
        # Strip path/query and then a possible :port suffix.
        value = value.split("/", 1)[0].split("?", 1)[0]
        if value.count(":") == 1:
            value = value.rsplit(":", 1)[0]

    return value.strip().strip(".")


def _host_in_domain(host: str, root_domain: str) -> bool:
    host = _extract_host(host)
    root_domain = _extract_host(root_domain)
    return bool(host and (host == root_domain or host.endswith(f".{root_domain}")))


def _matches_oos(host_or_url: str, oos: Iterable[str]) -> bool:
    host = _extract_host(host_or_url)
    if not host:
        return False

    for raw_pattern in oos:
        pattern = _extract_host(raw_pattern)
        if not pattern:
            continue

        # Preserve wildcard semantics when the original pattern uses them.
        wildcard_pattern = raw_pattern.strip().lower()
        if fnmatch.fnmatch(host, wildcard_pattern):
            return True

        if wildcard_pattern.startswith("*.") and host.endswith(wildcard_pattern[1:]):
            return True

        if host == pattern or host.endswith(f".{pattern}"):
            return True

    return False


def _unique_sorted_hosts(hosts: Iterable[str], root_domain: str, oos: list[str]) -> list[str]:
    clean: set[str] = set()
    for host in hosts:
        h = _extract_host(host)
        if _host_in_domain(h, root_domain) and not _matches_oos(h, oos):
            clean.add(h)
    return sorted(clean)


def _hosts_from_results(results: Iterable[ToolResult | None]) -> list[str]:
    hosts: list[str] = []
    for result in results:
        if not result:
            continue
        for row in result.data or []:
            value = row.get("host") or row.get("domain") or row.get("url") or ""
            if value:
                hosts.append(str(value))
    return hosts


def _hosts_from_files(domain_dir: Path) -> list[str]:
    hosts: list[str] = []
    for filename in SUBDOMAIN_FILES:
        path = domain_dir / filename
        if not path.exists():
            continue
        try:
            for line in path.read_text(errors="replace").splitlines():
                hosts.extend(DOMAIN_RE.findall(line))
        except Exception:
            logger.warning("Could not read subdomain artifact: %s", path)
    return hosts


def _write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines)
    if content:
        content += "\n"
    path.write_text(content)


def _file_sha256(path: Path) -> str:
    """Hash an artifact without loading large screenshots or logs into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_execution_manifest(scan: Scan, workspace: Path, domains: list[str],
                              oos: list[str], results: list[ToolResult]) -> Path:
    """Write an immutable execution/evidence manifest for reproducibility."""
    artifacts = []
    for artifact in sorted(workspace.rglob("*")):
        if not artifact.is_file() or artifact.name == "_manifest.json":
            continue
        artifacts.append({
            "path": artifact.relative_to(workspace).as_posix(),
            "size": artifact.stat().st_size,
            "sha256": _file_sha256(artifact),
        })

    manifest = {
        "schema_version": 1,
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "scope_hash": scan.scope_hash,
        "domains": sorted(domains),
        "out_of_scope": sorted(oos),
        "selected_tools": scan.tools,
        "wordlist": scan.wordlist,
        "verify_emails": scan.verify_emails,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "tool_results": [
            {
                "tool": result.tool,
                "domain": result.domain,
                "category": result.category.value,
                "count": result.count,
                "elapsed_s": result.elapsed_s,
                "error": result.error,
            }
            for result in sorted(results, key=lambda item: (item.domain, item.tool))
        ],
        "artifacts": artifacts,
    }
    manifest_path = workspace / "_manifest.json"
    temporary_path = workspace / "._manifest.json.tmp"
    temporary_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    temporary_path.replace(manifest_path)
    return manifest_path


def _write_merged_subdomains(domain: str, results: list[ToolResult | None], output_dir: Path, oos: list[str]) -> tuple[Path, int]:
    """Merge all subdomain sources into a canonical unique hand-off file."""
    domain_dir = output_dir / domain
    hosts = _hosts_from_results(results)
    hosts.extend(_hosts_from_files(domain_dir))
    merged = _unique_sorted_hosts(hosts, domain, oos)

    merged_path = domain_dir / "subdomains_merged.txt"
    canonical_path = domain_dir / "subdomains.txt"
    _write_lines(merged_path, merged)
    _write_lines(canonical_path, merged)
    return merged_path, len(merged)


def _write_alive_subdomains(domain: str, dns_results: list[ToolResult | None], output_dir: Path, oos: list[str]) -> tuple[Path, int]:
    """
    Write alive_subdomains.txt before HTTP tools run.

    Prefer dnsx-resolved hosts. If dnsx was not selected/available, fall back to
    merged subdomains so httpx can still probe and resolve on its own.
    """
    domain_dir = output_dir / domain
    dns_hosts = _hosts_from_results([r for r in dns_results if r and r.tool == "dnsx"])
    resolved_hosts = _unique_sorted_hosts(dns_hosts, domain, oos)
    candidates = list(resolved_hosts)

    if not candidates:
        merged = domain_dir / "subdomains_merged.txt"
        if merged.exists():
            candidates = _unique_sorted_hosts(merged.read_text(errors="replace").splitlines(), domain, oos)

    # Preserve the legacy hand-off name for compatible tools, but never label
    # unresolved fallback candidates as alive. HTTP tools consume the explicit
    # candidate file and establish reachability themselves.
    out = domain_dir / "alive_subdomains.txt"
    _write_lines(out, resolved_hosts)
    _write_lines(domain_dir / "resolved_subdomains.txt", resolved_hosts)
    _write_lines(domain_dir / "probe_candidates.txt", candidates)
    return out, len(resolved_hosts)


def _url_from_port(host: str, port: int) -> str | None:
    if port in {80}:
        return f"http://{host}"
    if port in {443}:
        return f"https://{host}"
    if port in {8080, 8000, 8008, 8888, 5000, 3000}:
        return f"http://{host}:{port}"
    if port in {8443, 9443}:
        return f"https://{host}:{port}"
    return None


def _write_alive_urls(domain: str, http_results: list[ToolResult | None], output_dir: Path, oos: list[str]) -> tuple[Path, int]:
    """Write canonical alive_urls.txt for URL discovery, nuclei and gowitness.

    Primary source is httpx JSON output. If httpx fails or returns no rows, we
    still build useful candidates from naabu web ports. As a last-resort fallback
    we emit https/http candidates from alive_subdomains.txt so screenshot/crawl
    tools have something to try instead of silently producing zero results.
    """
    urls: set[str] = set()
    domain_dir = output_dir / domain

    for result in http_results:
        if not result:
            continue
        for row in result.data or []:
            url = str(row.get("url") or "").strip()
            if url and not _matches_oos(url, oos):
                urls.add(url)
                continue

            if result.tool == "naabu":
                host = _extract_host(str(row.get("host") or ""))
                try:
                    port = int(row.get("port") or 0)
                except Exception:
                    port = 0
                candidate = _url_from_port(host, port) if host and port else None
                if candidate and not _matches_oos(candidate, oos):
                    urls.add(candidate)

    out = domain_dir / "alive_urls.txt"
    _write_lines(out, sorted(urls))
    return out, len(urls)


async def _run_tool(
    tool_name: str,
    domain: str,
    scan: Scan,
    oos: list[str],
    output_dir: Path,
    data_dir: Path,
    storage: BaseStorage,
    wordlist: str | None,
    *,
    phase: str,
    phase_index: int,
    completed_tools_ref: dict[str, int],
    total_tools: int,
    overall_completed_tools_ref: dict[str, int],
    overall_total_tools: int,
) -> ToolResult | None:
    tool = get_tool(tool_name, output_dir, data_dir)
    if tool is None:
        completed_tools_ref["value"] += 1
        overall_completed_tools_ref["value"] += 1
        await _emit(
            scan, storage, tool_name, "skipped", "Not registered", domain=domain,
            phase=phase, phase_index=phase_index,
            completed_tools=completed_tools_ref["value"], total_tools=total_tools,
            overall_completed_tools=overall_completed_tools_ref["value"],
            overall_total_tools=overall_total_tools,
        )
        return None

    # Resume support: if this is a resumed scan and a prior successful result exists
    # for (domain, tool), copy it forward instead of re-running the tool.
    prior = _reuse_maps.get(scan.id, {}).get((domain, tool_name))
    # Evidence BLOBs are owned by one scan. Capture screenshots again instead of
    # copying metadata whose blob_id belongs to the previous assessment.
    if tool_name == "gowitness":
        prior = None
    if prior is not None:
        reused = ToolResult(
            scan_id=scan.id, project_id=scan.project_id, tool=tool_name,
            category=prior.category, domain=domain, data=prior.data,
            count=prior.count, elapsed_s=prior.elapsed_s, error="",
        )
        await storage.save_result(reused)
        completed_tools_ref["value"] += 1
        overall_completed_tools_ref["value"] += 1
        await _emit(
            scan, storage, tool_name, "done", f"{prior.count} results (reused)", prior.count,
            domain=domain, phase=phase, phase_index=phase_index,
            completed_tools=completed_tools_ref["value"], total_tools=total_tools,
            overall_completed_tools=overall_completed_tools_ref["value"],
            overall_total_tools=overall_total_tools,
        )
        return reused

    availability_error = tool.availability_error()
    if availability_error:
        completed_tools_ref["value"] += 1
        overall_completed_tools_ref["value"] += 1
        await _emit(
            scan, storage, tool_name, "skipped", availability_error,
            domain=domain, phase=phase, phase_index=phase_index,
            completed_tools=completed_tools_ref["value"], total_tools=total_tools,
            overall_completed_tools=overall_completed_tools_ref["value"],
            overall_total_tools=overall_total_tools,
        )
        return None

    await _emit(
        scan, storage, tool_name, "running", domain=domain, phase=phase,
        phase_index=phase_index, completed_tools=completed_tools_ref["value"], total_tools=total_tools,
        overall_completed_tools=overall_completed_tools_ref["value"],
        overall_total_tools=overall_total_tools,
    )

    try:
        result = await tool.execute(
            domain, scan.id, scan.project_id, oos, wordlist,
            extra={"verify_emails": scan.verify_emails},
        )
        from evidence import persist_result_evidence
        await persist_result_evidence(result, output_dir, storage)
        await storage.save_result(result)
        completed_tools_ref["value"] += 1
        overall_completed_tools_ref["value"] += 1

        if result.error:
            await _emit(
                scan, storage, tool_name, "error", result.error[:500], result.count,
                domain=domain, phase=phase, phase_index=phase_index,
                completed_tools=completed_tools_ref["value"], total_tools=total_tools,
                overall_completed_tools=overall_completed_tools_ref["value"],
                overall_total_tools=overall_total_tools,
            )
        else:
            await _emit(
                scan, storage, tool_name, "done", f"{result.count} results", result.count,
                domain=domain, phase=phase, phase_index=phase_index,
                completed_tools=completed_tools_ref["value"], total_tools=total_tools,
                overall_completed_tools=overall_completed_tools_ref["value"],
                overall_total_tools=overall_total_tools,
            )
        return result

    except Exception as exc:
        logger.exception("%s raised exception", tool_name)
        completed_tools_ref["value"] += 1
        overall_completed_tools_ref["value"] += 1
        result = ToolResult(
            scan_id=scan.id,
            project_id=scan.project_id,
            tool=tool_name,
            category=getattr(tool, "category", ToolCategory.SUBDOMAIN),
            domain=domain,
            data=[],
            count=0,
            error=str(exc),
        )
        await storage.save_result(result)
        await _emit(
            scan, storage, tool_name, "error", str(exc)[:500], domain=domain,
            phase=phase, phase_index=phase_index,
            completed_tools=completed_tools_ref["value"], total_tools=total_tools,
            overall_completed_tools=overall_completed_tools_ref["value"],
            overall_total_tools=overall_total_tools,
        )
        return result


async def _run_phase(
    phase: dict[str, object],
    domain: str,
    scan: Scan,
    oos: list[str],
    output_dir: Path,
    data_dir: Path,
    storage: BaseStorage,
    overall_completed_tools_ref: dict[str, int],
    overall_total_tools: int,
) -> list[ToolResult | None]:
    index = int(phase["index"])
    name = str(phase["name"])
    tools = _selected_tools(scan, phase)
    label = f"Phase {index}: {name}"

    if not tools:
        await _emit(
            scan, storage, "__phase__", "skipped", f"{label} — no selected tools",
            domain=domain, phase=name, phase_index=index, completed_tools=0, total_tools=0,
            overall_completed_tools=overall_completed_tools_ref["value"],
            overall_total_tools=overall_total_tools,
        )
        return []

    await _emit(
        scan, storage, "__phase__", "running", label, domain=domain,
        phase=name, phase_index=index, completed_tools=0, total_tools=len(tools),
        overall_completed_tools=overall_completed_tools_ref["value"],
        overall_total_tools=overall_total_tools,
    )

    completed_ref = {"value": 0}
    results: list[ToolResult | None] = []

    # AI analysis must run last because it consumes the artifacts/results produced
    # by earlier phases plus phase-6 tools such as nuclei, gowitness and dorks.
    ai_tools = [t for t in tools if t == "ai_analysis"]
    normal_tools = [t for t in tools if t != "ai_analysis"]

    if normal_tools:
        async def run_limited(tool_name: str) -> ToolResult | None:
            async with _tool_semaphore:
                return await _run_tool(
                tool_name, domain, scan, oos, output_dir, data_dir, storage, scan.wordlist,
                phase=name, phase_index=index, completed_tools_ref=completed_ref, total_tools=len(tools),
                overall_completed_tools_ref=overall_completed_tools_ref,
                overall_total_tools=overall_total_tools,
            )

        normal_results = await asyncio.gather(*(run_limited(tool_name) for tool_name in normal_tools))
        results.extend(normal_results)

    for tool_name in ai_tools:
        ai_result = await _run_tool(
            tool_name, domain, scan, oos, output_dir, data_dir, storage, scan.wordlist,
            phase=name, phase_index=index, completed_tools_ref=completed_ref, total_tools=len(tools),
            overall_completed_tools_ref=overall_completed_tools_ref,
            overall_total_tools=overall_total_tools,
        )
        results.append(ai_result)

    await _emit(
        scan, storage, "__phase__", "done", f"{label} complete",
        domain=domain, phase=name, phase_index=index,
        completed_tools=len(tools), total_tools=len(tools),
        overall_completed_tools=overall_completed_tools_ref["value"],
        overall_total_tools=overall_total_tools,
    )
    return list(results)


async def run_scan(
    scan: Scan,
    domains: list[str],
    oos: list[str],
    output_dir: Path,
    data_dir: Path,
    storage: BaseStorage,
    reuse_previous: bool = False,
) -> None:
    """Main scan coroutine — called by the API background task or CLI."""
    apply_tool_api_keys(await storage.load_tool_api_keys())

    workspace_root = scan_workspace(output_dir, scan.project_id, scan.id)
    workspace_root.mkdir(parents=True, exist_ok=True)
    scan.workspace = str(workspace_root.relative_to(output_dir.resolve())).replace("\\", "/")
    scan.scope_hash = scope_fingerprint(
        domains, oos, scan.tools, scan.wordlist,
        {"verify_emails": scan.verify_emails},
    )

    if reuse_previous:
        _reuse_maps[scan.id] = await _build_reuse_map(scan, storage)
        logger.info("Resuming scan %s — reusing %d prior result(s)", scan.id, len(_reuse_maps[scan.id]))

    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    scan.completed_at = None
    scan.error = ""
    await storage.save_scan(scan)

    overall_total_tools = sum(len(_selected_tools(scan, phase)) for phase in PHASES) * len(domains)
    overall_completed_ref = {"value": 0}

    try:
        for domain in domains:
            if await _scan_cancelled(scan, storage):
                scan.status = ScanStatus.CANCELLED
                break

            await _emit(
                scan, storage, "__domain__", "start", domain, domain=domain,
                overall_completed_tools=overall_completed_ref["value"],
                overall_total_tools=overall_total_tools,
            )

            phase_results: dict[int, list[ToolResult | None]] = {}
            for phase in PHASES:
                if await _scan_cancelled(scan, storage):
                    scan.status = ScanStatus.CANCELLED
                    await _emit(scan, storage, "__scan__", "cancelled", "Scan cancelled", domain=domain)
                    break

                idx = int(phase["index"])

                # Hard gates: write dependent artifacts before the phase that needs them.
                if idx == 3:
                    merged_path, merged_count = _write_merged_subdomains(domain, phase_results.get(2, []), workspace_root, oos)
                    await _emit(
                        scan, storage, "subdomain-merge", "done",
                        f"Wrote {merged_path.name}", merged_count,
                        domain=domain, phase="Subdomain Enumeration", phase_index=2,
                        overall_completed_tools=overall_completed_ref["value"],
                        overall_total_tools=overall_total_tools,
                    )
                elif idx == 4:
                    alive_path, alive_count = _write_alive_subdomains(domain, phase_results.get(3, []), workspace_root, oos)
                    await _emit(
                        scan, storage, "alive-subdomains", "done",
                        f"Wrote {alive_path.name}", alive_count,
                        domain=domain, phase="DNS Resolution", phase_index=3,
                        overall_completed_tools=overall_completed_ref["value"],
                        overall_total_tools=overall_total_tools,
                    )

                phase_results[idx] = await _run_phase(
                    phase, domain, scan, oos, workspace_root, data_dir, storage,
                    overall_completed_tools_ref=overall_completed_ref,
                    overall_total_tools=overall_total_tools,
                )

                if idx == 4:
                    urls_path, urls_count = _write_alive_urls(domain, phase_results.get(4, []), workspace_root, oos)
                    await _emit(
                        scan, storage, "alive-urls", "done",
                        f"Wrote {urls_path.name}", urls_count,
                        domain=domain, phase="HTTP Probing & Port Scanning", phase_index=4,
                        overall_completed_tools=overall_completed_ref["value"],
                        overall_total_tools=overall_total_tools,
                    )

            if scan.status == ScanStatus.CANCELLED:
                break

            await _emit(
                scan, storage, "__domain__", "done", domain, domain=domain,
                overall_completed_tools=overall_completed_ref["value"],
                overall_total_tools=overall_total_tools,
            )

        if scan.status != ScanStatus.CANCELLED:
            normalized_results = await storage.list_results(scan.id)
            snapshot = build_inventory(
                scan_id=scan.id,
                project_id=scan.project_id,
                roots=domains,
                results=normalized_results,
            )
            await storage.save_inventory(snapshot)
            from finding_workflow import reopen_reappearing_findings
            await reopen_reappearing_findings(snapshot, storage)
            await asyncio.to_thread(
                _write_execution_manifest,
                scan,
                workspace_root,
                domains,
                oos,
                normalized_results,
            )
            scan.status = ScanStatus.COMPLETED

    except Exception as exc:
        logger.exception("Scan failed")
        scan.status = ScanStatus.FAILED
        scan.error = str(exc)

    scan.completed_at = datetime.now(timezone.utc)
    await storage.save_scan(scan)
    if scan.status == ScanStatus.COMPLETED:
        from notifications import notify_scan_completed
        await notify_scan_completed(scan, storage)
    await _emit(
        scan, storage, "__scan__", scan.status.value, scan.status.value,
        overall_completed_tools=overall_completed_ref["value"],
        overall_total_tools=overall_total_tools,
    )

    _reuse_maps.pop(scan.id, None)

    # A cancelled scan must leave no data behind. We purge its results and progress
    # here — after the phase loop has fully unwound and every tool coroutine has
    # returned — so there is no race with in-flight result persistence. The scan
    # record itself is kept as a lightweight "cancelled" history entry until the
    # project's data is cleared. Shared per-domain artifacts are intentionally not
    # touched because they are not owned by any single scan.
    if scan.status == ScanStatus.CANCELLED:
        try:
            await storage.delete_results(scan.id)
            await storage.delete_scan_artifacts(scan)
            scan.progress = []
            await storage.save_scan(scan)
            logger.info("Purged data for cancelled scan %s", scan.id)
        except Exception:
            logger.exception("Failed to purge data for cancelled scan %s", scan.id)

    # Leave queue open briefly so the frontend can drain final events.
    await asyncio.sleep(60)
    drop_progress_queue(scan.id)
