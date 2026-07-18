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
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from models import Scan, ScanProgress, ScanStatus, ToolCategory, ToolResult
from storage import DualStorage
from tools.registry import get_tool
from tool_secrets import apply_tool_api_keys

logger = logging.getLogger(__name__)

# scan_id → asyncio.Queue of SSE event dicts
_progress_queues: dict[str, asyncio.Queue] = {}

# scan_id → {(domain, tool): ToolResult} reused from a prior scan when resuming.
_reuse_maps: dict[str, dict[tuple[str, str], ToolResult]] = {}

PHASES: list[dict[str, object]] = [
    {"index": 1, "name": "Asset Discovery", "tools": ["whois", "asnmap"]},
    {"index": 2, "name": "Subdomain Enumeration", "tools": ["crtsh", "assetfinder", "subfinder", "amass", "shuffledns"]},
    {"index": 3, "name": "DNS Resolution", "tools": ["dnsx", "dns_records", "zone_transfer"]},
    {"index": 4, "name": "HTTP Probing & Port Scanning", "tools": ["httpx", "naabu"]},
    {"index": 5, "name": "URL Discovery", "tools": ["waybackurls", "gau", "katana", "urlfinder"]},
    {"index": 6, "name": "Vulnerability Scan, Takeovers, Screenshots, Dorks & AI", "tools": ["google_dorks", "nuclei", "subdomain_takeover", "wpscan", "gowitness", "whatweb", "ai_analysis"]},
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
    storage: DualStorage,
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


async def _scan_cancelled(scan: Scan, storage: DualStorage) -> bool:
    latest = await storage.get_scan(scan.id)
    return bool(latest and latest.status == ScanStatus.CANCELLED)


async def _build_reuse_map(scan: Scan, storage: DualStorage) -> dict[tuple[str, str], ToolResult]:
    """Map (domain, tool) → prior successful ToolResult from the project's most recent
    earlier scan, so a resumed scan can continue instead of repeating finished work."""
    reuse: dict[tuple[str, str], ToolResult] = {}
    try:
        prior_scans = [s for s in await storage.list_scans(scan.project_id) if s.id != scan.id]
        prior_scans.sort(key=lambda s: s.created_at, reverse=True)
        # Walk newest → oldest; first non-empty result for a (domain, tool) wins.
        for prev in prior_scans:
            for result in await storage.list_results(prev.id):
                if result.count <= 0 or result.error:
                    continue
                key = (result.domain, result.tool)
                reuse.setdefault(key, result)
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
    hosts = _unique_sorted_hosts(dns_hosts, domain, oos)

    if not hosts:
        merged = domain_dir / "subdomains_merged.txt"
        if merged.exists():
            hosts = _unique_sorted_hosts(merged.read_text(errors="replace").splitlines(), domain, oos)

    out = domain_dir / "alive_subdomains.txt"
    _write_lines(out, hosts)
    return out, len(hosts)


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

    if not urls:
        alive_subdomains = domain_dir / "alive_subdomains.txt"
        if alive_subdomains.exists():
            for host in _unique_sorted_hosts(alive_subdomains.read_text(errors="replace").splitlines(), domain, oos):
                urls.add(f"https://{host}")
                urls.add(f"http://{host}")

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
    storage: DualStorage,
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
        result = await tool.execute(domain, scan.id, scan.project_id, oos, wordlist)
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
    storage: DualStorage,
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
        normal_results = await asyncio.gather(*[
            _run_tool(
                tool_name, domain, scan, oos, output_dir, data_dir, storage, scan.wordlist,
                phase=name, phase_index=index, completed_tools_ref=completed_ref, total_tools=len(tools),
                overall_completed_tools_ref=overall_completed_tools_ref,
                overall_total_tools=overall_total_tools,
            )
            for tool_name in normal_tools
        ])
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
    storage: DualStorage,
    reuse_previous: bool = False,
) -> None:
    """Main scan coroutine — called by the API background task or CLI."""
    apply_tool_api_keys(await storage.load_tool_api_keys())

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
                    merged_path, merged_count = _write_merged_subdomains(domain, phase_results.get(2, []), output_dir, oos)
                    await _emit(
                        scan, storage, "subdomain-merge", "done",
                        f"Wrote {merged_path.name}", merged_count,
                        domain=domain, phase="Subdomain Enumeration", phase_index=2,
                        overall_completed_tools=overall_completed_ref["value"],
                        overall_total_tools=overall_total_tools,
                    )
                elif idx == 4:
                    alive_path, alive_count = _write_alive_subdomains(domain, phase_results.get(3, []), output_dir, oos)
                    await _emit(
                        scan, storage, "alive-subdomains", "done",
                        f"Wrote {alive_path.name}", alive_count,
                        domain=domain, phase="DNS Resolution", phase_index=3,
                        overall_completed_tools=overall_completed_ref["value"],
                        overall_total_tools=overall_total_tools,
                    )

                phase_results[idx] = await _run_phase(
                    phase, domain, scan, oos, output_dir, data_dir, storage,
                    overall_completed_tools_ref=overall_completed_ref,
                    overall_total_tools=overall_total_tools,
                )

                if idx == 4:
                    urls_path, urls_count = _write_alive_urls(domain, phase_results.get(4, []), output_dir, oos)
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
            scan.status = ScanStatus.COMPLETED

    except Exception as exc:
        logger.exception("Scan failed")
        scan.status = ScanStatus.FAILED
        scan.error = str(exc)

    scan.completed_at = datetime.now(timezone.utc)
    await storage.save_scan(scan)
    await _emit(
        scan, storage, "__scan__", scan.status.value, scan.status.value,
        overall_completed_tools=overall_completed_ref["value"],
        overall_total_tools=overall_total_tools,
    )

    _reuse_maps.pop(scan.id, None)

    # Leave queue open briefly so the frontend can drain final events.
    await asyncio.sleep(60)
    drop_progress_queue(scan.id)
