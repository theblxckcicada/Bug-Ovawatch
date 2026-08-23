"""WPScan vulnerability checks for every verified alive HTTP service.

Every alive service is passed to WPScan with ``--force`` so incomplete technology
fingerprinting cannot hide a WordPress installation. When a WPScan API token is
configured in Settings it is passed through for vulnerability-database results;
without one, WPScan still performs its built-in checks.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from models import ToolCategory
from tools.base import BaseTool, RunResult

class WpscanTool(BaseTool):
    name = "wpscan"
    category = ToolCategory.WORDPRESS
    description = "WordPress vulnerability checks across every verified alive site"
    parallel_group = "vuln"

    # ── Target selection ─────────────────────────────────────────────
    @staticmethod
    def _site_root(url: str) -> str:
        """Normalise a URL to its scheme://host[:port] root so each site is scanned once."""
        url = (url or "").strip()
        if not url:
            return ""
        parsed = urlparse(url if "://" in url else f"http://{url}")
        if not parsed.hostname:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    def _wordpress_targets(self, out_dir: Path) -> list[str]:
        """Collect every verified alive site root for WPScan.

        ``alive_urls.txt`` is the canonical source. All httpx results are also
        accepted as a defensive fallback because httpx only emits responsive HTTP
        services. Existing WhatWeb results provide a final compatibility fallback.
        Candidates are normalized to scheme://host[:port] and de-duplicated.
        """
        targets: set[str] = set()

        for url in self._read_lines(out_dir / "alive_urls.txt"):
            if not url.lower().startswith(("http://", "https://")):
                continue
            root = self._site_root(url)
            if root:
                targets.add(root)

        # httpx JSON lines represent services that answered an HTTP probe.
        for line in self._read_lines(out_dir / "httpx.jsonl"):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            root = self._site_root(str(obj.get("url") or obj.get("input") or ""))
            if root:
                targets.add(root)

        # Retain compatibility with scans whose only remaining artifact is WhatWeb.
        for line in self._read_lines(out_dir / "whatweb.jsonl"):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            for entry in (obj if isinstance(obj, list) else [obj]):
                if not isinstance(entry, dict):
                    continue
                root = self._site_root(str(entry.get("target") or entry.get("uri") or ""))
                if root:
                    targets.add(root)

        return sorted(targets)

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        targets = self._wordpress_targets(out_dir)
        summary_path = out_dir / "wpscan.txt"

        if not targets:
            summary_path.write_text("No verified alive sites — wpscan skipped.\n")
            return RunResult("No verified alive targets", "", 0, 0.0)

        api_token = os.environ.get("WPSCAN_API_TOKEN", "").strip()
        summaries: list[str] = []

        for idx, url in enumerate(targets):
            out_json = out_dir / f"wpscan_{idx}.json"
            cmd = [
                "wpscan", "--url", url,
                "--format", "json", "--output", str(out_json),
                "--no-banner", "--random-user-agent", "--disable-tls-checks",
                "--force", "--plugins-detection", "passive",
                "--enumerate", "vp,vt,dbe,u",
            ]
            if api_token:
                cmd += ["--api-token", api_token]

            # wpscan exits non-zero (e.g. 5) when it finds vulnerabilities, so its
            # return code is not treated as a failure here — findings are read from
            # the JSON artifact instead.
            result = await self._exec(cmd, timeout=900)
            summaries.append(f"{url}: exit={result.returncode}")

        summary_path.write_text(
            f"wpscan checked {len(targets)} verified alive site(s)"
            f"{' with API token' if api_token else ''}.\n" + "\n".join(summaries) + "\n"
        )
        return RunResult("\n".join(summaries), "", 0, 0.0)

    # ── Parsing ──────────────────────────────────────────────────────
    @staticmethod
    def _references(vuln: dict) -> list[str]:
        refs = vuln.get("references", {}) or {}
        out: list[str] = []
        if isinstance(refs, dict):
            for key in ("cve", "url", "wpvulndb", "secunia", "exploitdb"):
                values = refs.get(key) or []
                if not isinstance(values, list):
                    values = [values]
                for value in values:
                    out.append(f"CVE-{value}" if key == "cve" else str(value))
        return out[:20]

    def _rows_from_report(self, data: dict) -> list[dict[str, Any]]:
        if not isinstance(data, dict):
            return []

        target = data.get("target_url") or data.get("target_ip") or ""
        rows: list[dict[str, Any]] = []

        def add(wp_type: str, component: str, title: str, severity: str,
                version: str = "", fixed_in: str = "", references: list[str] | None = None) -> None:
            rows.append({
                "url": target,
                "wp_type": wp_type,
                "component": component,
                "title": title,
                "version": version,
                "fixed_in": fixed_in or "",
                "severity": severity,
                "references": references or [],
                "source": "wpscan",
            })

        # Interesting findings (headers, readme, xmlrpc, upload dirs, etc.)
        for finding in data.get("interesting_findings", []) or []:
            if not isinstance(finding, dict):
                continue
            refs = finding.get("references", {}) or {}
            add(
                "finding",
                str(finding.get("type", "")),
                str(finding.get("to_s") or finding.get("url") or "").strip(),
                "info",
                references=refs.get("url", []) if isinstance(refs, dict) else [],
            )

        # WordPress core
        version = data.get("version") or {}
        if isinstance(version, dict) and version.get("number"):
            number = str(version.get("number", ""))
            status = str(version.get("status", ""))
            if status and status != "latest":
                add("core", "WordPress core", f"WordPress {number} ({status})",
                    "medium" if status == "insecure" else "info", version=number)
            for vuln in version.get("vulnerabilities", []) or []:
                add("core", "WordPress core", str(vuln.get("title", "")), "high",
                    version=number, fixed_in=str(vuln.get("fixed_in", "") or ""),
                    references=self._references(vuln))

        # Active theme
        theme = data.get("main_theme") or {}
        if isinstance(theme, dict):
            theme_version = theme.get("version") or {}
            theme_num = theme_version.get("number", "") if isinstance(theme_version, dict) else ""
            for vuln in theme.get("vulnerabilities", []) or []:
                add("theme", str(theme.get("slug", "")), str(vuln.get("title", "")), "high",
                    version=str(theme_num), fixed_in=str(vuln.get("fixed_in", "") or ""),
                    references=self._references(vuln))

        # Plugins
        plugins = data.get("plugins") or {}
        if isinstance(plugins, dict):
            for slug, info in plugins.items():
                if not isinstance(info, dict):
                    continue
                plugin_version = info.get("version") or {}
                plugin_num = plugin_version.get("number", "") if isinstance(plugin_version, dict) else ""
                for vuln in info.get("vulnerabilities", []) or []:
                    add("plugin", str(slug), str(vuln.get("title", "")), "high",
                        version=str(plugin_num), fixed_in=str(vuln.get("fixed_in", "") or ""),
                        references=self._references(vuln))

        # Enumerated users
        users = data.get("users") or {}
        if isinstance(users, dict):
            for username in users:
                add("user", str(username), f"Enumerated user: {username}", "info")

        return rows

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        out_dir = self.output_dir / domain
        rows: list[dict[str, Any]] = []
        for report in sorted(out_dir.glob("wpscan_*.json")):
            try:
                data = json.loads(report.read_text(errors="replace"))
            except Exception:
                continue
            rows.extend(self._rows_from_report(data))
        return rows
