"""wpscan — WordPress vulnerability scanner for detected WordPress sites.

wpscan only targets hosts that were fingerprinted as WordPress by earlier phases
(httpx tech-detection, and whatweb when its output is already present), so we never
throw wpscan at non-WordPress URLs. When a WPScan API token is configured in
Settings it is passed through so the WordPress Vulnerability Database is queried
for CVE-level results; without it wpscan still runs with its built-in checks.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from models import ToolCategory
from tools.base import BaseTool, RunResult

# Cap the number of WordPress sites scanned per domain — wpscan is slow and this
# keeps a single scan from stalling on a large estate.
MAX_TARGETS = 15

# Path/query fragments that reliably indicate a WordPress site. An alive URL
# containing any of these is treated as a WordPress target even when tech
# fingerprinting (httpx/whatweb) did not flag its host — this is what lets wpscan
# run off the validated alive-URL set produced by the URL-discovery phase.
WP_URL_MARKERS: tuple[str, ...] = (
    "/wp-content/",
    "/wp-includes/",
    "/wp-json",
    "/wp-login.php",
    "/wp-admin",
    "/wp-cron.php",
    "/wp-signup.php",
    "/xmlrpc.php",
    "/?author=",
    "&author=",
)


class WpscanTool(BaseTool):
    name = "wpscan"
    category = ToolCategory.WORDPRESS
    description = "WordPress vulnerability scanning via wpscan (WordPress sites only)"
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

    @staticmethod
    def _looks_wordpress(url: str) -> bool:
        """True when a URL's path/query carries a known WordPress marker."""
        low = (url or "").lower()
        return any(marker in low for marker in WP_URL_MARKERS)

    def _wordpress_targets(self, out_dir: Path) -> list[str]:
        """Collect site roots to hand to wpscan, from three WordPress signals:

        1. httpx tech-detection (Wappalyzer) flagged the host as WordPress.
        2. whatweb flagged a WordPress plugin (when its artifact already exists).
        3. The validated alive URLs (``alive_urls.txt``) carry a WordPress path
           marker, or belong to a host already fingerprinted as WordPress.

        Every candidate is normalised to its scheme://host[:port] root and
        de-duplicated. Non-WordPress URLs never enter the set, so the
        WordPress-only guard holds and wpscan is never aimed at unrelated sites.
        """
        targets: set[str] = set()
        wp_hosts: set[str] = set()

        # Signal 1: httpx -tech-detect (Wappalyzer) output from HTTP probing.
        for line in self._read_lines(out_dir / "httpx.jsonl"):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            tech = obj.get("tech") or obj.get("technologies") or []
            if isinstance(tech, str):
                tech = [tech]
            if any("wordpress" in str(t).lower() for t in tech):
                root = self._site_root(str(obj.get("url") or obj.get("input") or ""))
                if root:
                    targets.add(root)
                    wp_hosts.add(self._extract_host(root))

        # Signal 2: whatweb, when its artifact already exists this scan.
        for line in self._read_lines(out_dir / "whatweb.jsonl"):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            for entry in (obj if isinstance(obj, list) else [obj]):
                if not isinstance(entry, dict):
                    continue
                plugins = entry.get("plugins", {}) or {}
                if any("wordpress" in str(k).lower() for k in plugins):
                    root = self._site_root(str(entry.get("target") or entry.get("uri") or ""))
                    if root:
                        targets.add(root)
                        wp_hosts.add(self._extract_host(root))

        # Signal 3: the validated alive URLs from the URL-discovery phase. A URL is
        # a WordPress target when it carries a WordPress path marker, or when its
        # host was already fingerprinted as WordPress by signals 1–2 above.
        for url in self._read_lines(out_dir / "alive_urls.txt"):
            if not url.lower().startswith("http"):
                continue
            if self._looks_wordpress(url) or self._extract_host(url) in wp_hosts:
                root = self._site_root(url)
                if root:
                    targets.add(root)

        return sorted(targets)

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        targets = self._wordpress_targets(out_dir)
        summary_path = out_dir / "wpscan.txt"

        if not targets:
            summary_path.write_text("No WordPress sites detected — wpscan skipped.\n")
            return RunResult("No WordPress targets detected", "", 0, 0.0)

        api_token = os.environ.get("WPSCAN_API_TOKEN", "").strip()
        summaries: list[str] = []

        for idx, url in enumerate(targets[:MAX_TARGETS]):
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
            f"wpscan scanned {min(len(targets), MAX_TARGETS)} WordPress site(s)"
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
