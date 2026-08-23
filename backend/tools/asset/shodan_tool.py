"""Optional Shodan enrichment for explicitly selected authorized domains."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import aiohttp

from models import ToolCategory
from tools.base import BaseTool, RunResult


class ShodanTool(BaseTool):
    """Query Shodan once per root domain and normalize in-scope service banners."""

    name = "shodan"
    binary_name = None
    category = ToolCategory.ASSET
    description = "Shodan service, technology, and reported-CVE enrichment (API key required)"
    parallel_group = "asset"

    def availability_error(self) -> str | None:
        if not os.getenv("SHODAN_API_KEY"):
            return "SHODAN_API_KEY is not configured in Settings"
        return None

    async def run(
        self, domain: str, out_dir: Path, data_dir: Path,
        wordlist: str | None, extra: dict,
    ) -> RunResult:
        key = os.getenv("SHODAN_API_KEY", "")
        output = out_dir / "shodan_results.json"
        try:
            timeout = aiohttp.ClientTimeout(total=45)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": key, "query": f"hostname:{domain}", "minify": "false"},
                    headers={"User-Agent": "ShadowGrid/3.1"},
                ) as response:
                    body = await response.text()
                    if response.status != 200:
                        try:
                            message = json.loads(body).get("error", body)
                        except json.JSONDecodeError:
                            message = body
                        return RunResult("", f"Shodan API HTTP {response.status}: {str(message)[:500]}", response.status, 0)
            output.write_text(body, encoding="utf-8")
            return RunResult(body, "", 0, 0)
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:
            return RunResult("", f"Shodan request failed: {exc}", 1, 0)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """Keep only exact/in-scope hostnames and expose service CVE metadata."""
        if not result.stdout:
            return []
        try:
            matches = json.loads(result.stdout).get("matches") or []
        except (AttributeError, json.JSONDecodeError):
            return []
        rows: list[dict[str, Any]] = []
        for match in matches[:100]:
            hostnames = [str(value).lower().rstrip(".") for value in match.get("hostnames") or []]
            scoped = [host for host in hostnames if host == domain or host.endswith(f".{domain}")]
            if not scoped:
                continue
            vulnerabilities = match.get("vulns") or []
            if isinstance(vulnerabilities, dict):
                vulnerabilities = list(vulnerabilities)
            cpes = match.get("cpe") or match.get("cpe23") or []
            if isinstance(cpes, str):
                cpes = [cpes]
            for host in scoped:
                rows.append({
                    "host": host,
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port"),
                    "transport": match.get("transport", ""),
                    "service": match.get("product") or match.get("_shodan", {}).get("module", ""),
                    "version": match.get("version", ""),
                    "technologies": cpes,
                    "vulnerabilities": sorted({str(cve).upper() for cve in vulnerabilities}),
                    "organization": match.get("org", ""),
                    "isp": match.get("isp", ""),
                    "asn": match.get("asn", ""),
                    "timestamp": match.get("timestamp", ""),
                    "banner": str(match.get("data") or "")[:2000],
                    "state": "shodan_observed",
                    "source": "shodan",
                })
        return rows
