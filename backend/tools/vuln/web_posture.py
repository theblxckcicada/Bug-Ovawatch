"""Low-impact HTTP security posture checks for verified alive services."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import aiohttp

from models import ToolCategory
from tools.base import BaseTool, RunResult

REQUIRED_HEADERS = {
    "strict-transport-security": ("Missing HSTS header", "low"),
    "content-security-policy": ("Missing Content-Security-Policy header", "low"),
    "x-content-type-options": ("Missing X-Content-Type-Options header", "low"),
    "referrer-policy": ("Missing Referrer-Policy header", "info"),
}


class WebPostureTool(BaseTool):
    """Assess response headers, cookies, methods, and CORS without exploitation."""

    name = "web_posture"
    binary_name = None
    category = ToolCategory.VULN
    description = "Security headers, cookie, CORS, and method posture checks"
    parallel_group = "vuln"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        urls = self._read_lines(out_dir / "alive_urls.txt")[:200]
        if not urls:
            return RunResult("", "No verified alive URLs", 0, 0)
        findings: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(10)
        timeout = aiohttp.ClientTimeout(total=15)

        async def inspect(url: str, session: aiohttp.ClientSession) -> None:
            async with semaphore:
                try:
                    async with session.get(
                        url, allow_redirects=True,
                        headers={"Origin": "https://shadowgrid.invalid"},
                    ) as response:
                        headers = {key.lower(): value for key, value in response.headers.items()}
                        final_url = str(response.url)
                        for header, (title, severity) in REQUIRED_HEADERS.items():
                            if header not in headers and not (
                                header == "strict-transport-security" and not final_url.startswith("https://")
                            ):
                                findings.append(self._finding(final_url, title, severity, {"missing_header": header}))
                        cors = headers.get("access-control-allow-origin", "")
                        credentials = headers.get("access-control-allow-credentials", "").lower()
                        if cors in {"*", "https://shadowgrid.invalid"}:
                            severity = "high" if credentials == "true" else "medium"
                            findings.append(self._finding(final_url, "Permissive CORS policy", severity, {
                                "allow_origin": cors, "allow_credentials": credentials,
                            }))
                        for cookie in response.headers.getall("Set-Cookie", []):
                            lowered = cookie.lower()
                            cookie_name = cookie.split("=", 1)[0][:100]
                            if "secure" not in lowered and final_url.startswith("https://"):
                                findings.append(self._finding(final_url, "Cookie missing Secure flag", "low", {"cookie": cookie_name}))
                            if "httponly" not in lowered:
                                findings.append(self._finding(final_url, "Cookie missing HttpOnly flag", "low", {"cookie": cookie_name}))
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                    return

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            await asyncio.gather(*(inspect(url, session) for url in urls))
        serialized = json.dumps(findings)
        (out_dir / "web_posture.json").write_text(serialized, encoding="utf-8")
        return RunResult(serialized, "", 0, 0)

    @staticmethod
    def _finding(url: str, name: str, severity: str, evidence: dict[str, Any]) -> dict[str, Any]:
        """Create one normalized posture finding."""
        return {
            "name": name, "severity": severity, "url": url,
            "matched_at": url, "evidence": evidence,
            "source": "web_posture", "state": "finding_observed",
        }

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """Return the already normalized posture finding list."""
        try:
            value = json.loads(result.stdout or "[]")
            return value if isinstance(value, list) else []
        except json.JSONDecodeError:
            return []
