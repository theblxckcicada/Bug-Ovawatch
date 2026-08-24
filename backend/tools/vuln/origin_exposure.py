"""Conservative direct-origin exposure checks using already resolved IPs."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from models import ToolCategory
from tools.base import BaseTool, RunResult

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


class OriginExposureTool(BaseTool):
    """Compare hostname and direct-IP responses to flag reachable origin candidates."""

    name = "origin_exposure"
    binary_name = None
    category = ToolCategory.VULN
    description = "Direct-origin exposure validation using DNS-correlated IPs"
    parallel_group = "vuln"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        source = out_dir / "httpx.jsonl"
        if not source.is_file():
            return RunResult("", "No HTTP inventory", 0, 0)
        candidates: list[tuple[str, str]] = []
        for line in self._read_lines(source):
            try:
                row = json.loads(line)
                url = str(row.get("url") or "")
                ip_value = row.get("a") or row.get("ip") or ""
                if isinstance(ip_value, list):
                    ip_value = ip_value[0] if ip_value else ""
                address = ipaddress.ip_address(str(ip_value))
                ip = str(address)
                if url and address.version == 4 and not address.is_private:
                    candidates.append((url, ip))
            except (ValueError, json.JSONDecodeError):
                continue
        findings: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(8)
        timeout = aiohttp.ClientTimeout(total=15)

        async def fetch(session: aiohttp.ClientSession, url: str, host: str | None = None):
            headers = {"Host": host} if host else {}
            async with session.get(url, headers=headers, allow_redirects=False) as response:
                body = (await response.content.read(500_000)).decode(errors="replace")
                title_match = TITLE_RE.search(body)
                title = " ".join(title_match.group(1).split())[:200] if title_match else ""
                digest = hashlib.sha256(re.sub(r"\s+", " ", body).encode()).hexdigest()
                return response.status, title, digest, response.headers.get("Server", "")

        async def inspect(url: str, ip: str, session: aiohttp.ClientSession) -> None:
            parsed = urlsplit(url)
            if not parsed.hostname or parsed.scheme not in {"http", "https"}:
                return
            port = f":{parsed.port}" if parsed.port else ""
            direct = f"{parsed.scheme}://{ip}{port}{parsed.path or '/'}"
            async with semaphore:
                try:
                    normal, origin = await asyncio.gather(
                        fetch(session, url), fetch(session, direct, parsed.netloc),
                    )
                    same_body = normal[2] == origin[2]
                    same_title = bool(normal[1]) and normal[1] == origin[1]
                    if origin[0] < 500 and (same_body or (same_title and normal[3] == origin[3])):
                        findings.append({
                            "name": "Potential directly reachable origin IP",
                            "severity": "medium", "url": url, "matched_at": direct,
                            "host": parsed.hostname, "ip": ip,
                            "evidence": {"status": origin[0], "title": origin[1], "exact_body_match": same_body},
                            "source": "origin_exposure", "state": "finding_observed",
                        })
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                    return

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            await asyncio.gather(*(inspect(url, ip, session) for url, ip in candidates[:150]))
        serialized = json.dumps(findings)
        (out_dir / "origin_exposure.json").write_text(serialized, encoding="utf-8")
        return RunResult(serialized, "", 0, 0)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """Return only high-confidence normalized origin candidates."""
        try:
            value = json.loads(result.stdout or "[]")
            return value if isinstance(value, list) else []
        except json.JSONDecodeError:
            return []
