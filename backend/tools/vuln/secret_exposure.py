"""Detect exposed secrets in bounded response samples without storing values."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import aiohttp

from models import ToolCategory
from tools.base import BaseTool, RunResult

MAX_BODY_BYTES = 1_000_000
PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "high"),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("GitHub token", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,255}\b"), "high"),
    ("JWT token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium"),
    ("Generic secret assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"]([^'\"\s]{8,})"), "medium"),
)


class SecretExposureTool(BaseTool):
    """Inspect discovered in-scope content and persist fingerprints, never secrets."""

    name = "secret_exposure"
    binary_name = None
    category = ToolCategory.VULN
    description = "Masked secret and credential exposure detection"
    parallel_group = "vuln"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        candidates = self._read_lines(out_dir / "alive_urls.txt")
        for filename in ("katana.txt", "gau.txt", "waybackurls.txt", "urlfinder.txt"):
            candidates.extend(self._read_lines(out_dir / filename))
        urls = list(dict.fromkeys(url for url in candidates if url.startswith(("http://", "https://"))))[:300]
        findings: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(10)
        timeout = aiohttp.ClientTimeout(total=15)

        async def inspect(url: str, session: aiohttp.ClientSession) -> None:
            async with semaphore:
                try:
                    async with session.get(url, allow_redirects=True) as response:
                        if response.status >= 400:
                            return
                        raw = await response.content.read(MAX_BODY_BYTES)
                        text = raw.decode(errors="replace")
                        for name, pattern, severity in PATTERNS:
                            match = pattern.search(text)
                            if not match:
                                continue
                            secret = match.group(1) if match.lastindex else match.group(0)
                            findings.append({
                                "name": f"Exposed {name}", "severity": severity,
                                "url": str(response.url), "matched_at": str(response.url),
                                "secret_fingerprint": hashlib.sha256(secret.encode()).hexdigest()[:16],
                                "masked_value": f"{secret[:3]}***{secret[-2:]}" if len(secret) >= 7 else "***",
                                "source": "secret_exposure", "state": "finding_observed",
                            })
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                    return

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            await asyncio.gather(*(inspect(url, session) for url in urls))
        serialized = json.dumps(findings)
        (out_dir / "secret_exposure.json").write_text(serialized, encoding="utf-8")
        return RunResult(serialized, "", 0, 0)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """Return masked findings without raw response bodies or credentials."""
        try:
            value = json.loads(result.stdout or "[]")
            return value if isinstance(value, list) else []
        except json.JSONDecodeError:
            return []
