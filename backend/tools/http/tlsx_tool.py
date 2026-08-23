"""ProjectDiscovery tlsx certificate and TLS service inventory."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from models import ToolCategory
from tools.base import BaseTool, RunResult


class TlsxTool(BaseTool):
    """Collect TLS versions, certificate subjects, issuers, and SAN names."""

    name = "tlsx"
    category = ToolCategory.TECH
    description = "TLS and certificate inventory including SAN relationships"
    parallel_group = "http"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        targets = out_dir / "probe_candidates.txt"
        if not targets.exists() or not targets.read_text(errors="replace").strip():
            return RunResult("", "No TLS probe candidates", 0, 0)
        output = out_dir / "tlsx.jsonl"
        return await self._exec([
            "tlsx", "-silent", "-l", str(targets), "-json", "-o", str(output),
        ], timeout=900)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """Normalize JSONL output while preserving certificate relationships."""
        rows: list[dict[str, Any]] = []
        lines = result.lines or self._read_lines(self.output_dir / domain / "tlsx.jsonl")
        for line in lines:
            try:
                item = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            host = item.get("host") or item.get("ip") or item.get("input") or ""
            rows.append({
                "host": host, "ip": item.get("ip", ""), "port": item.get("port", 443),
                "subject_cn": item.get("subject_cn") or item.get("subject-cn", ""),
                "issuer_cn": item.get("issuer_cn") or item.get("issuer-cn", ""),
                "sans": item.get("subject_an") or item.get("subject-an") or [],
                "tls_version": item.get("tls_version") or item.get("tls-version", ""),
                "cipher": item.get("cipher", ""),
                "not_before": item.get("not_before") or item.get("not-before", ""),
                "not_after": item.get("not_after") or item.get("not-after", ""),
                "state": "tls_responding", "source": "tlsx",
            })
        return [row for row in rows if row["host"]]
