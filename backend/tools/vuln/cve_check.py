"""Dedicated CVE template checks against verified alive URLs."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from models import ToolCategory
from tools.base import BaseTool, RunResult

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class CveCheckTool(BaseTool):
    """Run only Nuclei templates tagged as CVEs against alive HTTP targets."""

    name = "cve_check"
    binary_name = "nuclei"
    category = ToolCategory.VULN
    description = "CVE-specific Nuclei checks against verified alive URLs"
    parallel_group = "vuln"

    async def run(
        self, domain: str, out_dir: Path, data_dir: Path,
        wordlist: str | None, extra: dict,
    ) -> RunResult:
        alive_file = out_dir / "alive_urls.txt"
        if not alive_file.exists() or not alive_file.read_text(errors="replace").strip():
            return RunResult("", "No verified alive URLs; CVE check skipped", 0, 0)
        output = out_dir / "cve_results.jsonl"
        command = [
            "nuclei", "-list", str(alive_file), "-tags", "cve",
            "-severity", "low,medium,high,critical", "-jsonl", "-o", str(output), "-silent",
        ]
        result = await self._exec(command, timeout=3600)
        if result.returncode != 0 and "unknown flag" in (result.stderr or "").lower():
            command[command.index("-jsonl")] = "-json"
            result = await self._exec(command, timeout=3600)
        return result

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """Normalize CVE findings with explicit CVE identifiers and evidence."""
        rows: list[dict[str, Any]] = []
        lines = result.lines or self._read_lines(self.output_dir / domain / "cve_results.jsonl")
        for line in lines:
            try:
                finding = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            info = finding.get("info") or {}
            classification = info.get("classification") or {}
            raw_ids = classification.get("cve-id") or classification.get("cve_id") or []
            if isinstance(raw_ids, str):
                raw_ids = [raw_ids]
            discovered = CVE_RE.findall(" ".join([
                str(finding.get("template-id") or ""), str(info.get("name") or ""),
                " ".join(str(value) for value in raw_ids),
            ]))
            cve_ids = sorted({value.upper() for value in discovered})
            rows.append({
                "template_id": finding.get("template-id", ""),
                "cve_ids": cve_ids,
                "name": info.get("name") or (cve_ids[0] if cve_ids else "CVE finding"),
                "severity": info.get("severity", finding.get("severity", "unknown")),
                "host": finding.get("host", ""),
                "url": finding.get("matched-at") or finding.get("host", ""),
                "matched_at": finding.get("matched-at", ""),
                "description": info.get("description", ""),
                "references": info.get("reference") or [],
                "request": str(finding.get("request") or "")[:2000],
                "response": str(finding.get("response") or "")[:2000],
                "state": "cve_detected",
                "source": "nuclei-cve",
            })
        return rows
