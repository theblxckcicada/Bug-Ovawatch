"""WAF fingerprinting for verified alive URLs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from models import ToolCategory
from tools.base import BaseTool, RunResult


class Wafw00fTool(BaseTool):
    """Identify web application firewalls using WAFW00F JSON output."""

    name = "wafw00f"
    category = ToolCategory.TECH
    description = "WAF and reverse-proxy fingerprinting on alive web services"
    parallel_group = "screenshots"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        urls = self._read_lines(out_dir / "alive_urls.txt")
        if not urls:
            return RunResult("", "No verified alive URLs", 0, 0)
        rows: list[Any] = []
        errors: list[str] = []
        for index, url in enumerate(urls[:100]):
            output = out_dir / f"wafw00f_{index}.json"
            result = await self._exec([
                "wafw00f", url, "-f", "json", "-o", str(output), "-a",
            ], timeout=45)
            if output.is_file():
                try:
                    value = json.loads(output.read_text(encoding="utf-8"))
                    rows.extend(value if isinstance(value, list) else [value])
                except (OSError, json.JSONDecodeError):
                    errors.append(f"Could not parse WAF result for {url}")
            elif result.returncode:
                errors.append(result.stderr[:300])
        serialized = json.dumps(rows)
        (out_dir / "wafw00f_results.json").write_text(serialized, encoding="utf-8")
        return RunResult(serialized, "; ".join(errors), 0 if rows or not errors else 1, 0)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """Normalize WAFW00F results across supported JSON schemas."""
        try:
            entries = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return []
        rows = []
        for entry in entries if isinstance(entries, list) else []:
            url = str(entry.get("url") or entry.get("target") or "")
            detected = entry.get("detected") or entry.get("firewall") or entry.get("waf") or []
            if isinstance(detected, str):
                detected = [detected]
            if url:
                rows.append({
                    "url": url, "host": self._extract_host(url),
                    "technologies": [str(item) for item in detected if item],
                    "waf": detected,
                    "state": "waf_detected" if detected else "waf_not_detected",
                    "source": "wafw00f",
                })
        return rows
