"""nuclei — vulnerability scanning."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

from models import ToolCategory
from tools.base import BaseTool, RunResult


class NucleiTool(BaseTool):
    name = "nuclei"
    category = ToolCategory.VULN
    description = "Vulnerability scanning via nuclei templates (low–critical)"
    parallel_group = "vuln"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        alive_file = out_dir / "alive_urls.txt"
        if not alive_file.exists():
            return RunResult("", "No alive_urls.txt", 0, 0)
        if not alive_file.read_text(errors="replace").strip():
            return RunResult("", "alive_urls.txt is empty — skipping nuclei", 0, 0)

        outfile = out_dir / "nuclei_results.jsonl"
        result = await self._exec([
            "nuclei", "-list", str(alive_file),
            "-exclude-tags", "cve",
            "-severity", "low,medium,high,critical",
            "-jsonl", "-o", str(outfile), "-silent",
        ], timeout=3600)

        # Older nuclei used -json instead of -jsonl.
        if result.returncode != 0 and "unknown flag" in (result.stderr or "").lower():
            result = await self._exec([
                "nuclei", "-list", str(alive_file),
                "-exclude-tags", "cve",
                "-severity", "low,medium,high,critical",
                "-json", "-o", str(outfile), "-silent",
            ], timeout=3600)
        return result

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        rows = []
        lines = result.lines or self._read_lines(self.output_dir / domain / "nuclei_results.jsonl")
        for line in lines:
            try:
                f = json.loads(line)
                rows.append({
                    "template_id": f.get("template-id", ""),
                    "name":        f.get("info", {}).get("name", ""),
                    "severity":    f.get("info", {}).get("severity", f.get("severity", "unknown")),
                    "host":        f.get("host", ""),
                    "matched_at":  f.get("matched-at", ""),
                    "description": f.get("info", {}).get("description", ""),
                    "tags":        f.get("info", {}).get("tags", ""),
                    "request":     f.get("request", "")[:2000],
                    "response":    f.get("response", "")[:2000],
                    "curl":        f.get("curl-command", ""),
                    "timestamp":   f.get("timestamp", ""),
                    "source":      "nuclei",
                })
            except Exception:
                pass
        return rows
