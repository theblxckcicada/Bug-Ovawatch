"""Bounded content discovery against verified alive HTTP services."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from models import ToolCategory
from tools.base import BaseTool, RunResult


class FfufTool(BaseTool):
    """Run a conservative ffuf pass against each verified service root."""

    name = "ffuf"
    category = ToolCategory.URL
    description = "Opt-in bounded content discovery against alive web services"
    parallel_group = "urls"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        alive = self._read_lines(out_dir / "alive_urls.txt")
        if not alive:
            return RunResult("", "No verified alive URLs", 0, 0)
        content_wordlist = data_dir / "wordlists" / "content.txt"
        if not content_wordlist.is_file():
            return RunResult("", "Content wordlist is unavailable", 1, 0)

        combined: list[dict[str, Any]] = []
        errors: list[str] = []
        for index, value in enumerate(alive[:50]):
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            base = f"{parsed.scheme}://{parsed.netloc}"
            output = out_dir / f"ffuf_{index}.json"
            command = [
                "ffuf", "-u", f"{base}/FUZZ", "-w", str(content_wordlist),
                "-of", "json", "-o", str(output), "-ac", "-mc", "all",
                "-fc", "404", "-rate", "25", "-t", "10", "-timeout", "8",
                "-maxtime", "120", "-noninteractive", "-s",
            ] + self._header_args()
            result = await self._exec(command, timeout=150)
            if output.is_file():
                try:
                    payload = json.loads(output.read_text(encoding="utf-8"))
                    combined.extend(payload.get("results") or [])
                except (OSError, json.JSONDecodeError):
                    errors.append(f"Could not parse ffuf output for {base}")
            elif result.returncode:
                errors.append(result.stderr[:300])
        serialized = json.dumps(combined)
        (out_dir / "ffuf_results.json").write_text(serialized, encoding="utf-8")
        return RunResult(serialized, "; ".join(errors), 0 if combined or not errors else 1, 0)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """Normalize ffuf JSON while retaining response matching evidence."""
        try:
            entries = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return []
        rows = []
        for entry in entries if isinstance(entries, list) else []:
            url = str(entry.get("url") or "")
            if not url:
                continue
            rows.append({
                "url": url, "host": self._extract_host(url),
                "status": entry.get("status"), "length": entry.get("length"),
                "words": entry.get("words"), "lines": entry.get("lines"),
                "content_type": entry.get("content-type", ""),
                "state": "content_discovered", "source": "ffuf",
            })
        return rows
