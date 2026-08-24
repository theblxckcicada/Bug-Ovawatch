"""whatweb — technology fingerprinting."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class WhatWebTool(BaseTool):
    name = "whatweb"
    category = ToolCategory.TECH
    description = "Web technology fingerprinting via whatweb"
    parallel_group = "screenshots"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        urls_file = out_dir / "alive_urls.txt"
        if not urls_file.exists():
            return RunResult("", "No alive_urls.txt", 1, 0)
        outfile = out_dir / "whatweb.jsonl"
        command = [
            "whatweb", "--input-file", str(urls_file),
            "--log-json", str(outfile), "--quiet", "--no-errors",
        ] + self._header_args("--header")
        return await self._exec(command, timeout=600)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        rows = []
        out = self.output_dir / domain / "whatweb.jsonl"
        if not out.exists():
            return rows
        for line in self._read_lines(out):
            try:
                obj = json.loads(line)
                for entry in (obj if isinstance(obj, list) else [obj]):
                    plugins = entry.get("plugins", {})
                    rows.append({
                        "url":     entry.get("target", entry.get("uri", "")),
                        "plugins": list(plugins.keys()),
                        "source":  "whatweb",
                    })
            except Exception:
                pass
        return rows
