"""katana — active web crawler."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class KatanaTool(BaseTool):
    name = "katana"
    category = ToolCategory.URL
    description = "Active web crawling with JavaScript support"
    parallel_group = "urls"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        urls_file = out_dir / "alive_urls.txt"
        if not urls_file.exists():
            return RunResult("", "No alive_urls.txt", 1, 0)
        outfile = out_dir / "katana.txt"
        command = [
            "katana", "-list", str(urls_file),
            "-jsl", "-jc", "-d", "3", "-silent", "-o", str(outfile),
        ] + self._header_args()
        result = await self._exec(command, timeout=900)
        raw = self._read_lines(outfile) or [l for l in result.stdout.splitlines() if l.strip().startswith("http")]
        # Re-probe crawled URLs so any that went dead mid/after crawl are removed.
        valid = await self._validate_urls(raw, out_dir, "katana")
        outfile.write_text("\n".join(valid) + ("\n" if valid else ""))
        return RunResult("\n".join(valid), result.stderr, result.returncode, result.elapsed)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        lines = result.lines or self._read_lines(self.output_dir / domain / "katana.txt")
        return [{"url": l, "source": "katana"} for l in lines if l.startswith("http")]
