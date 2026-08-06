"""gau — GetAllURLs (Wayback + CommonCrawl + OTX + URLScan).

gau reads newline-delimited domains on stdin, so we feed every discovered
subdomain. Output is written to a file so partial results survive a timeout.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult


class GauTool(BaseTool):
    name = "gau"
    category = ToolCategory.URL
    description = "URL discovery: Wayback + CommonCrawl + OTX + URLScan (all subdomains)"
    parallel_group = "urls"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        hosts = self._target_hosts(domain, out_dir)
        outfile = out_dir / "gau.txt"
        # --subs keeps results scoped to each host's own subdomains; -o streams to
        # disk so a timeout still leaves whatever was collected.
        result = await self._exec_stdin(
            ["gau", "--subs", "--threads", "5", "--o", str(outfile)],
            "\n".join(hosts),
            timeout=600,
        )
        raw = self._read_lines(outfile) or [l for l in result.stdout.splitlines() if l.strip().startswith("http")]
        # gau aggregates archive sources — validate so dead historical links are dropped.
        valid = await self._validate_urls(raw, out_dir, "gau")
        outfile.write_text("\n".join(valid) + ("\n" if valid else ""))
        return RunResult("\n".join(valid), result.stderr, result.returncode, result.elapsed)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        lines = self._read_lines(self.output_dir / domain / "gau.txt") or result.lines
        seen, rows = set(), []
        for line in lines:
            if line.startswith("http") and line not in seen:
                seen.add(line)
                rows.append({"url": line, "source": "gau"})
        return rows
