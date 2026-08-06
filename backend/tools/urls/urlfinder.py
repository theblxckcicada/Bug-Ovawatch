"""urlfinder — passive URL discovery (ProjectDiscovery).

urlfinder accepts a file of domains via ``-list``; we feed it every discovered
subdomain and stream results to disk so partial output survives a timeout.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult


class UrlFinderTool(BaseTool):
    name = "urlfinder"
    category = ToolCategory.URL
    description = "Passive URL discovery via urlfinder (all subdomains)"
    parallel_group = "urls"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        hosts = self._target_hosts(domain, out_dir)
        list_file = out_dir / "urlfinder_targets.txt"
        list_file.write_text("\n".join(hosts) + "\n")
        outfile = out_dir / "urlfinder.txt"
        result = await self._exec(
            ["urlfinder", "-list", str(list_file), "-silent", "-o", str(outfile)],
            timeout=600,
        )
        raw = self._read_lines(outfile) or [l for l in result.stdout.splitlines() if l.strip().startswith("http")]
        # urlfinder is passive — drop links whose hosts/pages no longer respond.
        valid = await self._validate_urls(raw, out_dir, "urlfinder")
        outfile.write_text("\n".join(valid) + ("\n" if valid else ""))
        return RunResult("\n".join(valid), result.stderr, result.returncode, result.elapsed)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        lines = self._read_lines(self.output_dir / domain / "urlfinder.txt") or result.lines
        seen, rows = set(), []
        for line in lines:
            if line.startswith("http") and line not in seen:
                seen.add(line)
                rows.append({"url": line, "source": "urlfinder"})
        return rows
