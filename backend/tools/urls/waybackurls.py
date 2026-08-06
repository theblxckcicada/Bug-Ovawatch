"""waybackurls — historical URLs from the Wayback Machine.

waybackurls reads newline-delimited domains on stdin, so we feed it every
discovered subdomain rather than only the apex domain. Output is persisted to a
file so a timeout still yields the URLs collected up to that point.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult


class WaybackUrlsTool(BaseTool):
    name = "waybackurls"
    category = ToolCategory.URL
    description = "Historical URLs from the Wayback Machine (all subdomains)"
    parallel_group = "urls"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        hosts = self._target_hosts(domain, out_dir)
        result = await self._exec_stdin(["waybackurls"], "\n".join(hosts), timeout=600)
        raw = [l for l in result.stdout.splitlines() if l.strip().startswith("http")]
        # Historical Wayback URLs are frequently dead — keep only those still reachable.
        valid = await self._validate_urls(raw, out_dir, "waybackurls")
        (out_dir / "waybackurls.txt").write_text("\n".join(valid) + ("\n" if valid else ""))
        return RunResult("\n".join(valid), result.stderr, result.returncode, result.elapsed)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        lines = result.lines or self._read_lines(self.output_dir / domain / "waybackurls.txt")
        seen, rows = set(), []
        for line in lines:
            if line.startswith("http") and line not in seen:
                seen.add(line)
                rows.append({"url": line, "source": "waybackurls"})
        return rows
