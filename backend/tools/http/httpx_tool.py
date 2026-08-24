"""ProjectDiscovery httpx — HTTP probing with tech detection.

Important: do not call the binary name ``httpx`` directly in this project.
The Python dependency of the same name can install its own CLI and overwrite
/usr/local/bin/httpx during pip install. The Dockerfile stages the
ProjectDiscovery binary as ``pd-httpx`` to avoid that collision.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

from models import ToolCategory
from tools.base import BaseTool, RunResult


class HttpxTool(BaseTool):
    name = "httpx"
    binary_name = "pd-httpx"
    category = ToolCategory.HTTP
    description = "HTTP service detection with title, status, tech fingerprinting"
    parallel_group = "http"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        alive_file = out_dir / "probe_candidates.txt"
        if not alive_file.exists():
            return RunResult("", "No probe_candidates.txt", 1, 0)
        if not alive_file.read_text(errors="replace").strip():
            return RunResult("", "probe_candidates.txt is empty", 0, 0)

        outfile = out_dir / "httpx.jsonl"
        command = [
            "pd-httpx", "-silent", "-list", str(alive_file),
            "-title", "-status-code", "-follow-redirects",
            "-tech-detect", "-json", "-o", str(outfile),
        ] + self._header_args()
        return await self._exec(command, timeout=900)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        rows = []
        lines = result.lines or self._read_lines(self.output_dir / domain / "httpx.jsonl")
        for line in lines:
            try:
                obj = json.loads(line)
                url = obj.get("url") or obj.get("input") or ""
                techs = obj.get("tech") or obj.get("technologies") or []
                if isinstance(techs, str):
                    techs = [techs]
                rows.append({
                    "url": url,
                    "host": obj.get("host") or self._extract_host(url),
                    "status": obj.get("status-code") or obj.get("status_code"),
                    "title": obj.get("title", ""),
                    "server": obj.get("webserver") or obj.get("web-server", ""),
                    "tech": techs if isinstance(techs, list) else [],
                    "ip": obj.get("a") or obj.get("ip", ""),
                    "state": "http_responding",
                    "source": "httpx",
                })
            except Exception:
                pass
        return [row for row in rows if row.get("url")]
