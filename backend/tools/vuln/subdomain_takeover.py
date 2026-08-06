"""subdomain_takeover — detect dangling / claimable subdomains.

Takeovers usually live on subdomains whose DNS still points at a deprovisioned
third-party service (CNAME to an unclaimed S3 bucket, Heroku app, GitHub Pages,
etc.). We therefore test the full merged subdomain set, not just HTTP-alive hosts.

Engines (best-effort, results are merged):
  1. nuclei takeover templates  — the guaranteed engine (nuclei ships in the image
     and its takeover templates are well maintained).
  2. subzy                      — used additionally when the binary is present.

Findings are written to the standard results table as high-severity vuln rows.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from models import ToolCategory
from tools.base import BaseTool, RunResult


class SubdomainTakeoverTool(BaseTool):
    name = "subdomain_takeover"
    # nuclei is the always-available engine; the availability gate keys off it.
    binary_name = "nuclei"
    category = ToolCategory.VULN
    description = "Detect dangling subdomains vulnerable to takeover (nuclei + subzy)"
    parallel_group = "vuln"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        candidates = (
            self._read_lines(out_dir / "subdomains_merged.txt")
            or self._read_lines(out_dir / "alive_subdomains.txt")
            or [domain]
        )
        targets_file = out_dir / "takeover_targets.txt"
        targets_file.write_text("\n".join(candidates) + "\n")

        nuclei_out = out_dir / "takeover_nuclei.jsonl"
        result = await self._exec([
            "nuclei", "-list", str(targets_file),
            "-tags", "takeover",
            "-jsonl", "-o", str(nuclei_out), "-silent",
        ], timeout=1800)

        # Older nuclei used -json instead of -jsonl.
        if result.returncode != 0 and "unknown flag" in (result.stderr or "").lower():
            result = await self._exec([
                "nuclei", "-list", str(targets_file),
                "-tags", "takeover",
                "-json", "-o", str(nuclei_out), "-silent",
            ], timeout=1800)

        # Optional second opinion from subzy when it is installed.
        if shutil.which("subzy"):
            subzy_out = out_dir / "subzy.json"
            await self._exec([
                "subzy", "run", "--targets", str(targets_file),
                "--hide_fails", "--output", str(subzy_out),
            ], timeout=900)

        return result

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        out_dir = self.output_dir / domain
        rows: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        # nuclei JSONL findings
        for line in self._read_lines(out_dir / "takeover_nuclei.jsonl"):
            try:
                f = json.loads(line)
            except Exception:
                continue
            host = f.get("host", "") or f.get("matched-at", "")
            template = f.get("template-id", "")
            key = (host, template)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "host": host,
                "template_id": template,
                "name": f.get("info", {}).get("name", "Possible subdomain takeover"),
                "severity": f.get("info", {}).get("severity", "high"),
                "matched_at": f.get("matched-at", ""),
                "service": ",".join(f.get("info", {}).get("tags", []) or []) if isinstance(f.get("info", {}).get("tags"), list) else f.get("info", {}).get("tags", ""),
                "engine": "nuclei",
                "source": "subdomain_takeover",
            })

        # subzy JSON findings (array of {subdomain, engine, vulnerable, ...})
        subzy_path = out_dir / "subzy.json"
        if subzy_path.exists():
            try:
                entries = json.loads(subzy_path.read_text(errors="replace"))
            except Exception:
                entries = []
            for entry in entries if isinstance(entries, list) else []:
                if not entry.get("vulnerable"):
                    continue
                host = entry.get("subdomain", "")
                key = (host, "subzy")
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "host": host,
                    "template_id": "subzy",
                    "name": f"Subdomain takeover — {entry.get('engine', 'unknown service')}",
                    "severity": "high",
                    "matched_at": host,
                    "service": entry.get("engine", ""),
                    "engine": "subzy",
                    "source": "subdomain_takeover",
                })

        return rows
