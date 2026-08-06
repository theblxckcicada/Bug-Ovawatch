"""Advanced Google dorking — generates dorks AND executes them to return results.

Search backends, in priority order:
  1. Google Programmable Search (CSE) JSON API — used when both
     ``GOOGLE_CSE_API_KEY`` and ``GOOGLE_CSE_CX`` are configured in Settings.
     This is the supported, ToS-friendly way to query Google programmatically.
  2. DuckDuckGo HTML endpoint — a no-API-key fallback that honours most dork
     operators (``site:``, ``filetype:``, ``intitle:``) and returns real result
     links so the dork tab is populated even without Google credentials.

If every backend is unavailable, the tool degrades gracefully to emitting the
dork query + a ready-to-click Google URL (the original behaviour) so nothing is
lost.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

import aiohttp

from models import ToolCategory
from tools.base import BaseTool, RunResult, clean_tool_output

# Keep total runtime and request volume bounded — dorking is a recon aid, not a crawl.
MAX_DORKS_SEARCHED = 14
MAX_RESULTS_PER_DORK = 10
INTER_QUERY_DELAY = 1.0  # politeness delay between search requests
RESULTS_FILE = "google_dorks_results.json"

_DDG_LINK_RE = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
_DDG_SNIPPET_RE = re.compile(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")


class GoogleDorksTool(BaseTool):
    name = "google_dorks"
    binary_name = None
    category = ToolCategory.DORK
    description = "Generate advanced Google dorks and fetch live search results"
    parallel_group = "analysis"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        hosts = self._read_lines(out_dir / "subdomains_merged.txt") or [domain]
        hosts = sorted({self._extract_host(h) for h in hosts if self._extract_host(h)})[:50]
        dorks = self._build_dorks(domain, hosts)

        # Reference Markdown (clickable dorks) is always written.
        self._write_markdown(domain, dorks, out_dir)

        backend = self._select_backend()
        rows: list[dict[str, Any]] = []
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20),
                headers={"User-Agent": "Mozilla/5.0 (compatible; ShadowGrid/1.0)"},
            ) as session:
                for dork in dorks[:MAX_DORKS_SEARCHED]:
                    hits = await self._search(session, backend, dork["dork"])
                    if hits:
                        for hit in hits:
                            rows.append({**self._row_meta(dork), **hit})
                    else:
                        # Preserve the dork even when it returned nothing to search.
                        rows.append({**self._row_meta(dork), "title": "", "url": "",
                                     "snippet": "(no results)", "engine": backend})
                    await asyncio.sleep(INTER_QUERY_DELAY)

            # Keep the remaining (unsearched) dorks as ready-to-click reference rows so
            # the full attack-surface dork set is still available in the UI.
            for dork in dorks[MAX_DORKS_SEARCHED:]:
                rows.append({**self._row_meta(dork), "title": "", "url": dork["google_url"],
                             "snippet": "Not auto-searched — open manually", "engine": "manual"})
        except Exception as exc:  # network failure → fall back to link-only rows
            rows = [{**self._row_meta(d), "title": "", "url": d["google_url"],
                     "snippet": "Search backend unavailable — open manually",
                     "engine": "manual"} for d in dorks]
            (out_dir / RESULTS_FILE).write_text(json.dumps(rows, indent=2), encoding="utf-8")
            return RunResult(json.dumps(rows), clean_tool_output(str(exc)), 0, 0.0)

        (out_dir / RESULTS_FILE).write_text(json.dumps(rows, indent=2), encoding="utf-8")
        return RunResult(json.dumps(rows), "", 0, 0.0)

    # ── Search backends ──────────────────────────────────────────────
    def _select_backend(self) -> str:
        if os.environ.get("GOOGLE_CSE_API_KEY") and os.environ.get("GOOGLE_CSE_CX"):
            return "google_cse"
        return "duckduckgo"

    async def _search(self, session: aiohttp.ClientSession, backend: str, query: str) -> list[dict[str, str]]:
        try:
            if backend == "google_cse":
                return await self._search_google_cse(session, query)
            return await self._search_duckduckgo(session, query)
        except Exception:
            return []

    async def _search_google_cse(self, session: aiohttp.ClientSession, query: str) -> list[dict[str, str]]:
        params = {
            "key": os.environ["GOOGLE_CSE_API_KEY"],
            "cx": os.environ["GOOGLE_CSE_CX"],
            "q": query,
            "num": str(MAX_RESULTS_PER_DORK),
        }
        async with session.get("https://www.googleapis.com/customsearch/v1", params=params) as resp:
            if resp.status >= 400:
                return []
            data = await resp.json()
        hits = []
        for item in (data.get("items") or [])[:MAX_RESULTS_PER_DORK]:
            hits.append({
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "snippet": item.get("snippet", ""),
                "engine": "google_cse",
            })
        return hits

    async def _search_duckduckgo(self, session: aiohttp.ClientSession, query: str) -> list[dict[str, str]]:
        async with session.post(
            "https://html.duckduckgo.com/html/", data={"q": query}
        ) as resp:
            if resp.status >= 400:
                return []
            html = await resp.text()

        snippets = [self._strip_html(s) for s in _DDG_SNIPPET_RE.findall(html)]
        hits = []
        for idx, (href, title) in enumerate(_DDG_LINK_RE.findall(html)):
            url = self._decode_ddg_href(href)
            if not url:
                continue
            hits.append({
                "title": self._strip_html(title),
                "url": url,
                "snippet": snippets[idx] if idx < len(snippets) else "",
                "engine": "duckduckgo",
            })
            if len(hits) >= MAX_RESULTS_PER_DORK:
                break
        return hits

    @staticmethod
    def _decode_ddg_href(href: str) -> str:
        """DuckDuckGo wraps result links in a redirect carrying the real target in
        the ``uddg`` query parameter."""
        if href.startswith("//"):
            href = "https:" + href
        parsed = urlparse(href)
        if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
            target = parse_qs(parsed.query).get("uddg", [])
            if target:
                return unquote(target[0])
        return href if href.startswith("http") else ""

    @staticmethod
    def _strip_html(value: str) -> str:
        return unescape(_TAG_RE.sub("", value or "")).strip()

    # ── Dork generation ──────────────────────────────────────────────
    def _row_meta(self, dork: dict[str, str]) -> dict[str, str]:
        return {
            "priority": dork["priority"],
            "purpose": dork["purpose"],
            "dork": dork["dork"],
            "google_url": dork["google_url"],
            "source": "google_dorks",
        }

    def _row(self, priority: str, purpose: str, dork: str) -> dict[str, str]:
        return {
            "priority": priority,
            "purpose": purpose,
            "dork": dork,
            "google_url": f"https://www.google.com/search?q={quote_plus(dork)}",
            "source": "google_dorks",
        }

    def _build_dorks(self, domain: str, hosts: list[str]) -> list[dict[str, str]]:
        root = domain.strip().lower()
        dorks: list[dict[str, str]] = [
            self._row("P1", "Potential login/admin panels", f"site:{root} (inurl:admin OR inurl:login OR inurl:signin OR intitle:admin)"),
            self._row("P1", "Public config/secrets exposure", f"site:{root} (ext:env OR ext:ini OR ext:conf OR ext:config OR ext:yml OR ext:yaml)"),
            self._row("P1", "Database/backup leakage", f"site:{root} (ext:sql OR ext:db OR ext:bak OR ext:backup OR ext:old OR ext:zip OR ext:tar OR ext:gz)"),
            self._row("P1", "Stack traces and verbose errors", f"site:{root} (\"stack trace\" OR \"Traceback\" OR \"Unhandled exception\" OR \"System.NullReferenceException\")"),
            self._row("P1", "Cloud keys/tokens accidentally indexed", f"site:{root} (\"AKIA\" OR \"secret_key\" OR \"client_secret\" OR \"api_key\" OR \"access_token\")"),
            self._row("P2", "API docs and Swagger/OpenAPI", f"site:{root} (inurl:swagger OR inurl:openapi OR inurl:api-docs OR intitle:Swagger)"),
            self._row("P2", "Interesting files", f"site:{root} (filetype:pdf OR filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:docx)"),
            self._row("P2", "Directory listings", f"site:{root} intitle:\"index of\""),
            self._row("P2", "Dev/staging/test surface", f"site:{root} (dev OR staging OR test OR qa OR sandbox OR preprod)"),
            self._row("P2", "Parameter-heavy endpoints", f"site:{root} inurl:?"),
            self._row("P2", "Upload/import/export functionality", f"site:{root} (inurl:upload OR inurl:import OR inurl:export OR inurl:file)"),
            self._row("P3", "Robots/sitemap/indexing clues", f"site:{root} (inurl:robots.txt OR inurl:sitemap.xml)"),
            self._row("P3", "Cached third-party mentions", f"\"{root}\" (password OR token OR secret OR leaked OR breached)"),
        ]

        for host in hosts[:15]:
            dorks.extend([
                self._row("P2", f"Host-specific admin/login: {host}", f"site:{host} (inurl:admin OR inurl:login OR inurl:signin)"),
                self._row("P2", f"Host-specific sensitive files: {host}", f"site:{host} (ext:env OR ext:sql OR ext:bak OR intitle:\"index of\")"),
            ])
        return dorks

    def _write_markdown(self, domain: str, dorks: list[dict[str, str]], out_dir: Path) -> None:
        md = [f"# Google Dorks — {domain}", "", "> Generated dorks with live search results in the Dorks tab.", ""]
        for row in dorks:
            md.append(f"## {row['priority']} — {row['purpose']}")
            md.append(f"`{row['dork']}`")
            md.append(f"[Open search]({row['google_url']})")
            md.append("")
        (out_dir / "google_dorks.md").write_text("\n".join(md), encoding="utf-8")

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        results_path = self.output_dir / domain / RESULTS_FILE
        if results_path.exists():
            try:
                return json.loads(results_path.read_text(errors="replace"))
            except Exception:
                pass
        # Fallback: at least surface the generated dorks.
        hosts = self._read_lines(self.output_dir / domain / "subdomains_merged.txt") or [domain]
        return [{**self._row_meta(d), "title": "", "url": d["google_url"],
                 "snippet": "", "engine": "manual"} for d in self._build_dorks(domain, hosts)]
