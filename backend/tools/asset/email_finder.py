"""Hunter-backed email discovery with optional deliverability verification."""
from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from typing import Any

import aiohttp

from models import ToolCategory
from tools.base import BaseTool, RunResult

DOMAIN_SEARCH_URL = "https://api.hunter.io/v2/domain-search"
EMAIL_VERIFIER_URL = "https://api.hunter.io/v2/email-verifier"
MAX_EMAILS_PER_DOMAIN = 10
_EMAIL_RE = re.compile(r"^[^\s@]+@([^\s@]+)$", re.IGNORECASE)


class EmailFinderTool(BaseTool):
    """Discover domain emails through Hunter and optionally verify each address."""

    name = "email_finder"
    binary_name = None
    category = ToolCategory.EMAIL
    description = "Hunter email discovery with optional deliverability verification"
    parallel_group = "asset"

    def availability_error(self) -> str | None:
        if not os.getenv("HUNTER_API_KEY"):
            return "HUNTER_API_KEY is not configured in Settings"
        return None

    @staticmethod
    async def _response_json(response: aiohttp.ClientResponse) -> dict[str, Any]:
        """Decode a Hunter response without exposing the API key in errors."""
        body = await response.text()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {}
        if response.status >= 400:
            errors = payload.get("errors") or []
            if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                detail = errors[0].get("details") or errors[0].get("id") or body
            elif isinstance(errors, dict):
                detail = errors.get("details") or errors.get("id") or body
            else:
                detail = body
            raise RuntimeError(f"Hunter API HTTP {response.status}: {str(detail)[:300]}")
        return payload

    async def _verify_email(
        self, session: aiohttp.ClientSession, email: str, api_key: str,
    ) -> dict[str, Any]:
        """Return Hunter's latest verifier data, polling once for a 202 response."""
        for attempt in range(2):
            async with session.get(
                EMAIL_VERIFIER_URL,
                params={"email": email, "api_key": api_key},
            ) as response:
                if response.status == 202 and attempt == 0:
                    await response.read()
                    await asyncio.sleep(2)
                    continue
                payload = await self._response_json(response)
                return payload.get("data") or {}
        return {"status": "unknown"}

    async def run(
        self, domain: str, out_dir: Path, data_dir: Path,
        wordlist: str | None, extra: dict,
    ) -> RunResult:
        api_key = os.environ.get("HUNTER_API_KEY", "").strip()
        verify_requested = bool(extra.get("verify_emails", False))
        output_path = out_dir / "hunter_emails.json"

        try:
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(
                timeout=timeout,
                headers={"User-Agent": "ShadowGrid/3.1"},
            ) as session:
                async with session.get(
                    DOMAIN_SEARCH_URL,
                    params={
                        "domain": domain,
                        "limit": str(MAX_EMAILS_PER_DOMAIN),
                        "api_key": api_key,
                    },
                ) as response:
                    payload = await self._response_json(response)

                emails = (payload.get("data") or {}).get("emails") or []
                if verify_requested and emails:
                    semaphore = asyncio.Semaphore(3)

                    async def verify(item: dict[str, Any]) -> None:
                        email = str(item.get("value") or "").strip().lower()
                        if not email:
                            return
                        try:
                            async with semaphore:
                                item["_verification"] = await self._verify_email(
                                    session, email, api_key
                                )
                        except (aiohttp.ClientError, TimeoutError, RuntimeError) as exc:
                            item["_verification"] = {
                                "status": "unknown",
                                "error": str(exc)[:300],
                            }

                    await asyncio.gather(*(
                        verify(item) for item in emails if isinstance(item, dict)
                    ))

                payload["_verification_requested"] = verify_requested
                output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                return RunResult(json.dumps(payload), "", 0, 0.0)
        except (aiohttp.ClientError, TimeoutError, OSError, RuntimeError) as exc:
            return RunResult("", f"Hunter email discovery failed: {exc}", 1, 0.0)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """Normalize in-scope Hunter contacts and explicit verifier outcomes."""
        if not result.stdout:
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        data = payload.get("data") or {}
        verification_requested = bool(payload.get("_verification_requested", False))
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in (data.get("emails") or [])[:MAX_EMAILS_PER_DOMAIN]:
            if not isinstance(item, dict):
                continue
            email = str(item.get("value") or "").strip().lower()
            match = _EMAIL_RE.fullmatch(email)
            if not match or match.group(1).lower().rstrip(".") != domain.lower().rstrip("."):
                continue
            if email in seen:
                continue
            seen.add(email)

            verification = item.get("_verification") or {}
            verification_status = (
                str(verification.get("status") or "unknown").lower()
                if verification_requested else "not_requested"
            )
            sources = [
                str(source.get("uri"))
                for source in item.get("sources") or []
                if isinstance(source, dict) and source.get("uri")
            ][:20]
            rows.append({
                "email": email,
                "domain": domain.lower(),
                "first_name": item.get("first_name") or "",
                "last_name": item.get("last_name") or "",
                "full_name": " ".join(
                    str(value) for value in (item.get("first_name"), item.get("last_name"))
                    if value
                ),
                "position": item.get("position") or "",
                "department": item.get("department") or "",
                "seniority": item.get("seniority") or "",
                "type": item.get("type") or "",
                "confidence": item.get("confidence"),
                "sources": sources,
                "verification_requested": verification_requested,
                "verification_status": verification_status,
                "verification_score": verification.get("score"),
                "verification_details": verification,
                "state": (
                    "email_verified" if verification_status == "valid"
                    else "email_discovered"
                ),
                "source": "hunter",
            })
        return rows
