"""Tests for SerpApi-backed Google dork execution."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tool_secrets import normalize_tool_api_keys
from tools.analysis.google_dorks import GoogleDorksTool


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self.payload = payload
        self.status = status

    async def __aenter__(self) -> "_FakeResponse":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def json(self) -> dict[str, Any]:
        return self.payload


class _FakeSession:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.url = ""
        self.params: dict[str, str] = {}

    def get(self, url: str, *, params: dict[str, str]) -> _FakeResponse:
        self.url = url
        self.params = params
        return _FakeResponse(self.payload)


def _tool(tmp_path: Path) -> GoogleDorksTool:
    return GoogleDorksTool(output_dir=tmp_path, data_dir=tmp_path)


def test_serpapi_selected_only_when_key_is_configured(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)
    assert _tool(tmp_path)._select_backend() == "duckduckgo"

    monkeypatch.setenv("SERPAPI_API_KEY", "secret")
    assert _tool(tmp_path)._select_backend() == "serpapi"


def test_serpapi_google_contract_and_organic_result_parsing(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("SERPAPI_API_KEY", "secret")
    session = _FakeSession({
        "organic_results": [{
            "title": "Admin portal",
            "link": "https://admin.example.test/login",
            "snippet": "Sign in",
        }],
    })

    rows = asyncio.run(_tool(tmp_path)._search_serpapi(session, "site:example.test inurl:admin"))

    assert session.url == "https://serpapi.com/search.json"
    assert session.params == {
        "engine": "google",
        "api_key": "secret",
        "q": "site:example.test inurl:admin",
        "num": "10",
        "hl": "en",
    }
    assert "key" not in session.params
    assert "cx" not in session.params
    assert rows == [{
        "title": "Admin portal",
        "url": "https://admin.example.test/login",
        "snippet": "Sign in",
        "engine": "serpapi_google",
    }]


def test_legacy_cse_credentials_are_not_part_of_active_configuration() -> None:
    normalized = normalize_tool_api_keys({
        "google_cse_api_key": "legacy-key",
        "google_cse_cx": "legacy-cx",
        "serpapi_api_key": "serp-key",
    })

    assert normalized["serpapi_api_key"] == "serp-key"
    assert "google_cse_api_key" not in normalized
    assert "google_cse_cx" not in normalized
