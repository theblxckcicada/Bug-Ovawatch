"""Hunter email discovery and opt-in verification tests."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import tools.asset.email_finder as email_module
from inventory import AssetType, build_inventory
from models import ToolResult
from tools.asset.email_finder import DOMAIN_SEARCH_URL, EMAIL_VERIFIER_URL, EmailFinderTool


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self.payload = payload
        self.status = status

    async def __aenter__(self) -> "_FakeResponse":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def text(self) -> str:
        return json.dumps(self.payload)

    async def read(self) -> bytes:
        return json.dumps(self.payload).encode()


class _FakeSession:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def get(self, url: str, *, params: dict[str, str]) -> _FakeResponse:
        self.calls.append((url, params))
        if url == DOMAIN_SEARCH_URL:
            return _FakeResponse({
                "data": {
                    "domain": "example.test",
                    "emails": [
                        {
                            "value": "alice@example.test",
                            "first_name": "Alice",
                            "last_name": "Admin",
                            "position": "Security Engineer",
                            "type": "personal",
                            "confidence": 95,
                            "sources": [{"uri": "https://example.test/team"}],
                        },
                        {"value": "security@example.test", "type": "generic"},
                    ],
                },
            })
        email = params["email"]
        status = "valid" if email.startswith("alice") else "accept_all"
        return _FakeResponse({"data": {"status": status, "score": 91}})


def _run_tool(
    tmp_path: Path, monkeypatch, verify_emails: bool,
) -> tuple[EmailFinderTool, ToolResult, _FakeSession]:
    session = _FakeSession()
    monkeypatch.setenv("HUNTER_API_KEY", "hunter-secret")
    monkeypatch.setattr(email_module.aiohttp, "ClientSession", lambda *_a, **_kw: session)
    tool = EmailFinderTool(output_dir=tmp_path, data_dir=tmp_path)
    result = asyncio.run(tool.execute(
        "example.test", "scan-1", "project-1", extra={"verify_emails": verify_emails}
    ))
    return tool, result, session


def test_discovery_does_not_verify_without_opt_in(tmp_path: Path, monkeypatch) -> None:
    _, result, session = _run_tool(tmp_path, monkeypatch, verify_emails=False)

    assert [url for url, _ in session.calls] == [DOMAIN_SEARCH_URL]
    assert len(result.data) == 2
    assert {row["verification_status"] for row in result.data} == {"not_requested"}
    stored_payload = (tmp_path / "example.test" / "hunter_emails.json").read_text()
    assert "hunter-secret" not in stored_payload


def test_opt_in_verifies_each_discovered_email(tmp_path: Path, monkeypatch) -> None:
    _, result, session = _run_tool(tmp_path, monkeypatch, verify_emails=True)

    assert [url for url, _ in session.calls].count(EMAIL_VERIFIER_URL) == 2
    assert result.data[0]["verification_status"] == "valid"
    assert result.data[0]["verification_score"] == 91
    assert result.data[1]["verification_status"] == "accept_all"


def test_email_results_become_inventory_assets(tmp_path: Path, monkeypatch) -> None:
    _, result, _ = _run_tool(tmp_path, monkeypatch, verify_emails=True)
    snapshot = build_inventory("scan-1", "project-1", ["example.test"], [result])

    emails = [asset for asset in snapshot.assets if asset.type == AssetType.EMAIL]
    assert {asset.value for asset in emails} == {
        "alice@example.test", "security@example.test",
    }
    assert any(link.type == "has_email_contact" for link in snapshot.relationships)


def test_parser_rejects_out_of_scope_email_domains(tmp_path: Path) -> None:
    tool = EmailFinderTool(output_dir=tmp_path, data_dir=tmp_path)
    result = email_module.RunResult(json.dumps({
        "data": {"emails": [
            {"value": "valid@example.test"},
            {"value": "external@attacker.test"},
        ]},
        "_verification_requested": False,
    }), "", 0, 0.0)

    assert [row["email"] for row in tool.parse(result, "example.test")] == [
        "valid@example.test"
    ]
