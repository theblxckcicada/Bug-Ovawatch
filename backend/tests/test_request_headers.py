"""Assessment User-Agent and custom-header security tests."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from models import Scan, ScanCreate
from request_config import DEFAULT_USER_AGENT, target_request_headers
from tools.base import BaseTool
from api.scans import _public_scan


def test_assessment_has_default_user_agent() -> None:
    scan = Scan(project_id="project-1")
    assert scan.user_agent == DEFAULT_USER_AGENT
    assert target_request_headers(scan.user_agent, scan.custom_headers) == {
        "User-Agent": DEFAULT_USER_AGENT,
    }


@pytest.mark.parametrize("headers", [
    {"Host": "attacker.test"},
    {"Content-Length": "1"},
    {"User-Agent": "duplicate"},
    {"X-Test\r\nInjected": "yes"},
    {"X-Test": "safe\r\nInjected: yes"},
])
def test_unsafe_custom_headers_are_rejected(headers: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        ScanCreate(project_id="project-1", custom_headers=headers)


def test_safe_headers_are_normalized_and_cli_logs_are_redacted() -> None:
    body = ScanCreate(
        project_id="project-1", user_agent="Authorized-Assessment/1.0",
        custom_headers={"Authorization": "Bearer secret", "X-Program": "alpha"},
    )
    headers = target_request_headers(body.user_agent, body.custom_headers)
    assert headers["Authorization"] == "Bearer secret"
    command = ["nuclei", "-H", "Authorization: Bearer secret", "-H", "X-Program: alpha"]
    rendered = " ".join(BaseTool._redacted_cmd(command))
    assert "Bearer secret" not in rendered
    assert "alpha" not in rendered
    assert rendered.count("<redacted>") == 2
    scan = Scan(
        project_id="project-1", custom_headers={"Authorization": "Bearer secret"},
    )
    public = _public_scan(scan)
    assert public["custom_headers"] == {"Authorization": "********"}
    tool = SimpleNamespace(_request_headers={"Authorization": "Bearer secret"})
    assert "Bearer secret" not in BaseTool._redact_sensitive_text(
        tool, "invalid Bearer secret",
    )
