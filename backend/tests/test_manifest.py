"""Execution manifest integrity tests."""
from __future__ import annotations

import json
import uuid

from models import Scan, ToolCategory, ToolResult
from scan_engine import _write_execution_manifest


def test_manifest_hashes_artifacts_and_summarizes_tools(tmp_path) -> None:
    scan = Scan(
        project_id=str(uuid.uuid4()), tools=["dnsx"],
        custom_headers={"Authorization": "Bearer manifest-secret"},
    )
    scan.scope_hash = "scope-hash"
    artifact = tmp_path / "example.com" / "dnsx.txt"
    artifact.parent.mkdir()
    artifact.write_text("app.example.com\n")
    result = ToolResult(
        scan_id=scan.id, project_id=scan.project_id, tool="dnsx",
        category=ToolCategory.DNS, domain="example.com",
        data=[{"host": "app.example.com"}],
    )

    manifest_path = _write_execution_manifest(
        scan, tmp_path, ["example.com"], [], [result],
    )
    manifest = json.loads(manifest_path.read_text())

    assert manifest["scope_hash"] == "scope-hash"
    assert manifest["tool_results"][0]["count"] == 1
    assert manifest["artifacts"][0]["path"] == "example.com/dnsx.txt"
    assert len(manifest["artifacts"][0]["sha256"]) == 64
    assert manifest["custom_header_names"] == ["Authorization"]
    assert "manifest-secret" not in manifest_path.read_text()
