"""Security regression tests for target validation and scan confinement."""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from models import Scan
from scope import normalize_domain, scan_workspace, scope_fingerprint
from storage import SqlStorage


@pytest.mark.parametrize("value", [
    "../escape.example.com", "/tmp/escape", "https://example.com",
    "example.com:443", "127.0.0.1", "localhost", "example.com/path",
])
def test_invalid_domain_targets_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_domain(value, allow_wildcard=True)


def test_domain_is_canonicalized_and_wildcard_is_oos_only() -> None:
    assert normalize_domain("WWW.Example.COM.") == "www.example.com"
    assert normalize_domain("*.Example.COM", allow_wildcard=True) == "*.example.com"
    with pytest.raises(ValueError):
        normalize_domain("*.example.com")


def test_workspace_is_confined_to_scan_identity(tmp_path: Path) -> None:
    project_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    workspace = scan_workspace(tmp_path, project_id, scan_id)
    assert workspace == tmp_path / "projects" / project_id / "scans" / scan_id / "assets"


def test_scope_fingerprint_changes_with_policy() -> None:
    first = scope_fingerprint(["example.com"], [], ["dnsx"], None)
    second = scope_fingerprint(["example.com"], ["dev.example.com"], ["dnsx"], None)
    assert first != second


@pytest.mark.asyncio
async def test_artifact_deletion_cannot_escape_workspace(tmp_path: Path) -> None:
    storage = SqlStorage(tmp_path)
    scan = Scan(
        project_id=str(uuid.uuid4()),
        workspace="../outside",
    )
    with pytest.raises(ValueError):
        await storage.delete_scan_artifacts(scan)


@pytest.mark.asyncio
async def test_owned_scan_workspace_is_deleted(tmp_path: Path) -> None:
    storage = SqlStorage(tmp_path)
    scan = Scan(project_id=str(uuid.uuid4()))
    workspace = scan_workspace(tmp_path, scan.project_id, scan.id)
    workspace.mkdir(parents=True)
    (workspace / "evidence.txt").write_text("evidence")
    scan.workspace = str(workspace.relative_to(tmp_path)).replace("\\", "/")

    await storage.delete_scan_artifacts(scan)

    assert not workspace.parent.exists()
