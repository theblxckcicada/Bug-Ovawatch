"""Persistence, relational-integrity, and legacy migration tests for SQLite."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from models import Project, Scan, Target, ToolCategory, ToolResult
from storage import SqlStorage


@pytest.mark.asyncio
async def test_sql_storage_round_trip_and_cascade_delete(tmp_path: Path) -> None:
    """Deleting a project cascades through all SQL-owned child records."""
    storage = SqlStorage(tmp_path)
    project = Project(id="project-1", name="Program")
    target = Target(id="target-1", project_id=project.id, domain="example.com")
    scan = Scan(id="scan-1", project_id=project.id)
    result = ToolResult(
        id="result-1",
        scan_id=scan.id,
        project_id=project.id,
        tool="subfinder",
        category=ToolCategory.SUBDOMAIN,
        domain="example.com",
        data=[{"host": "app.example.com"}],
    )

    await storage.save_project(project)
    await storage.save_target(target)
    await storage.save_scan(scan)
    await storage.save_result(result)

    assert (await storage.get_project(project.id)) == project
    assert (await storage.list_targets(project.id))[0] == target
    assert (await storage.list_scans(project.id))[0] == scan
    assert (await storage.list_results(scan.id))[0] == result

    await storage.delete_project(project.id)

    assert await storage.get_project(project.id) is None
    assert await storage.list_targets(project.id) == []
    assert await storage.list_scans(project.id) == []
    assert await storage.list_results(scan.id) == []


@pytest.mark.asyncio
async def test_sql_storage_rejects_orphan_records(tmp_path: Path) -> None:
    """Foreign keys prevent scans from existing without their project."""
    storage = SqlStorage(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        await storage.save_scan(Scan(id="scan-1", project_id="missing"))


@pytest.mark.asyncio
async def test_auth_and_tool_keys_are_sql_backed(tmp_path: Path) -> None:
    storage = SqlStorage(tmp_path)
    await storage.save_auth({"password_hash": "hash", "secret": "secret"})
    await storage.save_tool_api_keys({"github_token": "token"})

    assert (await storage.load_auth())["secret"] == "secret"
    assert (await storage.load_tool_api_keys())["github_token"] == "token"
    assert not (tmp_path / ".meta" / "auth.json").exists()


@pytest.mark.asyncio
async def test_legacy_json_is_imported_once(tmp_path: Path) -> None:
    """Existing deployments retain metadata and authentication during upgrade."""
    legacy = tmp_path / ".meta"
    (legacy / "projects").mkdir(parents=True)
    project = Project(id="legacy-project", name="Legacy")
    (legacy / "projects" / "legacy-project.json").write_text(
        json.dumps(project.model_dump(), default=str), encoding="utf-8"
    )
    (legacy / "auth.json").write_text(
        json.dumps({"password_hash": "old", "secret": "preserved"}), encoding="utf-8"
    )

    storage = SqlStorage(tmp_path)
    assert (await storage.get_project(project.id)) == project
    assert (await storage.load_auth())["secret"] == "preserved"

    # A later legacy edit cannot overwrite authoritative SQL state.
    (legacy / "auth.json").write_text(
        json.dumps({"password_hash": "changed", "secret": "changed"}), encoding="utf-8"
    )
    reopened = SqlStorage(tmp_path)
    assert (await reopened.load_auth())["secret"] == "preserved"
