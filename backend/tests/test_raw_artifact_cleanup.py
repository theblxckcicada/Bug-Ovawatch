"""Tests for deleting raw scan outputs while retaining SQL records."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi import HTTPException

import api.results as results_api
from models import Project, Scan, ScanStatus, ToolCategory, ToolResult
from scope import scan_workspace
from storage import SqlStorage


def _seed_finished_scan(tmp_path: Path) -> tuple[SqlStorage, Project, Scan, Path]:
    """Create a completed assessment with both SQL evidence and raw files."""
    storage = SqlStorage(tmp_path)
    project = Project(name="Retained program")
    scan = Scan(project_id=project.id, status=ScanStatus.COMPLETED)
    workspace = scan_workspace(tmp_path, project.id, scan.id)
    workspace.mkdir(parents=True)
    (workspace / "naabu.txt").write_text("app.example.test:443\n")
    (workspace / "httpx.jsonl").write_text('{"url":"https://app.example.test"}\n')
    scan.workspace = workspace.relative_to(tmp_path).as_posix()

    asyncio.run(storage.save_project(project))
    asyncio.run(storage.save_scan(scan))
    asyncio.run(storage.save_result(ToolResult(
        scan_id=scan.id,
        project_id=project.id,
        tool="naabu",
        category=ToolCategory.PORT,
        domain="example.test",
        data=[{"host": "app.example.test", "port": 443}],
    )))
    return storage, project, scan, workspace


def test_cleanup_deletes_files_but_retains_database_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, project, scan, workspace = _seed_finished_scan(tmp_path)
    monkeypatch.setattr(results_api, "_get_storage", lambda: storage)
    monkeypatch.setattr(results_api.settings, "output_dir", str(tmp_path))

    response = asyncio.run(results_api.delete_raw_artifacts(scan.id))

    assert response["files_deleted"] == 2
    assert response["bytes_freed"] > 0
    assert response["database_records_retained"] is True
    assert not workspace.parent.exists()
    assert asyncio.run(storage.get_project(project.id)) is not None
    retained_scan = asyncio.run(storage.get_scan(scan.id))
    assert retained_scan is not None
    assert retained_scan.artifacts_deleted_at is not None
    assert len(asyncio.run(storage.list_results(scan.id))) == 1


def test_cleanup_rejects_active_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, _, scan, workspace = _seed_finished_scan(tmp_path)
    scan.status = ScanStatus.RUNNING
    asyncio.run(storage.save_scan(scan))
    monkeypatch.setattr(results_api, "_get_storage", lambda: storage)
    monkeypatch.setattr(results_api.settings, "output_dir", str(tmp_path))

    with pytest.raises(HTTPException) as exc:
        asyncio.run(results_api.delete_raw_artifacts(scan.id))

    assert exc.value.status_code == 409
    assert workspace.exists()
    assert asyncio.run(storage.list_results(scan.id))
