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
    screenshot = workspace / "example.test" / "screenshots" / "home.png"
    screenshot.parent.mkdir(parents=True)
    screenshot.write_bytes(b"\x89PNG\r\n\x1a\n" + (b"screenshot" * 256))
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
    asyncio.run(storage.save_result(ToolResult(
        scan_id=scan.id,
        project_id=project.id,
        tool="gowitness",
        category=ToolCategory.SCREENSHOT,
        domain="example.test",
        data=[{
            "filename": "home.png",
            "path": screenshot.relative_to(workspace).as_posix(),
            "source": "gowitness",
        }],
    )))
    return storage, project, scan, workspace


def test_cleanup_deletes_files_but_retains_database_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, project, scan, workspace = _seed_finished_scan(tmp_path)
    monkeypatch.setattr(results_api, "_get_storage", lambda: storage)
    monkeypatch.setattr(results_api.settings, "output_dir", str(tmp_path))

    response = asyncio.run(results_api.delete_raw_artifacts(scan.id))

    assert response["files_deleted"] == 3
    assert response["bytes_freed"] > 0
    assert response["screenshots_stored"] == 1
    assert response["database_records_retained"] is True
    assert not workspace.parent.exists()
    assert asyncio.run(storage.get_project(project.id)) is not None
    retained_scan = asyncio.run(storage.get_scan(scan.id))
    assert retained_scan is not None
    assert retained_scan.artifacts_deleted_at is not None
    retained_results = asyncio.run(storage.list_results(scan.id))
    assert len(retained_results) == 2
    screenshot_row = next(result for result in retained_results if result.tool == "gowitness").data[0]
    assert screenshot_row["blob_id"]
    blob = asyncio.run(storage.get_evidence_blob(scan.id, screenshot_row["blob_id"]))
    assert blob is not None
    assert blob["mime_type"] == "image/png"
    assert blob["content"].startswith(b"\x89PNG")

    served = asyncio.run(
        results_api.get_database_evidence(scan.id, screenshot_row["blob_id"])
    )
    assert served.media_type == "image/png"
    assert bytes(served.body).startswith(b"\x89PNG")


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
