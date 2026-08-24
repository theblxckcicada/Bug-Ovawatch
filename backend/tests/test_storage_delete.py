"""Unit tests for scan/result deletion in mandatory SQL storage.

Covers the storage primitives behind T3 (cancel purges a scan's data) and T5
(clearing a project removes every scan). Deletion must be idempotent and scoped
to the targeted scan only.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from models import Project, Scan, ScanStatus, ToolCategory, ToolResult
from storage import SqlStorage


def _seed(store: SqlStorage, project_id: str, scan_id: str) -> None:
    asyncio.run(store.save_project(Project(id=project_id, name="Test")))
    asyncio.run(store.save_scan(Scan(id=scan_id, project_id=project_id, status=ScanStatus.RUNNING)))
    asyncio.run(store.save_result(ToolResult(
        scan_id=scan_id, project_id=project_id, tool="subfinder",
        category=ToolCategory.SUBDOMAIN, domain="ex.test",
        data=[{"host": "a.ex.test"}],
    )))


def test_delete_results_removes_only_results(tmp_path: Path):
    store = SqlStorage(tmp_path)
    _seed(store, "p1", "s1")
    blob_id = asyncio.run(store.save_evidence_blob(
        "s1", "capture.png", "image/png", b"image-bytes", "digest-1"
    ))
    assert asyncio.run(store.list_results("s1"))
    assert asyncio.run(store.get_evidence_blob("s1", blob_id)) is not None
    asyncio.run(store.delete_results("s1"))
    assert asyncio.run(store.list_results("s1")) == []
    assert asyncio.run(store.get_evidence_blob("s1", blob_id)) is None
    # The scan record itself is retained.
    assert asyncio.run(store.get_scan("s1")) is not None


def test_delete_results_idempotent(tmp_path: Path):
    store = SqlStorage(tmp_path)
    # Deleting a scan that never had results must not raise.
    asyncio.run(store.delete_results("missing"))


def test_delete_scan_removes_record_and_results(tmp_path: Path):
    store = SqlStorage(tmp_path)
    _seed(store, "p1", "s1")
    asyncio.run(store.delete_scan("s1", "p1"))
    assert asyncio.run(store.get_scan("s1")) is None
    assert asyncio.run(store.list_results("s1")) == []
    # Idempotent second call.
    asyncio.run(store.delete_scan("s1", "p1"))


def test_delete_scan_scoped_to_target(tmp_path: Path):
    store = SqlStorage(tmp_path)
    _seed(store, "p1", "s1")
    _seed(store, "p1", "s2")
    asyncio.run(store.delete_scan("s1", "p1"))
    assert asyncio.run(store.get_scan("s1")) is None
    # A sibling scan's record and results are untouched.
    assert asyncio.run(store.get_scan("s2")) is not None
    assert asyncio.run(store.list_results("s2"))
