"""Unit tests for the project update + clear-data endpoints (T4, T5).

The endpoint coroutines are driven directly with an in-memory fake storage, so no
FastAPI server, real storage, or process registry is required.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

import api.projects as projects
from models import Project, ProjectUpdate, Scan, ScanStatus


class _FakeStore:
    def __init__(self) -> None:
        self.projects: dict[str, Project] = {}
        self.scans: dict[str, Scan] = {}
        self.deleted: list[str] = []

    async def get_project(self, pid: str):
        return self.projects.get(pid)

    async def save_project(self, project: Project) -> None:
        self.projects[project.id] = project

    async def list_scans(self, pid: str):
        return [s for s in self.scans.values() if s.project_id == pid]

    async def delete_scan(self, scan_id: str, pid: str) -> None:
        self.scans.pop(scan_id, None)
        self.deleted.append(scan_id)


@pytest.fixture
def store(monkeypatch):
    fake = _FakeStore()
    monkeypatch.setattr(projects, "_get_storage", lambda: fake)
    return fake


def test_update_description_only(store):
    project = Project(name="Acme")
    store.projects[project.id] = project
    updated = asyncio.run(projects.update_project(project.id, ProjectUpdate(description="new desc")))
    assert updated.description == "new desc"
    assert updated.name == "Acme"  # untouched


def test_update_missing_project_404(store):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(projects.update_project("nope", ProjectUpdate(description="x")))
    assert exc.value.status_code == 404


def test_update_blank_name_rejected(store):
    project = Project(name="Acme")
    store.projects[project.id] = project
    with pytest.raises(HTTPException) as exc:
        asyncio.run(projects.update_project(project.id, ProjectUpdate(name="   ")))
    assert exc.value.status_code == 400


def test_clear_removes_all_scans_and_resets_count(store, monkeypatch):
    import process_registry

    async def _noop(scan_id: str) -> int:
        return 0

    monkeypatch.setattr(process_registry, "terminate_scan", _noop)

    project = Project(name="Acme", scan_count=3)
    store.projects[project.id] = project
    for sid, status in [
        ("s1", ScanStatus.COMPLETED),
        ("s2", ScanStatus.RUNNING),
        ("s3", ScanStatus.CANCELLED),
    ]:
        store.scans[sid] = Scan(id=sid, project_id=project.id, status=status)

    result = asyncio.run(projects.clear_project_data(project.id))
    assert result["cleared_scans"] == 3
    assert store.scans == {}
    assert store.projects[project.id].scan_count == 0


def test_clear_missing_project_404(store):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(projects.clear_project_data("nope"))
    assert exc.value.status_code == 404
