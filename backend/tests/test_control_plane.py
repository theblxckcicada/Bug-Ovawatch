"""Scheduling, finding workflow, and audit persistence tests."""
from __future__ import annotations

import asyncio

from control_models import FindingDisposition, FindingState
from finding_workflow import reopen_reappearing_findings
from inventory import InventoryFinding, InventorySnapshot
from models import Project, ResultSeverity
from storage.sql_storage import SqlStorage


def test_control_records_are_durable_and_project_scoped(tmp_path) -> None:
    storage = SqlStorage(tmp_path / "db", output_dir=tmp_path / "output")

    async def exercise() -> None:
        await storage.save_control_record(
            "audit", "event-1", {"id": "event-1", "action": "created"}, "project-1",
        )
        await storage.save_control_record(
            "audit", "event-2", {"id": "event-2", "action": "updated"}, "project-2",
        )
        assert await storage.get_control_record("audit", "event-1") == {
            "id": "event-1", "action": "created",
        }
        scoped = await storage.list_control_records("audit", "project-1")
        assert [row["id"] for row in scoped] == ["event-1"]
        await storage.delete_control_record("audit", "event-1")
        assert await storage.get_control_record("audit", "event-1") is None

    asyncio.run(exercise())


def test_remediated_finding_reopens_when_observed_again(tmp_path) -> None:
    storage = SqlStorage(tmp_path / "db", output_dir=tmp_path / "output")
    project = Project(id="project-1", name="Example")
    finding = InventoryFinding(
        id="finding-1", asset_id="asset-1", tool="nuclei", title="Example",
        severity=ResultSeverity.HIGH, evidence_hash="abc",
    )
    snapshot = InventorySnapshot(
        scan_id="scan-2", project_id=project.id, findings=[finding],
    )
    state = FindingState(
        id=finding.id, project_id=project.id,
        disposition=FindingDisposition.REMEDIATED,
    )

    async def exercise() -> None:
        await storage.save_project(project)
        await storage.save_control_record(
            "finding_state", state.id, state.model_dump(mode="json"), project.id,
        )
        await reopen_reappearing_findings(snapshot, storage)
        saved = await storage.get_control_record("finding_state", state.id)
        assert saved is not None
        assert saved["disposition"] == "reopened"

    asyncio.run(exercise())
