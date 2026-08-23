"""Cross-program portfolio aggregation tests."""
from __future__ import annotations

from datetime import timedelta

import pytest

from api import portfolio as portfolio_api
from inventory import build_inventory
from models import Project, Scan, ScanStatus, ToolCategory, ToolResult, now_utc
from storage import SqlStorage


@pytest.mark.asyncio
async def test_portfolio_uses_latest_completed_inventory(monkeypatch, tmp_path) -> None:
    storage = SqlStorage(tmp_path)
    project = Project(id="project-1", name="Storefront")
    older = Scan(id="scan-old", project_id=project.id, status=ScanStatus.COMPLETED, created_at=now_utc()-timedelta(days=1))
    latest = Scan(id="scan-new", project_id=project.id, status=ScanStatus.COMPLETED, created_at=now_utc())
    await storage.save_project(project)
    await storage.save_scan(older)
    await storage.save_scan(latest)
    await storage.save_inventory(build_inventory(older.id, project.id, ["example.com"], []))
    result = ToolResult(scan_id=latest.id, project_id=project.id, tool="httpx", category=ToolCategory.HTTP, domain="example.com", data=[{"host":"app.example.com","state":"http_responding"}])
    await storage.save_inventory(build_inventory(latest.id, project.id, ["example.com"], [result]))
    monkeypatch.setattr(portfolio_api, "_storage", lambda: storage)

    response = await portfolio_api.portfolio()

    assert response["summary"]["programs_with_inventory"] == 1
    assert any(asset["value"] == "app.example.com" for asset in response["assets"])
    assert response["changes"][0]["previous_scan_id"] == older.id
