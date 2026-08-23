"""Normalized inventory and change-detection tests."""
from __future__ import annotations

from models import Project, Scan, ToolCategory, ToolResult
from inventory import AssetType, build_inventory, compare_inventories
from storage import SqlStorage


def _result(tool: str, category: ToolCategory, rows: list[dict]) -> ToolResult:
    return ToolResult(
        scan_id="scan-1", project_id="project-1", tool=tool,
        category=category, domain="example.com", data=rows,
    )


def test_build_inventory_correlates_host_ip_url_service_and_technology() -> None:
    snapshot = build_inventory("scan-1", "project-1", ["example.com"], [
        _result("httpx", ToolCategory.HTTP, [{
            "host": "app.example.com", "ip": "192.0.2.10",
            "url": "https://app.example.com/login", "status": 200,
            "tech": ["Angular", "nginx"], "state": "http_responding",
        }]),
        _result("naabu", ToolCategory.PORT, [{
            "host": "app.example.com", "port": 443,
            "service": "HTTPS", "state": "tcp_reachable",
        }]),
    ])

    by_type = {}
    for asset in snapshot.assets:
        by_type.setdefault(asset.type, []).append(asset.value)

    assert "app.example.com" in by_type[AssetType.HOSTNAME]
    assert "192.0.2.10" in by_type[AssetType.IP_ADDRESS]
    assert "https://app.example.com/login" in by_type[AssetType.URL]
    assert "app.example.com:443" in by_type[AssetType.SERVICE]
    assert set(by_type[AssetType.TECHNOLOGY]) == {"Angular", "nginx"}
    assert {relationship.type for relationship in snapshot.relationships} >= {
        "contains_hostname", "resolves_to", "served_by", "runs_on", "uses_technology",
    }


def test_vulnerability_rows_become_stable_findings() -> None:
    first = build_inventory("scan-1", "project-1", ["example.com"], [
        _result("nuclei", ToolCategory.VULN, [{
            "template_id": "missing-hsts", "name": "Missing HSTS",
            "severity": "low", "host": "app.example.com",
        }]),
    ])
    second = build_inventory("scan-2", "project-1", ["example.com"], [
        ToolResult(
            scan_id="scan-2", project_id="project-1", tool="nuclei",
            category=ToolCategory.VULN, domain="example.com", data=[{
                "template_id": "missing-hsts", "name": "Missing HSTS",
                "severity": "low", "host": "app.example.com",
            }],
        ),
    ])

    assert first.findings[0].id == second.findings[0].id
    assert compare_inventories(second, first).new_findings == []


def test_delta_reports_added_removed_and_resolved() -> None:
    previous = build_inventory("scan-1", "project-1", ["example.com"], [
        _result("nuclei", ToolCategory.VULN, [{
            "template_id": "old-finding", "name": "Old finding",
            "severity": "high", "host": "old.example.com",
        }]),
    ])
    current = build_inventory("scan-2", "project-1", ["example.com"], [
        ToolResult(
            scan_id="scan-2", project_id="project-1", tool="httpx",
            category=ToolCategory.HTTP, domain="example.com",
            data=[{"host": "new.example.com", "state": "http_responding"}],
        ),
    ])

    delta = compare_inventories(current, previous)
    assert any(asset.value == "new.example.com" for asset in delta.added_assets)
    assert any(asset.value == "old.example.com" for asset in delta.removed_assets)
    assert len(delta.resolved_findings) == 1


async def test_inventory_round_trip_and_scan_deletion(tmp_path) -> None:
    storage = SqlStorage(tmp_path)
    await storage.save_project(Project(id="project-1", name="Test"))
    await storage.save_scan(Scan(id="scan-1", project_id="project-1"))
    snapshot = build_inventory("scan-1", "project-1", ["example.com"], [])
    await storage.save_inventory(snapshot)

    loaded = await storage.load_inventory("scan-1")
    assert loaded is not None
    assert loaded.model_dump() == snapshot.model_dump()

    await storage.delete_scan("scan-1", "project-1")
    assert await storage.load_inventory("scan-1") is None
