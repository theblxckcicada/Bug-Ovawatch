"""Cross-program asset, finding, change, and operational health APIs."""
from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import APIRouter

from config import settings
from inventory import compare_inventories
from models import ScanStatus
from tools.registry import get_tool, list_tools
from control_models import SuppressionRule

router = APIRouter(prefix="/portfolio", tags=["portfolio"])


def _storage():
    from main import storage
    return storage


async def _latest_snapshots():
    """Return each program's latest and preceding completed inventory snapshots."""
    storage = _storage()
    rows = []
    for project in await storage.list_projects():
        scans = [
            scan for scan in await storage.list_scans(project.id)
            if scan.status == ScanStatus.COMPLETED
        ]
        scans.sort(key=lambda scan: scan.created_at, reverse=True)
        snapshots = []
        for scan in scans:
            snapshot = await storage.load_inventory(scan.id)
            if snapshot:
                snapshots.append((scan, snapshot))
            if len(snapshots) == 2:
                break
        if snapshots:
            rows.append((project, snapshots[0], snapshots[1] if len(snapshots) > 1 else None))
    return rows


@router.get("")
async def portfolio():
    """Aggregate latest inventories and drift across all application programs."""
    assets, findings, changes = [], [], []
    finding_states = {
        item["id"]: item for item in await _storage().list_control_records("finding_state")
    }
    suppression_rules = [
        SuppressionRule.model_validate(item)
        for item in await _storage().list_control_records("suppression")
        if item.get("enabled", True)
    ]
    programs_with_inventory = 0
    for project, current, previous in await _latest_snapshots():
        scan, snapshot = current
        programs_with_inventory += 1
        asset_values = {asset.id: asset.value for asset in snapshot.assets}
        assets.extend({
            **asset.model_dump(), "project_id": project.id, "project_name": project.name,
            "scan_id": scan.id,
            "finding_count": sum(1 for finding in snapshot.findings if finding.asset_id == asset.id),
            "findings": [
                finding.model_dump() for finding in snapshot.findings if finding.asset_id == asset.id
            ],
            "observations": [
                observation.model_dump() for observation in snapshot.observations
                if observation.asset_id == asset.id
            ],
            "relationships": [
                {
                    **relationship.model_dump(),
                    "source_value": asset_values.get(relationship.source_asset_id, "unknown"),
                    "target_value": asset_values.get(relationship.target_asset_id, "unknown"),
                }
                for relationship in snapshot.relationships
                if asset.id in {relationship.source_asset_id, relationship.target_asset_id}
            ],
        } for asset in snapshot.assets)
        for finding in snapshot.findings:
            workflow = finding_states.get(finding.id, {})
            row = {
                **finding.model_dump(), "project_id": project.id, "project_name": project.name,
                "scan_id": scan.id, "asset_value": asset_values.get(finding.asset_id, "unknown"),
                "disposition": workflow.get("disposition", "new"),
                "assignee": workflow.get("assignee", ""),
                "tags": workflow.get("tags", []),
                "notes": workflow.get("notes", ""),
            }
            if workflow.get("severity_override"):
                row["original_severity"] = row["severity"]
                row["severity"] = workflow["severity_override"]
            row["suppressed"] = any(
                (not rule.project_id or rule.project_id == project.id)
                and (not rule.tool or rule.tool.lower() == finding.tool.lower())
                and (not rule.title_contains or rule.title_contains.lower() in finding.title.lower())
                and (not rule.asset_contains or rule.asset_contains.lower() in row["asset_value"].lower())
                for rule in suppression_rules
            )
            findings.append(row)
        delta = compare_inventories(snapshot, previous[1] if previous else None)
        changes.append({
            **delta.model_dump(), "project_id": project.id, "project_name": project.name,
            "created_at": snapshot.created_at,
        })
    projects = await _storage().list_projects()
    return {
        "assets": assets,
        "findings": findings,
        "changes": changes,
        "summary": {
            "projects": len(projects),
            "programs_with_inventory": programs_with_inventory,
            "assets": len(assets),
            "findings": sum(1 for finding in findings if not finding.get("suppressed")),
            "critical_high": sum(
                1 for finding in findings
                if not finding.get("suppressed")
                and finding["severity"].lower() in {"critical", "high"}
            ),
        },
    }


@router.get("/system")
async def system_status():
    """Return storage capacity and scanner availability for the Settings UI."""
    storage = _storage()
    disk = shutil.disk_usage(settings.output_dir)
    tools = []
    for metadata in list_tools():
        tool = get_tool(metadata["name"], Path(settings.output_dir), Path(settings.data_dir))
        error = tool.availability_error() if tool else "Tool is not registered"
        tools.append({"name": metadata["name"], "available": error is None, "reason": error or ""})
    return {
        "database": str(storage.database_path),
        "database_size": storage.database_path.stat().st_size,
        "output_free": disk.free,
        "output_total": disk.total,
        "tools_available": sum(1 for tool in tools if tool["available"]),
        "tools_total": len(tools),
        "tools": tools,
    }
