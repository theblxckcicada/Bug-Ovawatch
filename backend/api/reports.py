"""Attack-surface graph and portable assessment report exports."""
from __future__ import annotations

import csv
import html
import io
import json

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

router = APIRouter(prefix="/reports", tags=["reports"])


def _storage():
    from main import storage
    return storage


async def _snapshot(scan_id: str):
    storage = _storage()
    scan = await storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Assessment not found")
    snapshot = await storage.load_inventory(scan_id)
    if not snapshot:
        raise HTTPException(404, "Inventory is not available")
    project = await storage.get_project(scan.project_id)
    return project, scan, snapshot


@router.get("/{scan_id}/graph")
async def attack_surface_graph(scan_id: str):
    """Return graph-ready nodes and edges from the normalized SQL inventory."""
    _, _, snapshot = await _snapshot(scan_id)
    finding_counts: dict[str, int] = {}
    for finding in snapshot.findings:
        finding_counts[finding.asset_id] = finding_counts.get(finding.asset_id, 0) + 1
    return {
        "nodes": [
            {
                "id": asset.id, "label": asset.value, "type": asset.type.value,
                "states": asset.states, "attributes": asset.attributes,
                "finding_count": finding_counts.get(asset.id, 0),
            }
            for asset in snapshot.assets
        ],
        "edges": [relationship.model_dump(mode="json") for relationship in snapshot.relationships],
    }


@router.get("/{scan_id}/export")
async def export_report(scan_id: str, format: str = Query("html", pattern="^(html|markdown|csv|json|sarif)$")):
    """Export an assessment without relying on commercial report services."""
    project, scan, snapshot = await _snapshot(scan_id)
    name = project.name if project else scan.project_id
    findings = [finding.model_dump(mode="json") for finding in snapshot.findings]
    assets = [asset.model_dump(mode="json") for asset in snapshot.assets]
    if format == "json":
        return Response(
            json.dumps({
                "project": name,
                "scan": {
                    **scan.model_dump(mode="json"),
                    "custom_headers": {key: "********" for key in scan.custom_headers},
                },
                "inventory": snapshot.model_dump(mode="json"),
            }, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="shadowgrid-{scan_id}.json"'},
        )
    if format == "csv":
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=["id", "asset_id", "tool", "title", "severity"])
        writer.writeheader()
        writer.writerows({key: row.get(key, "") for key in writer.fieldnames} for row in findings)
        return Response(stream.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="shadowgrid-{scan_id}.csv"'})
    if format == "sarif":
        rules = {}
        results = []
        asset_values = {asset["id"]: asset["value"] for asset in assets}
        for finding in findings:
            rule_id = f'{finding["tool"]}:{finding["title"]}'
            rules[rule_id] = {"id": rule_id, "shortDescription": {"text": finding["title"]}}
            results.append({
                "ruleId": rule_id,
                "level": {"critical": "error", "high": "error", "medium": "warning"}.get(finding["severity"], "note"),
                "message": {"text": finding["title"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": asset_values.get(finding["asset_id"], "unknown")}}}],
            })
        sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "ShadowGrid", "rules": list(rules.values())}}, "results": results}]}
        return Response(json.dumps(sarif, indent=2), media_type="application/sarif+json", headers={"Content-Disposition": f'attachment; filename="shadowgrid-{scan_id}.sarif"'})
    if format == "markdown":
        lines = [f"# ShadowGrid Assessment: {name}", "", f"- Assets: {len(assets)}", f"- Findings: {len(findings)}", "", "## Findings", ""]
        lines.extend(f'- **{row["severity"].upper()}** {row["title"]} (`{row["tool"]}`)' for row in findings)
        return Response("\n".join(lines), media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="shadowgrid-{scan_id}.md"'})

    rows = "".join(
        f"<tr><td>{html.escape(str(row['severity']))}</td><td>{html.escape(str(row['title']))}</td><td>{html.escape(str(row['tool']))}</td></tr>"
        for row in findings
    )
    document = f"""<!doctype html><html><head><meta charset='utf-8'><title>ShadowGrid Report</title>
<style>body{{font-family:system-ui;margin:40px;color:#17202a}}table{{border-collapse:collapse;width:100%}}th,td{{padding:8px;border:1px solid #ccd1d1;text-align:left}}@media print{{button{{display:none}}}}</style></head>
<body><button onclick='window.print()'>Print / Save as PDF</button><h1>{html.escape(name)}</h1><p>Assessment {html.escape(scan_id)}</p><p>{len(assets)} assets · {len(findings)} findings</p><table><thead><tr><th>Severity</th><th>Finding</th><th>Tool</th></tr></thead><tbody>{rows}</tbody></table></body></html>"""
    return Response(document, media_type="text/html", headers={"Content-Disposition": f'attachment; filename="shadowgrid-{scan_id}.html"'})
