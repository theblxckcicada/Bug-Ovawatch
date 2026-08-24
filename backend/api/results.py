"""Results retrieval and safe artifact serving."""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse

from config import settings
from models import ScanStatus, now_utc

router = APIRouter(prefix="/results", tags=["results"])


def _get_storage():
    from main import storage
    return storage


def _scan_workspace_path(scan) -> Path:
    """Return a scan's canonical confined workspace or reject unsafe metadata."""
    base = Path(settings.output_dir).resolve()
    if not scan.workspace:
        raise HTTPException(404, "This legacy scan has no isolated artifact workspace")
    workspace = (base / scan.workspace).resolve()
    expected = (
        base / "projects" / scan.project_id / "scans" / scan.id / "assets"
    ).resolve()
    if base not in workspace.parents or workspace != expected:
        raise HTTPException(400, "Invalid scan workspace")
    return workspace


def _safe_output_path(scan, rel_path: str) -> Path:
    workspace = _scan_workspace_path(scan)
    candidate = (workspace / rel_path).resolve()
    if workspace not in candidate.parents:
        raise HTTPException(400, "Invalid artifact path")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(404, "Artifact not found")
    return candidate


def _workspace_stats(workspace: Path) -> tuple[int, int]:
    """Return the regular-file count and byte size for an artifact workspace."""
    file_count = 0
    byte_count = 0
    if not workspace.exists():
        return file_count, byte_count
    for path in workspace.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            byte_count += path.stat().st_size
            file_count += 1
        except OSError:
            continue
    return file_count, byte_count


@router.get("/{scan_id}")
async def get_results(scan_id: str):
    return await _get_storage().list_results(scan_id)


@router.get("/{scan_id}/by-category/{category}")
async def get_results_by_category(scan_id: str, category: str):
    results = await _get_storage().list_results(scan_id)
    return [r for r in results if r.category.value == category]


@router.get("/{scan_id}/summary")
async def get_summary(scan_id: str):
    results = await _get_storage().list_results(scan_id)
    summary = {}
    for r in results:
        cat = r.category.value
        summary[cat] = summary.get(cat, 0) + r.count
    return {
        "scan_id": scan_id,
        "totals": summary,
        "tool_count": len(results),
    }


@router.get("/{scan_id}/artifact")
async def get_artifact(scan_id: str, path: str = Query(..., min_length=1)):
    scan = await _get_storage().get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    artifact = _safe_output_path(scan, path)
    return FileResponse(str(artifact))


@router.get("/{scan_id}/artifact-text", response_class=PlainTextResponse)
async def get_artifact_text(scan_id: str, path: str = Query(..., min_length=1)):
    scan = await _get_storage().get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    artifact = _safe_output_path(scan, path)
    if artifact.suffix.lower() not in {".txt", ".md", ".json", ".jsonl", ".log"}:
        raise HTTPException(400, "Artifact is not a text file")
    return artifact.read_text(errors="replace")


@router.delete("/{scan_id}/artifacts")
async def delete_raw_artifacts(scan_id: str):
    """Delete raw files for a finished scan while retaining all SQL records."""
    storage = _get_storage()
    scan = await storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status in {ScanStatus.PENDING, ScanStatus.RUNNING}:
        raise HTTPException(409, "Raw outputs cannot be deleted while a scan is active")

    workspace = _scan_workspace_path(scan)
    file_count, byte_count = await asyncio.to_thread(_workspace_stats, workspace)
    await storage.delete_scan_artifacts(scan)

    scan.artifacts_deleted_at = now_utc()
    await storage.save_scan(scan)
    return {
        "scan_id": scan.id,
        "files_deleted": file_count,
        "bytes_freed": byte_count,
        "artifacts_deleted_at": scan.artifacts_deleted_at,
        "database_records_retained": True,
    }
