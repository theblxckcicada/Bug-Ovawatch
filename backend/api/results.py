"""Results retrieval and safe artifact serving."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse

from config import settings

router = APIRouter(prefix="/results", tags=["results"])


def _get_storage():
    from main import storage
    return storage


def _safe_output_path(scan, rel_path: str) -> Path:
    base = Path(settings.output_dir).resolve()
    if not scan.workspace:
        raise HTTPException(404, "This legacy scan has no isolated artifact workspace")
    workspace = (base / scan.workspace).resolve()
    if base not in workspace.parents:
        raise HTTPException(400, "Invalid scan workspace")
    candidate = (workspace / rel_path).resolve()
    if workspace not in candidate.parents:
        raise HTTPException(400, "Invalid artifact path")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(404, "Artifact not found")
    return candidate


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
