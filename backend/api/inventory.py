"""Normalized asset inventory and assessment change APIs."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from inventory import compare_inventories
from models import ScanStatus


router = APIRouter(prefix="/inventory", tags=["inventory"])


def _get_storage():
    from main import storage
    return storage


@router.get("/{scan_id}")
async def get_inventory(scan_id: str):
    """Return the normalized inventory snapshot for an assessment."""
    storage = _get_storage()
    scan = await storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    snapshot = await storage.load_inventory(scan_id)
    if not snapshot:
        raise HTTPException(404, "Inventory is not available for this scan")
    return snapshot


@router.get("/{scan_id}/delta")
async def get_inventory_delta(scan_id: str):
    """Compare one snapshot with the immediately preceding completed snapshot."""
    storage = _get_storage()
    scan = await storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    current = await storage.load_inventory(scan_id)
    if not current:
        raise HTTPException(404, "Inventory is not available for this scan")

    previous_snapshot = None
    scans = [
        candidate for candidate in await storage.list_scans(scan.project_id)
        if candidate.id != scan.id
        and candidate.status == ScanStatus.COMPLETED
        and candidate.created_at < scan.created_at
    ]
    scans.sort(key=lambda candidate: candidate.created_at, reverse=True)
    for candidate in scans:
        previous_snapshot = await storage.load_inventory(candidate.id)
        if previous_snapshot:
            break

    return compare_inventories(current, previous_snapshot)
