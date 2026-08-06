"""Scan management + SSE progress stream."""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse

from models import Scan, ScanCreate, ScanStatus

router = APIRouter(prefix="/scans", tags=["scans"])

TERMINAL_SCAN_STATUSES = {"completed", "failed", "cancelled"}


def _get_storage():
    from main import storage
    return storage


def _get_settings():
    from config import settings
    return settings


@router.post("/", status_code=201)
async def create_scan(body: ScanCreate, background_tasks: BackgroundTasks):
    storage = _get_storage()
    settings = _get_settings()

    project = await storage.get_project(body.project_id)
    if not project:
        raise HTTPException(404, "Project not found")

    targets = await storage.list_targets(body.project_id)
    in_scope = [t.domain for t in targets if not t.is_oos]
    oos = [t.domain for t in targets if t.is_oos]

    if not in_scope:
        raise HTTPException(400, "No in-scope targets defined for this project")

    scan = Scan(project_id=body.project_id, tools=body.tools, wordlist=body.wordlist)
    await storage.save_scan(scan)

    project.scan_count += 1
    await storage.save_project(project)

    from pathlib import Path
    from scan_engine import run_scan

    background_tasks.add_task(
        run_scan,
        scan=scan,
        domains=in_scope,
        oos=oos,
        output_dir=Path(settings.output_dir),
        data_dir=Path(settings.data_dir),
        storage=storage,
        reuse_previous=body.reuse_previous,
    )

    return scan


@router.get("/{project_id}/list")
async def list_scans(project_id: str):
    return await _get_storage().list_scans(project_id)


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    scan = await _get_storage().get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


async def _cancel(scan_id: str) -> dict:
    """Mark a running scan cancelled and terminate its live tool processes."""
    import process_registry

    storage = _get_storage()
    scan = await storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != ScanStatus.RUNNING:
        return {"cancelled": False, "status": scan.status.value}

    scan.status = ScanStatus.CANCELLED
    await storage.save_scan(scan)
    terminated = await process_registry.terminate_scan(scan_id)

    # Delete the cancelled scan's data immediately. The running scan coroutine also
    # purges on exit (the authoritative pass that wins any race with a tool still
    # flushing its result); doing it here as well guarantees cleanup even when no
    # engine task is alive to reach that final pass (e.g. after a backend restart
    # left the scan marked RUNNING). Both passes are idempotent.
    await storage.delete_results(scan_id)
    scan.progress = []
    await storage.save_scan(scan)

    return {"cancelled": True, "terminated_processes": terminated, "status": "cancelled"}


@router.post("/{scan_id}/cancel")
async def cancel_scan_post(scan_id: str):
    """Stop a running scan and kill any in-flight tool processes."""
    return await _cancel(scan_id)


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(scan_id: str):
    await _cancel(scan_id)


@router.get("/{scan_id}/progress")
async def scan_progress_stream(scan_id: str):
    """SSE endpoint — streams persisted progress first, then live events."""
    from scan_engine import get_progress_queue

    async def event_generator():
        storage = _get_storage()
        scan = await storage.get_scan(scan_id)
        if not scan:
            yield f"data: {json.dumps({'tool': '__scan__', 'status': 'failed', 'message': 'Scan not found'})}\n\n"
            return

        # Replay persisted progress so a refresh/reconnect does not lose state.
        replayed = 0
        for progress in scan.progress[-1000:]:
            payload = progress.model_dump(mode="json")
            yield f"data: {json.dumps(payload)}\n\n"
            replayed += 1

        if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            yield f"data: {json.dumps({'tool': '__scan__', 'status': scan.status.value, 'message': scan.status.value})}\n\n"
            return

        q = get_progress_queue(scan_id)
        timeout_counter = 0

        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30)
                yield f"data: {json.dumps(event)}\n\n"

                if event.get("tool") == "__scan__" and event.get("status") in TERMINAL_SCAN_STATUSES:
                    break

            except asyncio.TimeoutError:
                latest = await storage.get_scan(scan_id)
                if latest and latest.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                    yield f"data: {json.dumps({'tool': '__scan__', 'status': latest.status.value, 'message': latest.status.value})}\n\n"
                    break

                yield 'data: {"heartbeat":true}\n\n'
                timeout_counter += 1
                if timeout_counter > 40:  # 20 minutes of silence; client may reconnect.
                    break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
