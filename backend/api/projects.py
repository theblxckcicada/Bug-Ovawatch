"""Projects, Targets CRUD."""
from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from models import (
    Project,
    ProjectCreate,
    ProjectUpdate,
    ScanStatus,
    Target,
    TargetCreate,
)

router = APIRouter(prefix="/projects", tags=["projects"])


def _get_storage():
    from main import storage
    return storage


@router.get("/")
async def list_projects():
    return await _get_storage().list_projects()


@router.post("/", status_code=201)
async def create_project(body: ProjectCreate):
    p = Project(name=body.name, description=body.description)
    await _get_storage().save_project(p)
    return p


@router.get("/{project_id}")
async def get_project(project_id: str):
    p = await _get_storage().get_project(project_id)
    if not p:
        raise HTTPException(404, "Project not found")
    return p


@router.patch("/{project_id}")
async def update_project(project_id: str, body: ProjectUpdate):
    """Update editable project fields (name, description) after creation.

    Only fields present in the request body are applied, so a caller can change
    just the description without resending the name. Returns the updated project.
    """
    storage = _get_storage()
    project = await storage.get_project(project_id)
    if not project:
        raise HTTPException(404, "Project not found")

    changes = body.model_dump(exclude_unset=True)
    if "name" in changes and changes["name"] is not None:
        new_name = changes["name"].strip()
        if not new_name:
            raise HTTPException(400, "Project name cannot be empty")
        project.name = new_name
    if "description" in changes and changes["description"] is not None:
        project.description = changes["description"]

    project.updated_at = datetime.now(timezone.utc)
    await storage.save_project(project)
    return project


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: str):
    await _get_storage().delete_project(project_id)


@router.post("/{project_id}/clear")
async def clear_project_data(project_id: str):
    """Remove all scan history for a project — every scan and its results,
    including cancelled ones — while keeping the project and its targets.

    Any scan still running is terminated first so no orphaned tool process
    outlives the wipe. Idempotent: clearing an already-empty project is a no-op
    that returns ``cleared_scans: 0``.
    """
    import process_registry

    storage = _get_storage()
    project = await storage.get_project(project_id)
    if not project:
        raise HTTPException(404, "Project not found")

    cleared = 0
    for scan in await storage.list_scans(project_id):
        if scan.status == ScanStatus.RUNNING:
            await process_registry.terminate_scan(scan.id)
        await storage.delete_scan(scan.id, project_id)
        cleared += 1

    project.scan_count = 0
    project.updated_at = datetime.now(timezone.utc)
    await storage.save_project(project)
    return {"cleared_scans": cleared}


# ── Targets ──────────────────────────────────────────────────────

@router.get("/{project_id}/targets")
async def list_targets(project_id: str):
    return await _get_storage().list_targets(project_id)


@router.post("/{project_id}/targets", status_code=201)
async def add_target(project_id: str, body: TargetCreate):
    t = Target(project_id=project_id, domain=body.domain, is_oos=body.is_oos)
    await _get_storage().save_target(t)
    return t


@router.delete("/{project_id}/targets/{target_id}", status_code=204)
async def delete_target(project_id: str, target_id: str):
    await _get_storage().delete_target(target_id, project_id)
