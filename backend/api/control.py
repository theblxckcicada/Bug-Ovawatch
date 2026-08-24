"""Scheduling, finding workflow, notification, and audit APIs."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from control_models import (
    AuditEvent, FindingDisposition, FindingState, NotificationChannel,
    ScanSchedule, SuppressionRule, utc_now,
)
from tools.registry import REGISTRY
from request_config import DEFAULT_USER_AGENT

router = APIRouter(prefix="/control", tags=["control"])


def _storage():
    from main import storage
    return storage


async def _audit(action: str, resource_type: str, resource_id: str,
                 project_id: str = "", details: dict | None = None) -> None:
    event = AuditEvent(
        action=action, resource_type=resource_type, resource_id=resource_id,
        project_id=project_id, details=details or {},
    )
    await _storage().save_control_record("audit", event.id, event.model_dump(mode="json"), project_id)


class ScheduleCreate(BaseModel):
    project_id: str
    interval_minutes: int = Field(default=10080, ge=15, le=525600)
    tools: list[str] = Field(min_length=1, max_length=40)
    verify_emails: bool = False
    user_agent: str = DEFAULT_USER_AGENT
    custom_headers: dict[str, str] = Field(default_factory=dict)


@router.get("/schedules")
async def list_schedules(project_id: str | None = None):
    records = await _storage().list_control_records("schedule", project_id)
    for record in records:
        record["custom_headers"] = {
            name: "********" for name in (record.get("custom_headers") or {})
        }
    return records


@router.post("/schedules", status_code=201)
async def create_schedule(body: ScheduleCreate):
    storage = _storage()
    if not await storage.get_project(body.project_id):
        raise HTTPException(404, "Project not found")
    unknown = sorted(set(body.tools) - set(REGISTRY))
    if unknown:
        raise HTTPException(422, f"Unknown tools: {', '.join(unknown)}")
    schedule = ScanSchedule(
        **body.model_dump(), next_run_at=utc_now() + timedelta(minutes=body.interval_minutes),
    )
    await storage.save_control_record("schedule", schedule.id, schedule.model_dump(mode="json"), body.project_id)
    await _audit("schedule_created", "schedule", schedule.id, body.project_id)
    payload = schedule.model_dump(mode="json")
    payload["custom_headers"] = {name: "********" for name in schedule.custom_headers}
    return payload


@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: str):
    await _storage().delete_control_record("schedule", schedule_id)
    await _audit("schedule_deleted", "schedule", schedule_id)


@router.get("/finding-states")
async def list_finding_states(project_id: str | None = None):
    return await _storage().list_control_records("finding_state", project_id)


class FindingUpdate(BaseModel):
    project_id: str
    disposition: FindingDisposition
    assignee: str = Field(default="", max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=30)
    notes: str = Field(default="", max_length=5000)
    severity_override: str = ""


@router.put("/finding-states/{finding_id}")
async def update_finding_state(finding_id: str, body: FindingUpdate):
    if body.severity_override and body.severity_override not in {
        "unknown", "info", "low", "medium", "high", "critical"
    }:
        raise HTTPException(422, "Invalid severity override")
    state = FindingState(id=finding_id, **body.model_dump())
    await _storage().save_control_record(
        "finding_state", finding_id, state.model_dump(mode="json"), body.project_id,
    )
    await _audit(
        "finding_triaged", "finding", finding_id, body.project_id,
        {"disposition": body.disposition.value, "assignee": body.assignee},
    )
    return state


@router.get("/notifications")
async def list_notifications():
    records = await _storage().list_control_records("notification")
    for record in records:
        record["webhook_url"] = "configured"
    return records


@router.post("/notifications", status_code=201)
async def create_notification(channel: NotificationChannel):
    await _storage().save_control_record("notification", channel.id, channel.model_dump(mode="json"))
    await _audit("notification_created", "notification", channel.id)
    return {**channel.model_dump(mode="json"), "webhook_url": "configured"}


@router.delete("/notifications/{channel_id}", status_code=204)
async def delete_notification(channel_id: str):
    await _storage().delete_control_record("notification", channel_id)
    await _audit("notification_deleted", "notification", channel_id)


@router.get("/audit")
async def list_audit_events(project_id: str | None = None, limit: int = 250):
    records = await _storage().list_control_records("audit", project_id)
    return records[:max(1, min(limit, 1000))]


@router.get("/suppressions")
async def list_suppressions(project_id: str | None = None):
    return await _storage().list_control_records("suppression", project_id)


@router.post("/suppressions", status_code=201)
async def create_suppression(rule: SuppressionRule):
    if not any((rule.tool, rule.title_contains, rule.asset_contains)):
        raise HTTPException(422, "At least one suppression matcher is required")
    await _storage().save_control_record(
        "suppression", rule.id, rule.model_dump(mode="json"), rule.project_id,
    )
    await _audit("suppression_created", "suppression", rule.id, rule.project_id)
    return rule


@router.delete("/suppressions/{rule_id}", status_code=204)
async def delete_suppression(rule_id: str):
    await _storage().delete_control_record("suppression", rule_id)
    await _audit("suppression_deleted", "suppression", rule_id)
