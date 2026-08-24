"""Durable models for scheduling, triage, notifications, and audit history."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl
from pydantic import field_validator
from request_config import DEFAULT_USER_AGENT, validate_custom_headers, validate_user_agent


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(timezone.utc)


class FindingDisposition(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"
    REOPENED = "reopened"


class ScanSchedule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str
    interval_minutes: int = Field(default=10080, ge=15, le=525600)
    tools: list[str] = Field(min_length=1, max_length=40)
    verify_emails: bool = False
    user_agent: str = DEFAULT_USER_AGENT
    custom_headers: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    next_run_at: datetime = Field(default_factory=utc_now)
    last_run_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)

    _validate_user_agent = field_validator("user_agent")(validate_user_agent)
    _validate_custom_headers = field_validator("custom_headers")(validate_custom_headers)


class FindingState(BaseModel):
    id: str
    project_id: str
    disposition: FindingDisposition = FindingDisposition.NEW
    assignee: str = Field(default="", max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=30)
    notes: str = Field(default="", max_length=5000)
    severity_override: str = ""
    updated_at: datetime = Field(default_factory=utc_now)


class NotificationChannel(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(min_length=1, max_length=100)
    webhook_url: HttpUrl
    minimum_severity: str = "medium"
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action: str
    resource_type: str
    resource_id: str
    project_id: str = ""
    actor: str = "administrator"
    details: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class SuppressionRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str = ""
    name: str = Field(min_length=1, max_length=100)
    tool: str = Field(default="", max_length=100)
    title_contains: str = Field(default="", max_length=200)
    asset_contains: str = Field(default="", max_length=200)
    reason: str = Field(min_length=1, max_length=1000)
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)
