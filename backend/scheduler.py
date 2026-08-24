"""Persistent interval scheduler for unattended ShadowGrid assessments."""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from pathlib import Path

from control_models import AuditEvent, ScanSchedule, utc_now
from models import Scan, ScanStatus

logger = logging.getLogger(__name__)


async def launch_scheduled_scan(schedule: ScanSchedule, storage, settings) -> Scan | None:
    """Launch a due schedule unless its project already has an active scan."""
    project = await storage.get_project(schedule.project_id)
    if not project:
        schedule.enabled = False
        await storage.save_control_record("schedule", schedule.id, schedule.model_dump(mode="json"), schedule.project_id)
        return None
    scans = await storage.list_scans(schedule.project_id)
    if any(scan.status == ScanStatus.RUNNING for scan in scans):
        schedule.next_run_at = utc_now() + timedelta(minutes=15)
        await storage.save_control_record("schedule", schedule.id, schedule.model_dump(mode="json"), schedule.project_id)
        return None
    targets = await storage.list_targets(schedule.project_id)
    domains = [target.domain for target in targets if not target.is_oos]
    oos = [target.domain for target in targets if target.is_oos]
    if not domains:
        return None

    scan = Scan(
        project_id=schedule.project_id, tools=schedule.tools,
        verify_emails=schedule.verify_emails and "email_finder" in schedule.tools,
        user_agent=schedule.user_agent, custom_headers=schedule.custom_headers,
    )
    await storage.save_scan(scan)
    project.scan_count += 1
    await storage.save_project(project)
    schedule.last_run_at = utc_now()
    schedule.next_run_at = schedule.last_run_at + timedelta(minutes=schedule.interval_minutes)
    await storage.save_control_record("schedule", schedule.id, schedule.model_dump(mode="json"), schedule.project_id)
    event = AuditEvent(
        action="scheduled_scan_started", resource_type="scan", resource_id=scan.id,
        project_id=schedule.project_id, details={"schedule_id": schedule.id},
    )
    await storage.save_control_record("audit", event.id, event.model_dump(mode="json"), schedule.project_id)

    from scan_engine import run_scan
    asyncio.create_task(run_scan(
        scan=scan, domains=domains, oos=oos,
        output_dir=Path(settings.output_dir), data_dir=Path(settings.data_dir),
        storage=storage, reuse_previous=False,
    ))
    return scan


async def scheduler_loop(storage, settings) -> None:
    """Poll durable schedules and launch due work until application shutdown."""
    while True:
        try:
            now = utc_now()
            records = await storage.list_control_records("schedule")
            for record in records:
                schedule = ScanSchedule.model_validate(record)
                if schedule.enabled and schedule.next_run_at <= now:
                    await launch_scheduled_scan(schedule, storage, settings)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scheduled assessment poll failed")
        await asyncio.sleep(60)
