"""Best-effort webhook delivery for completed assessment deltas."""
from __future__ import annotations

import hashlib
import logging

import aiohttp

from control_models import NotificationChannel
from inventory import compare_inventories
from models import Scan, ScanStatus

logger = logging.getLogger(__name__)


async def notify_scan_completed(scan: Scan, storage) -> None:
    """Send one deduplicated summary to each enabled webhook channel."""
    if scan.status != ScanStatus.COMPLETED:
        return
    current = await storage.load_inventory(scan.id)
    if not current:
        return
    previous = None
    candidates = [
        item for item in await storage.list_scans(scan.project_id)
        if item.id != scan.id and item.status == ScanStatus.COMPLETED
        and item.created_at < scan.created_at
    ]
    for candidate in sorted(candidates, key=lambda item: item.created_at, reverse=True):
        previous = await storage.load_inventory(candidate.id)
        if previous:
            break
    delta = compare_inventories(current, previous)
    payload = {
        "event": "shadowgrid.assessment.completed",
        "project_id": scan.project_id,
        "scan_id": scan.id,
        "summary": {
            "assets": len(current.assets), "findings": len(current.findings),
            "added_assets": len(delta.added_assets),
            "removed_assets": len(delta.removed_assets),
            "changed_assets": len(delta.changed_assets),
            "new_findings": len(delta.new_findings),
            "resolved_findings": len(delta.resolved_findings),
        },
    }
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for record in await storage.list_control_records("notification"):
            try:
                channel = NotificationChannel.model_validate(record)
                if not channel.enabled:
                    continue
                delivery_id = hashlib.sha256(f"{channel.id}:{scan.id}".encode()).hexdigest()
                if await storage.get_control_record("notification_delivery", delivery_id):
                    continue
                async with session.post(str(channel.webhook_url), json=payload) as response:
                    if 200 <= response.status < 300:
                        await storage.save_control_record(
                            "notification_delivery", delivery_id,
                            {"id": delivery_id, "channel_id": channel.id, "scan_id": scan.id},
                        )
                    else:
                        logger.warning("Webhook %s returned HTTP %d", channel.name, response.status)
            except (aiohttp.ClientError, ValueError):
                logger.exception("Could not deliver completion webhook")
