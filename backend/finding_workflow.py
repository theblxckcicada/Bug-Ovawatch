"""Reconcile durable analyst decisions with newly observed findings."""
from __future__ import annotations

from control_models import FindingDisposition, FindingState, utc_now
from inventory import InventorySnapshot


async def reopen_reappearing_findings(snapshot: InventorySnapshot, storage) -> None:
    """Reopen findings marked remediated when a later scan observes them again."""
    states = {
        item["id"]: FindingState.model_validate(item)
        for item in await storage.list_control_records("finding_state", snapshot.project_id)
    }
    for finding in snapshot.findings:
        state = states.get(finding.id)
        if state and state.disposition == FindingDisposition.REMEDIATED:
            state.disposition = FindingDisposition.REOPENED
            state.updated_at = utc_now()
            await storage.save_control_record(
                "finding_state", state.id, state.model_dump(mode="json"), snapshot.project_id,
            )
