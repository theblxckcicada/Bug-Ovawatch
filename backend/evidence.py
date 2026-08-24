"""Ingest durable binary evidence from a scan's transient tool workspace."""
from __future__ import annotations

import asyncio
import hashlib
import mimetypes
from pathlib import Path

from models import ToolResult
from storage.base import BaseStorage


async def persist_result_evidence(
    result: ToolResult, workspace: Path, storage: BaseStorage,
) -> int:
    """Persist filesystem-backed result evidence and annotate its database row.

    Tool output paths are treated as untrusted even though parsers generate them:
    every resolved file must remain under the canonical scan workspace. Currently
    Gowitness screenshots are the only durable binary result type; parsed text and
    structured findings are already contained in ``ToolResult.data``.
    """
    if result.tool != "gowitness":
        return 0

    workspace = workspace.resolve()
    stored = 0
    for row in result.data:
        if row.get("blob_id"):
            continue
        relative_path = str(row.get("path") or "").strip()
        if not relative_path:
            continue
        candidate = (workspace / relative_path).resolve()
        if workspace not in candidate.parents or not candidate.is_file():
            continue
        content = await asyncio.to_thread(candidate.read_bytes)
        mime_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        if not mime_type.startswith("image/"):
            continue
        digest = hashlib.sha256(content).hexdigest()
        blob_id = await storage.save_evidence_blob(
            result.scan_id, candidate.name, mime_type, content, digest
        )
        row["blob_id"] = blob_id
        row["mime_type"] = mime_type
        row["sha256"] = digest
        stored += 1
    return stored


async def backfill_screenshot_evidence(storage: BaseStorage, output_dir: Path) -> int:
    """Persist filesystem-only screenshots from assessments created before BLOB storage."""
    output_root = output_dir.resolve()
    stored = 0
    for project in await storage.list_projects():
        for scan in await storage.list_scans(project.id):
            if not scan.workspace:
                continue
            workspace = (output_root / scan.workspace).resolve()
            expected = (
                output_root / "projects" / project.id / "scans" / scan.id / "assets"
            ).resolve()
            if workspace != expected or not workspace.exists():
                continue
            for result in await storage.list_results(scan.id):
                captured = await persist_result_evidence(result, workspace, storage)
                if captured:
                    stored += captured
                    await storage.save_result(result)
    return stored
