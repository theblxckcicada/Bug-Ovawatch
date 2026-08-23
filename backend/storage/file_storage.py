"""
storage/file_storage.py — JSON-file backed storage.
Always active. Lives at output_dir/.meta/
"""
from __future__ import annotations
import asyncio
import json
import os
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any

from models import Project, Target, Scan, ToolResult
from inventory import InventorySnapshot
from storage.base import BaseStorage


class FileStorage(BaseStorage):
    def __init__(self, base_dir: str | Path):
        self._base = Path(base_dir)
        self._meta = self._base / ".meta"
        self._meta.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()

    @property
    def output_dir(self) -> str:
        """Return the configured output root."""
        return str(self._base)

    # ── helpers ────────────────────────────────────────────
    def _read(self, path: Path) -> Any:
        if not path.exists():
            return None
        with open(path) as f:
            return json.load(f)

    def _write(self, path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._write_lock:
            temporary_path: str | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", dir=path.parent,
                    prefix=f".{path.name}.", suffix=".tmp", delete=False,
                ) as temporary:
                    json.dump(data, temporary, indent=2, default=str)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                    temporary_path = temporary.name
                os.replace(temporary_path, path)
                if path.name in {"auth.json", "tool_api_keys.json", "storage_config.json"}:
                    try:
                        path.chmod(0o600)
                    except OSError:
                        pass
            finally:
                if temporary_path and Path(temporary_path).exists():
                    Path(temporary_path).unlink(missing_ok=True)

    def _read_all(self, directory: Path) -> list[dict]:
        if not directory.exists():
            return []
        result = []
        for p in directory.glob("*.json"):
            try:
                with open(p) as f:
                    result.append(json.load(f))
            except Exception:
                pass
        return result

    # ── Projects ───────────────────────────────────────────
    async def save_project(self, project: Project) -> None:
        path = self._meta / "projects" / f"{project.id}.json"
        self._write(path, project.model_dump())

    async def get_project(self, project_id: str) -> Project | None:
        path = self._meta / "projects" / f"{project_id}.json"
        data = self._read(path)
        return Project(**data) if data else None

    async def list_projects(self) -> list[Project]:
        return [Project(**d) for d in self._read_all(self._meta / "projects")]

    async def delete_project(self, project_id: str) -> None:
        path = self._meta / "projects" / f"{project_id}.json"
        path.unlink(missing_ok=True)

    # ── Targets ────────────────────────────────────────────
    async def save_target(self, target: Target) -> None:
        path = self._meta / "targets" / target.project_id / f"{target.id}.json"
        self._write(path, target.model_dump())

    async def list_targets(self, project_id: str) -> list[Target]:
        return [Target(**d) for d in self._read_all(self._meta / "targets" / project_id)]

    async def delete_target(self, target_id: str, project_id: str) -> None:
        path = self._meta / "targets" / project_id / f"{target_id}.json"
        path.unlink(missing_ok=True)

    # ── Scans ──────────────────────────────────────────────
    async def save_scan(self, scan: Scan) -> None:
        path = self._meta / "scans" / scan.project_id / f"{scan.id}.json"
        self._write(path, scan.model_dump())

    async def get_scan(self, scan_id: str) -> Scan | None:
        # scan_id is unique so we search across all projects
        for scan_dir in (self._meta / "scans").iterdir() if (self._meta / "scans").exists() else []:
            path = scan_dir / f"{scan_id}.json"
            if path.exists():
                data = self._read(path)
                return Scan(**data) if data else None
        return None

    async def list_scans(self, project_id: str) -> list[Scan]:
        return [Scan(**d) for d in self._read_all(self._meta / "scans" / project_id)]

    async def delete_scan(self, scan_id: str, project_id: str) -> None:
        """Remove a scan's metadata record and all of its results. Idempotent."""
        path = self._meta / "scans" / project_id / f"{scan_id}.json"
        path.unlink(missing_ok=True)
        await self.delete_results(scan_id)
        (self._meta / "inventory" / f"{scan_id}.json").unlink(missing_ok=True)

    # ── Results ────────────────────────────────────────────
    async def save_result(self, result: ToolResult) -> None:
        path = self._meta / "results" / result.scan_id / f"{result.id}.json"
        self._write(path, result.model_dump())

    async def list_results(self, scan_id: str) -> list[ToolResult]:
        return [ToolResult(**d) for d in self._read_all(self._meta / "results" / scan_id)]

    async def delete_results(self, scan_id: str) -> None:
        """Remove the whole results directory for a scan. Idempotent.

        Deletion is strictly confined to ``.meta/results/<scan_id>/``; the shared
        per-domain artifact directories under the output root are intentionally
        left untouched because they are not owned by a single scan.
        """
        results_dir = self._meta / "results" / scan_id
        shutil.rmtree(results_dir, ignore_errors=True)

    async def delete_scan_artifacts(self, scan: Scan) -> None:
        """Delete a scan workspace after verifying it is confined and owned."""
        if not scan.workspace:
            return
        base = self._base.resolve()
        workspace = (base / scan.workspace).resolve()
        if base not in workspace.parents or workspace == base:
            raise ValueError("Refusing to delete an unconfined scan workspace")
        scan_dir = workspace.parent
        expected = (base / "projects" / scan.project_id / "scans" / scan.id).resolve()
        if scan_dir != expected:
            raise ValueError("Scan workspace does not match its scan identifier")
        shutil.rmtree(scan_dir, ignore_errors=True)

    async def save_inventory(self, snapshot: InventorySnapshot) -> None:
        """Persist one immutable normalized inventory snapshot atomically."""
        path = self._meta / "inventory" / f"{snapshot.scan_id}.json"
        self._write(path, snapshot.model_dump())

    async def load_inventory(self, scan_id: str) -> InventorySnapshot | None:
        """Load a normalized inventory snapshot by scan identifier."""
        data = self._read(self._meta / "inventory" / f"{scan_id}.json")
        return InventorySnapshot(**data) if data else None

    # ── Config ─────────────────────────────────────────────
    async def save_storage_config(self, config: dict) -> None:
        self._write(self._meta / "storage_config.json", config)

    async def load_storage_config(self) -> dict:
        return self._read(self._meta / "storage_config.json") or {}

    async def save_tool_api_keys(self, config: dict) -> None:
        self._write(self._meta / "tool_api_keys.json", config)

    async def load_tool_api_keys(self) -> dict:
        return self._read(self._meta / "tool_api_keys.json") or {}

    # ── Auth ───────────────────────────────────────────────
    async def save_auth(self, record: dict) -> None:
        self._write(self._meta / "auth.json", record)

    async def load_auth(self) -> dict:
        return self._read(self._meta / "auth.json") or {}
