"""Mandatory SQLite persistence for ShadowGrid control-plane data."""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, TypeVar

from inventory import InventorySnapshot
from models import Project, Scan, Target, ToolResult
from storage.base import BaseStorage

logger = logging.getLogger(__name__)
ModelT = TypeVar("ModelT", Project, Scan, Target, ToolResult, InventorySnapshot)


class SqlStorage(BaseStorage):
    """Store all application metadata in a required local SQLite database.

    A connection is opened per operation and writes are serialized within the
    process. WAL mode and a busy timeout allow concurrent readers and safely
    coordinate multiple worker threads without holding an event loop hostage.
    """

    def __init__(
        self, database_dir: str | Path, *, output_dir: str | Path | None = None,
    ):
        self._base = Path(output_dir) if output_dir is not None else Path(database_dir)
        self._base.mkdir(parents=True, exist_ok=True)
        self._database_root = Path(database_dir)
        self._database_root.mkdir(parents=True, exist_ok=True)
        self._database = self._database_root / "shadowgrid.db"
        self._write_lock = threading.RLock()
        self._migrate_output_database()
        self._initialize()
        self._migrate_legacy_json()

    @property
    def output_dir(self) -> str:
        """Return the filesystem root used for evidence artifacts."""
        return str(self._base)

    @property
    def database_path(self) -> Path:
        """Return the mandatory SQLite database path."""
        return self._database

    def _migrate_output_database(self) -> None:
        """Copy the pre-separation output database into durable data storage once."""
        legacy_database = self._base / "shadowgrid.db"
        if (
            self._database.resolve() == legacy_database.resolve()
            or self._database.exists()
            or not legacy_database.is_file()
        ):
            return
        with sqlite3.connect(legacy_database) as source, sqlite3.connect(self._database) as target:
            source.backup(target)
        logger.info(
            "Migrated SQLite database from transient output storage %s to %s",
            legacy_database,
            self._database,
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS targets (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            payload TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id);
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            payload TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
        CREATE TABLE IF NOT EXISTS results (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            payload TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
        CREATE TABLE IF NOT EXISTS inventories (
            scan_id TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS evidence_blobs (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            content BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            UNIQUE(scan_id, sha256)
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_blobs_scan ON evidence_blobs(scan_id);
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            connection.executescript(schema)
        try:
            self._database.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _serialize(value: Any) -> str:
        if hasattr(value, "model_dump"):
            value = value.model_dump()
        return json.dumps(value, default=str, separators=(",", ":"))

    def _run_write(self, operation: Callable[[sqlite3.Connection], None]) -> None:
        with self._write_lock, self._connect() as connection:
            operation(connection)

    async def _write(self, operation: Callable[[sqlite3.Connection], None]) -> None:
        await asyncio.to_thread(self._run_write, operation)

    def _query_one(self, query: str, parameters: tuple[Any, ...]) -> str | None:
        with self._connect() as connection:
            row = connection.execute(query, parameters).fetchone()
        return str(row["payload"]) if row else None

    def _query_all(self, query: str, parameters: tuple[Any, ...]) -> list[str]:
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [str(row["payload"]) for row in rows]

    async def _load_one(
        self, query: str, parameters: tuple[Any, ...], model: type[ModelT]
    ) -> ModelT | None:
        payload = await asyncio.to_thread(self._query_one, query, parameters)
        return model.model_validate_json(payload) if payload else None

    async def _load_all(
        self, query: str, parameters: tuple[Any, ...], model: type[ModelT]
    ) -> list[ModelT]:
        payloads = await asyncio.to_thread(self._query_all, query, parameters)
        return [model.model_validate_json(payload) for payload in payloads]

    def _migration_done(self, connection: sqlite3.Connection) -> bool:
        row = connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'legacy_json_migrated'"
        ).fetchone()
        return row is not None

    def _migrate_legacy_json(self) -> None:
        """Import the previous `.meta` JSON store exactly once."""
        legacy = self._base / ".meta"
        with self._write_lock, self._connect() as connection:
            if self._migration_done(connection):
                return
            counts = {"projects": 0, "targets": 0, "scans": 0, "results": 0, "inventories": 0}

            def import_rows(directory: Path, table: str, parent_key: str | None = None) -> None:
                if not directory.exists():
                    return
                for path in directory.rglob("*.json"):
                    try:
                        payload = json.loads(path.read_text(encoding="utf-8"))
                        row_id = str(payload["scan_id"] if table == "inventories" else payload["id"])
                        serialized = self._serialize(payload)
                        if parent_key:
                            parent_id = str(payload[parent_key])
                            connection.execute(
                                f"INSERT OR IGNORE INTO {table} (id, {parent_key}, payload) VALUES (?, ?, ?)",
                                (row_id, parent_id, serialized),
                            )
                        elif table == "inventories":
                            connection.execute(
                                "INSERT OR IGNORE INTO inventories (scan_id, payload) VALUES (?, ?)",
                                (row_id, serialized),
                            )
                        else:
                            connection.execute(
                                f"INSERT OR IGNORE INTO {table} (id, payload) VALUES (?, ?)",
                                (row_id, serialized),
                            )
                        counts[table] += 1
                    except (
                        KeyError,
                        OSError,
                        ValueError,
                        json.JSONDecodeError,
                        sqlite3.IntegrityError,
                    ) as exc:
                        logger.warning("Skipped invalid legacy record %s: %s", path, exc)

            import_rows(legacy / "projects", "projects")
            import_rows(legacy / "targets", "targets", "project_id")
            import_rows(legacy / "scans", "scans", "project_id")
            import_rows(legacy / "results", "results", "scan_id")
            import_rows(legacy / "inventory", "inventories")
            for key, filename in {
                "tool_api_keys": "tool_api_keys.json",
                "auth": "auth.json",
            }.items():
                path = legacy / filename
                if path.exists():
                    try:
                        payload = json.loads(path.read_text(encoding="utf-8"))
                        connection.execute(
                            "INSERT OR IGNORE INTO config (key, payload) VALUES (?, ?)",
                            (key, self._serialize(payload)),
                        )
                    except (OSError, ValueError, json.JSONDecodeError) as exc:
                        logger.warning("Skipped invalid legacy configuration %s: %s", path, exc)
            connection.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('legacy_json_migrated', '1')"
            )
        if any(counts.values()):
            logger.info("Migrated legacy JSON metadata into SQLite: %s", counts)

    async def save_project(self, project: Project) -> None:
        await self._write(lambda db: db.execute(
            "INSERT INTO projects (id, payload) VALUES (?, ?) "
            "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
            (project.id, self._serialize(project)),
        ))

    async def get_project(self, project_id: str) -> Project | None:
        return await self._load_one("SELECT payload FROM projects WHERE id=?", (project_id,), Project)

    async def list_projects(self) -> list[Project]:
        return await self._load_all("SELECT payload FROM projects ORDER BY id", (), Project)

    async def delete_project(self, project_id: str) -> None:
        await self._write(lambda db: db.execute("DELETE FROM projects WHERE id=?", (project_id,)))

    async def save_target(self, target: Target) -> None:
        await self._write(lambda db: db.execute(
            "INSERT INTO targets (id, project_id, payload) VALUES (?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET project_id=excluded.project_id, payload=excluded.payload",
            (target.id, target.project_id, self._serialize(target)),
        ))

    async def list_targets(self, project_id: str) -> list[Target]:
        return await self._load_all(
            "SELECT payload FROM targets WHERE project_id=? ORDER BY id", (project_id,), Target
        )

    async def delete_target(self, target_id: str, project_id: str) -> None:
        await self._write(lambda db: db.execute(
            "DELETE FROM targets WHERE id=? AND project_id=?", (target_id, project_id)
        ))

    async def save_scan(self, scan: Scan) -> None:
        await self._write(lambda db: db.execute(
            "INSERT INTO scans (id, project_id, payload) VALUES (?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET project_id=excluded.project_id, payload=excluded.payload",
            (scan.id, scan.project_id, self._serialize(scan)),
        ))

    async def get_scan(self, scan_id: str) -> Scan | None:
        return await self._load_one("SELECT payload FROM scans WHERE id=?", (scan_id,), Scan)

    async def list_scans(self, project_id: str) -> list[Scan]:
        return await self._load_all(
            "SELECT payload FROM scans WHERE project_id=? ORDER BY id", (project_id,), Scan
        )

    async def delete_scan(self, scan_id: str, project_id: str) -> None:
        scan = await self.get_scan(scan_id)
        if scan:
            await self.delete_scan_artifacts(scan)
        await self._write(lambda db: db.execute(
            "DELETE FROM scans WHERE id=? AND project_id=?", (scan_id, project_id)
        ))

    async def save_result(self, result: ToolResult) -> None:
        await self._write(lambda db: db.execute(
            "INSERT INTO results (id, scan_id, payload) VALUES (?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET scan_id=excluded.scan_id, payload=excluded.payload",
            (result.id, result.scan_id, self._serialize(result)),
        ))

    async def list_results(self, scan_id: str) -> list[ToolResult]:
        return await self._load_all(
            "SELECT payload FROM results WHERE scan_id=? ORDER BY id", (scan_id,), ToolResult
        )

    async def delete_results(self, scan_id: str) -> None:
        def delete_rows(db: sqlite3.Connection) -> None:
            db.execute("DELETE FROM evidence_blobs WHERE scan_id=?", (scan_id,))
            db.execute("DELETE FROM results WHERE scan_id=?", (scan_id,))

        await self._write(delete_rows)

    async def delete_scan_artifacts(self, scan: Scan) -> None:
        """Delete only the filesystem workspace owned by the supplied scan."""
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
        await asyncio.to_thread(shutil.rmtree, scan_dir, True)

    def _save_evidence_blob(
        self, scan_id: str, filename: str, mime_type: str, content: bytes, sha256: str,
    ) -> str:
        """Insert a deduplicated evidence BLOB in one serialized transaction."""
        with self._write_lock, self._connect() as connection:
            existing = connection.execute(
                "SELECT id FROM evidence_blobs WHERE scan_id=? AND sha256=?",
                (scan_id, sha256),
            ).fetchone()
            if existing:
                return str(existing["id"])
            blob_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO evidence_blobs "
                "(id, scan_id, filename, mime_type, sha256, content) VALUES (?, ?, ?, ?, ?, ?)",
                (blob_id, scan_id, filename, mime_type, sha256, content),
            )
            return blob_id

    async def save_evidence_blob(
        self, scan_id: str, filename: str, mime_type: str, content: bytes, sha256: str,
    ) -> str:
        """Persist binary evidence in SQLite, deduplicated within its scan."""
        return await asyncio.to_thread(
            self._save_evidence_blob, scan_id, filename, mime_type, content, sha256
        )

    def _get_evidence_blob(self, scan_id: str, blob_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT id, filename, mime_type, sha256, content "
                "FROM evidence_blobs WHERE id=? AND scan_id=?",
                (blob_id, scan_id),
            ).fetchone()
        if not row:
            return None
        return {
            "id": str(row["id"]),
            "filename": str(row["filename"]),
            "mime_type": str(row["mime_type"]),
            "sha256": str(row["sha256"]),
            "content": bytes(row["content"]),
        }

    async def get_evidence_blob(self, scan_id: str, blob_id: str) -> dict[str, Any] | None:
        """Load a scan-owned evidence BLOB without exposing another scan's data."""
        return await asyncio.to_thread(self._get_evidence_blob, scan_id, blob_id)

    async def save_inventory(self, snapshot: InventorySnapshot) -> None:
        await self._write(lambda db: db.execute(
            "INSERT INTO inventories (scan_id, payload) VALUES (?, ?) "
            "ON CONFLICT(scan_id) DO UPDATE SET payload=excluded.payload",
            (snapshot.scan_id, self._serialize(snapshot)),
        ))

    async def load_inventory(self, scan_id: str) -> InventorySnapshot | None:
        return await self._load_one(
            "SELECT payload FROM inventories WHERE scan_id=?", (scan_id,), InventorySnapshot
        )

    async def _save_config(self, key: str, config: dict[str, Any]) -> None:
        await self._write(lambda db: db.execute(
            "INSERT INTO config (key, payload) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET payload=excluded.payload",
            (key, self._serialize(config)),
        ))

    async def _load_config(self, key: str) -> dict[str, Any]:
        payload = await asyncio.to_thread(
            self._query_one, "SELECT payload FROM config WHERE key=?", (key,)
        )
        return json.loads(payload) if payload else {}

    async def save_tool_api_keys(self, config: dict) -> None:
        await self._save_config("tool_api_keys", config)

    async def load_tool_api_keys(self) -> dict:
        return await self._load_config("tool_api_keys")

    async def save_auth(self, record: dict) -> None:
        await self._save_config("auth", record)

    async def load_auth(self) -> dict:
        return await self._load_config("auth")
