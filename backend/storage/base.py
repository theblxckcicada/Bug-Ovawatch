"""storage/base.py — abstract storage interface."""
from __future__ import annotations
from abc import ABC, abstractmethod
from models import Project, Target, Scan, ToolResult
from inventory import InventorySnapshot


class BaseStorage(ABC):

    @abstractmethod
    async def save_project(self, project: Project) -> None: ...

    @abstractmethod
    async def get_project(self, project_id: str) -> Project | None: ...

    @abstractmethod
    async def list_projects(self) -> list[Project]: ...

    @abstractmethod
    async def delete_project(self, project_id: str) -> None: ...

    @abstractmethod
    async def save_target(self, target: Target) -> None: ...

    @abstractmethod
    async def list_targets(self, project_id: str) -> list[Target]: ...

    @abstractmethod
    async def delete_target(self, target_id: str, project_id: str) -> None: ...

    @abstractmethod
    async def save_scan(self, scan: Scan) -> None: ...

    @abstractmethod
    async def get_scan(self, scan_id: str) -> Scan | None: ...

    @abstractmethod
    async def list_scans(self, project_id: str) -> list[Scan]: ...

    @abstractmethod
    async def delete_scan(self, scan_id: str, project_id: str) -> None:
        """Delete a scan record and all of its results. Idempotent."""

    @abstractmethod
    async def save_result(self, result: ToolResult) -> None: ...

    @abstractmethod
    async def list_results(self, scan_id: str) -> list[ToolResult]: ...

    @abstractmethod
    async def delete_results(self, scan_id: str) -> None:
        """Delete every stored result for a scan. Idempotent."""

    async def delete_scan_artifacts(self, scan: Scan) -> None:
        """Delete the isolated filesystem workspace owned by a scan."""
        return None

    async def save_inventory(self, snapshot: InventorySnapshot) -> None:
        """Persist a normalized inventory snapshot."""
        raise NotImplementedError

    async def load_inventory(self, scan_id: str) -> InventorySnapshot | None:
        """Load a normalized inventory snapshot when one exists."""
        raise NotImplementedError

    @abstractmethod
    async def save_storage_config(self, config: dict) -> None: ...

    @abstractmethod
    async def load_storage_config(self) -> dict: ...

    @abstractmethod
    async def save_tool_api_keys(self, config: dict) -> None: ...

    @abstractmethod
    async def load_tool_api_keys(self) -> dict: ...

    # ── Auth (local-only control-plane secret; not mirrored to Azure) ──
    async def save_auth(self, record: dict) -> None:
        raise NotImplementedError

    async def load_auth(self) -> dict:
        raise NotImplementedError
