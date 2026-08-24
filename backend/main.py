"""
main.py — FastAPI application entry point.
"""
from __future__ import annotations

import logging
import os
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from storage import SqlStorage
from tool_secrets import apply_tool_api_keys, normalize_tool_api_keys
from models import ScanStatus
from observability import metrics_middleware, prometheus_metrics

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

logger = logging.getLogger(__name__)

# ── Global storage instance (singleton) ──────────────────────────
storage = SqlStorage(settings.database_dir, output_dir=settings.output_dir)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure output / data dirs exist
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.database_dir).mkdir(parents=True, exist_ok=True)

    stored_tool_keys = await storage.load_tool_api_keys()
    normalized_tool_keys = normalize_tool_api_keys(stored_tool_keys)
    if stored_tool_keys != normalized_tool_keys:
        # Persist the current schema so removed provider credentials (such as
        # legacy Google CSE fields) do not remain dormant in SQLite.
        await storage.save_tool_api_keys(normalized_tool_keys)
    apply_tool_api_keys(normalized_tool_keys)

    # Background tasks are process-local. Mark interrupted runs explicitly so a
    # restart never leaves an assessment permanently displayed as running.
    from datetime import datetime, timezone
    recovered = 0
    for project in await storage.list_projects():
        for scan in await storage.list_scans(project.id):
            if scan.status == ScanStatus.RUNNING:
                scan.status = ScanStatus.FAILED
                scan.error = "Backend restarted before the assessment completed"
                scan.completed_at = datetime.now(timezone.utc)
                await storage.save_scan(scan)
                recovered += 1
    if recovered:
        logger.warning("Marked %d interrupted assessment(s) as failed", recovered)

    # One-time-per-row, SHA-deduplicated compatibility pass for assessments made
    # before screenshots were persisted as SQLite BLOBs. This completes before
    # the API accepts cleanup requests, so an old raw workspace can be removed
    # without losing its screenshot gallery.
    from evidence import backfill_screenshot_evidence
    backfilled = await backfill_screenshot_evidence(storage, Path(settings.output_dir))
    if backfilled:
        logger.info("Persisted %d legacy screenshot(s) in SQLite", backfilled)

    logger.info("ShadowGrid backend started")
    from scheduler import scheduler_loop
    scheduler_task = asyncio.create_task(scheduler_loop(storage, settings))
    try:
        yield
    finally:
        scheduler_task.cancel()
        try:
            await scheduler_task
        except asyncio.CancelledError:
            pass
    logger.info("ShadowGrid backend stopped")


app = FastAPI(
    title="ShadowGrid Recon API",
    version="3.1.0",
    lifespan=lifespan,
)

app.middleware("http")(metrics_middleware)

# ── CORS ─────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in settings.cors_origins.split(",")
        if origin.strip()
    ],
    allow_credentials="*" not in settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Routes ───────────────────────────────────────────────────
from fastapi import Depends

from api.auth import router as auth_router, require_auth
from api.projects import router as projects_router
from api.scans import router as scans_router
from api.results import router as results_router
from api.settings import router as settings_router
from api.tools import router as tools_router
from api.inventory import router as inventory_router
from api.portfolio import router as portfolio_router
from api.control import router as control_router
from api.reports import router as reports_router

# Auth endpoints are public (status/setup/login). Everything else requires a token.
app.include_router(auth_router, prefix="/api")

for router in [
    projects_router,
    scans_router,
    results_router,
    settings_router,
    tools_router,
    inventory_router,
    portfolio_router,
    control_router,
    reports_router,
]:
    app.include_router(router, prefix="/api", dependencies=[Depends(require_auth)])


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "3.1.0"}


@app.get("/api/ready")
async def readiness():
    """Report whether required local persistence paths are usable."""
    output = Path(settings.output_dir)
    data = Path(settings.data_dir)
    checks = {
        "output_exists": output.is_dir(),
        "output_writable": output.is_dir() and os.access(output, os.W_OK),
        "database_exists": storage.database_path.is_file(),
        "database_writable": (
            storage.database_path.is_file()
            and os.access(storage.database_path, os.W_OK)
        ),
        "data_exists": data.is_dir(),
        "data_readable": data.is_dir() and os.access(data, os.R_OK),
    }
    from fastapi.responses import JSONResponse

    ready = all(checks.values())
    return JSONResponse(
        {"status": "ready" if ready else "not_ready", "checks": checks},
        status_code=200 if ready else 503,
    )


@app.get("/api/metrics", dependencies=[Depends(require_auth)])
async def metrics():
    """Return Prometheus-compatible process metrics to authenticated callers."""
    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(await prometheus_metrics(), media_type="text/plain; version=0.0.4")


# ── Serve Angular frontend (built files) ─────────────────────────
FRONTEND_DIR = Path("/app/frontend/dist/shadowgrid/browser")
ASSETS_DIR = FRONTEND_DIR / "assets"
INDEX_FILE = FRONTEND_DIR / "index.html"

if FRONTEND_DIR.exists() and INDEX_FILE.exists():
    # Angular may not generate assets/ if there are no assets.
    # Starlette StaticFiles crashes if the directory does not exist.
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)

    app.mount(
        "/assets",
        StaticFiles(directory=str(ASSETS_DIR)),
        name="assets",
    )

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        requested_file = FRONTEND_DIR / full_path

        if requested_file.exists() and requested_file.is_file():
            return FileResponse(str(requested_file))

        return FileResponse(str(INDEX_FILE))

else:
    logger.warning(
        "Angular frontend build not found. Expected index.html at: %s",
        INDEX_FILE,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
