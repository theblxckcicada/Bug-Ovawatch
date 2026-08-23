"""Dependency-free operational metrics for ShadowGrid's control plane."""
from __future__ import annotations

import asyncio
import time
from collections import Counter, defaultdict

from fastapi import Request


_lock = asyncio.Lock()
_requests: Counter[tuple[str, str, int]] = Counter()
_durations: dict[tuple[str, str], list[float]] = defaultdict(list)


async def record_request(request: Request, status_code: int, elapsed_seconds: float) -> None:
    """Record bounded request counters and recent duration samples."""
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    key = (request.method, path)
    async with _lock:
        _requests[(request.method, path, status_code)] += 1
        samples = _durations[key]
        samples.append(elapsed_seconds)
        if len(samples) > 500:
            del samples[:-500]


async def prometheus_metrics() -> str:
    """Render current process metrics using Prometheus text exposition format."""
    async with _lock:
        request_items = list(_requests.items())
        duration_items = [(key, list(values)) for key, values in _durations.items()]

    lines = [
        "# HELP shadowgrid_http_requests_total HTTP requests handled by the API.",
        "# TYPE shadowgrid_http_requests_total counter",
    ]
    for (method, path, status), count in sorted(request_items):
        lines.append(
            f'shadowgrid_http_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}'
        )
    lines.extend([
        "# HELP shadowgrid_http_request_duration_seconds Recent API request duration.",
        "# TYPE shadowgrid_http_request_duration_seconds summary",
    ])
    for (method, path), samples in sorted(duration_items):
        if not samples:
            continue
        labels = f'method="{method}",path="{path}"'
        lines.append(f"shadowgrid_http_request_duration_seconds_sum{{{labels}}} {sum(samples):.6f}")
        lines.append(f"shadowgrid_http_request_duration_seconds_count{{{labels}}} {len(samples)}")
    return "\n".join(lines) + "\n"


async def metrics_middleware(request: Request, call_next):
    """ASGI middleware callback that measures one request."""
    started = time.monotonic()
    try:
        response = await call_next(request)
    except Exception:
        await record_request(request, 500, time.monotonic() - started)
        raise
    await record_request(request, response.status_code, time.monotonic() - started)
    return response
