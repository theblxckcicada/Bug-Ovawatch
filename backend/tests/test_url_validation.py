"""Unit tests for ``BaseTool._validate_urls`` (T1 — URL liveness validation).

These exercise the pure filtering logic with a mocked httpx prober, so they run
without the ``pd-httpx`` binary or any network access.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import tools.base as base
from tools.base import BaseTool, RunResult


class _DummyTool(BaseTool):
    """Minimal concrete tool so ``_validate_urls`` can be invoked in isolation."""

    name = "dummy"
    binary_name = None

    async def run(self, *args, **kwargs) -> RunResult:  # pragma: no cover
        return RunResult("", "", 0, 0.0)

    def parse(self, *args, **kwargs):  # pragma: no cover
        return []


def _tool(tmp_path: Path) -> _DummyTool:
    return _DummyTool(output_dir=tmp_path, data_dir=tmp_path)


def _fake_exec(stdout: str, returncode: int):
    async def _exec(cmd, timeout: int = 600) -> RunResult:
        return RunResult(stdout, "", returncode, 0.0)

    return _exec


def _line(url: str, code) -> str:
    obj: dict = {"input": url}
    if code is not None:
        obj["status_code"] = code
    return json.dumps(obj)


def test_missing_prober_keeps_all_deduped(tmp_path, monkeypatch):
    monkeypatch.setattr(base.shutil, "which", lambda *_a, **_k: None)
    tool = _tool(tmp_path)
    urls = ["http://a.test/", "http://b.test/", "http://a.test/"]
    out = asyncio.run(tool._validate_urls(urls, tmp_path, "dummy"))
    assert out == ["http://a.test/", "http://b.test/"]


def test_completed_probe_drops_dead_and_gone(tmp_path, monkeypatch):
    monkeypatch.setattr(base.shutil, "which", lambda *_a, **_k: "/usr/bin/pd-httpx")
    tool = _tool(tmp_path)
    urls = ["http://ok.test/", "http://404.test/", "http://410.test/", "http://silent.test/"]
    stdout = "\n".join([
        _line("http://ok.test/", 200),
        _line("http://404.test/", 404),
        _line("http://410.test/", 410),
        # silent.test never answered → dropped because the probe finished cleanly
    ])
    monkeypatch.setattr(tool, "_exec", _fake_exec(stdout, 0))
    out = asyncio.run(tool._validate_urls(urls, tmp_path, "dummy"))
    assert out == ["http://ok.test/"]


def test_empty_probe_output_keeps_all(tmp_path, monkeypatch):
    monkeypatch.setattr(base.shutil, "which", lambda *_a, **_k: "/usr/bin/pd-httpx")
    tool = _tool(tmp_path)
    urls = ["http://a.test/", "http://b.test/"]
    monkeypatch.setattr(tool, "_exec", _fake_exec("", 0))
    out = asyncio.run(tool._validate_urls(urls, tmp_path, "dummy"))
    assert set(out) == set(urls)


def test_incomplete_probe_keeps_unprobed(tmp_path, monkeypatch):
    monkeypatch.setattr(base.shutil, "which", lambda *_a, **_k: "/usr/bin/pd-httpx")
    tool = _tool(tmp_path)
    urls = ["http://ok.test/", "http://unprobed.test/", "http://404.test/"]
    stdout = "\n".join([
        _line("http://ok.test/", 200),
        _line("http://404.test/", 404),
    ])
    # Non-zero return code → the prober did not finish, so un-probed URLs are kept
    # rather than mistaken for dead hosts. A confirmed 404 is still dropped.
    monkeypatch.setattr(tool, "_exec", _fake_exec(stdout, 1))
    out = asyncio.run(tool._validate_urls(urls, tmp_path, "dummy"))
    assert "http://404.test/" not in out
    assert "http://ok.test/" in out
    assert "http://unprobed.test/" in out


def test_non_http_entries_filtered(tmp_path, monkeypatch):
    monkeypatch.setattr(base.shutil, "which", lambda *_a, **_k: None)
    tool = _tool(tmp_path)
    urls = ["ftp://x.test/", "http://a.test/", "   ", "not-a-url"]
    out = asyncio.run(tool._validate_urls(urls, tmp_path, "dummy"))
    assert out == ["http://a.test/"]


def test_empty_input_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(base.shutil, "which", lambda *_a, **_k: "/usr/bin/pd-httpx")
    tool = _tool(tmp_path)
    assert asyncio.run(tool._validate_urls([], tmp_path, "dummy")) == []
