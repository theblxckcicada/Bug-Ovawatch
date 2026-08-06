"""Unit tests for ``WpscanTool`` target selection (T2 — wpscan from alive URLs)."""
from __future__ import annotations

import json
from pathlib import Path

from tools.vuln.wpscan import WpscanTool


def _tool(tmp_path: Path) -> WpscanTool:
    return WpscanTool(output_dir=tmp_path, data_dir=tmp_path)


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n")


def test_httpx_wordpress_host_selected(tmp_path):
    tool = _tool(tmp_path)
    _write(tmp_path / "httpx.jsonl", [
        json.dumps({"url": "https://wp.test", "tech": ["WordPress", "PHP"]}),
        json.dumps({"url": "https://plain.test", "tech": ["nginx"]}),
    ])
    targets = tool._wordpress_targets(tmp_path)
    assert "https://wp.test" in targets
    assert "https://plain.test" not in targets


def test_alive_url_marker_selected_and_normalised(tmp_path):
    tool = _tool(tmp_path)
    _write(tmp_path / "alive_urls.txt", [
        "https://blog.test/wp-login.php",
        "https://blog.test/wp-admin/",
        "https://shop.test/products",  # no WordPress marker → excluded
    ])
    # Both blog.test URLs collapse to one site root; shop.test is excluded.
    assert tool._wordpress_targets(tmp_path) == ["https://blog.test"]


def test_alive_url_on_fingerprinted_host_selected(tmp_path):
    tool = _tool(tmp_path)
    _write(tmp_path / "httpx.jsonl", [
        json.dumps({"url": "https://wp.test", "tech": ["WordPress"]}),
    ])
    _write(tmp_path / "alive_urls.txt", [
        "https://wp.test/some/path",     # same host as a WP fingerprint → included
        "https://other.test/some/path",  # unrelated host, no marker → excluded
    ])
    targets = tool._wordpress_targets(tmp_path)
    assert "https://wp.test" in targets
    assert "https://other.test" not in targets


def test_whatweb_plugin_selected(tmp_path):
    tool = _tool(tmp_path)
    _write(tmp_path / "whatweb.jsonl", [
        json.dumps({"target": "http://cms.test", "plugins": {"WordPress": {}}}),
    ])
    assert tool._wordpress_targets(tmp_path) == ["http://cms.test"]


def test_non_wordpress_alive_urls_excluded(tmp_path):
    tool = _tool(tmp_path)
    _write(tmp_path / "alive_urls.txt", [
        "https://a.test/index.html",
        "https://b.test/about",
    ])
    assert tool._wordpress_targets(tmp_path) == []


def test_no_artifacts_returns_empty(tmp_path):
    assert _tool(tmp_path)._wordpress_targets(tmp_path) == []


def test_site_root_normalisation():
    assert WpscanTool._site_root("https://Site.test/wp-login.php") == "https://site.test"
    assert WpscanTool._site_root("http://h.test:8080/wp-admin") == "http://h.test:8080"
    assert WpscanTool._site_root("") == ""


def test_looks_wordpress_markers():
    assert WpscanTool._looks_wordpress("https://x.test/wp-content/uploads/a.png")
    assert WpscanTool._looks_wordpress("https://x.test/xmlrpc.php")
    assert not WpscanTool._looks_wordpress("https://x.test/static/app.js")
