"""Unit tests for WPScan coverage of verified alive HTTP services."""
from __future__ import annotations

import json
from pathlib import Path

from tools.vuln.wpscan import WpscanTool


def _tool(tmp_path: Path) -> WpscanTool:
    return WpscanTool(output_dir=tmp_path, data_dir=tmp_path)


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n")


def test_all_httpx_alive_hosts_selected(tmp_path):
    tool = _tool(tmp_path)
    _write(tmp_path / "httpx.jsonl", [
        json.dumps({"url": "https://wp.test", "tech": ["WordPress", "PHP"]}),
        json.dumps({"url": "https://plain.test", "tech": ["nginx"]}),
    ])
    targets = tool._wordpress_targets(tmp_path)
    assert "https://wp.test" in targets
    assert "https://plain.test" in targets


def test_all_alive_urls_selected_and_normalised(tmp_path):
    tool = _tool(tmp_path)
    _write(tmp_path / "alive_urls.txt", [
        "https://blog.test/wp-login.php",
        "https://blog.test/wp-admin/",
        "https://shop.test/products",
    ])
    assert tool._wordpress_targets(tmp_path) == ["https://blog.test", "https://shop.test"]


def test_alive_urls_do_not_require_wordpress_fingerprint(tmp_path):
    tool = _tool(tmp_path)
    _write(tmp_path / "httpx.jsonl", [
        json.dumps({"url": "https://wp.test", "tech": ["WordPress"]}),
    ])
    _write(tmp_path / "alive_urls.txt", [
        "https://wp.test/some/path",
        "https://other.test/some/path",
    ])
    targets = tool._wordpress_targets(tmp_path)
    assert "https://wp.test" in targets
    assert "https://other.test" in targets


def test_whatweb_plugin_selected(tmp_path):
    tool = _tool(tmp_path)
    _write(tmp_path / "whatweb.jsonl", [
        json.dumps({"target": "http://cms.test", "plugins": {"WordPress": {}}}),
    ])
    assert tool._wordpress_targets(tmp_path) == ["http://cms.test"]


def test_non_wordpress_alive_urls_included(tmp_path):
    tool = _tool(tmp_path)
    _write(tmp_path / "alive_urls.txt", [
        "https://a.test/index.html",
        "https://b.test/about",
    ])
    assert tool._wordpress_targets(tmp_path) == ["https://a.test", "https://b.test"]


def test_target_selection_has_no_fixed_limit(tmp_path):
    tool = _tool(tmp_path)
    _write(
        tmp_path / "alive_urls.txt",
        [f"https://subdomain-{index}.test/path" for index in range(25)],
    )
    assert len(tool._wordpress_targets(tmp_path)) == 25


def test_no_artifacts_returns_empty(tmp_path):
    assert _tool(tmp_path)._wordpress_targets(tmp_path) == []


def test_site_root_normalisation():
    assert WpscanTool._site_root("https://Site.test/wp-login.php") == "https://site.test"
    assert WpscanTool._site_root("http://h.test:8080/wp-admin") == "http://h.test:8080"
    assert WpscanTool._site_root("") == ""
