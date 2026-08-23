"""CVE-specific scanning and optional Shodan enrichment tests."""
from __future__ import annotations

import json

from inventory import build_inventory
from models import ToolCategory, ToolResult
from tools.asset.shodan_tool import ShodanTool
from tools.base import RunResult
from tools.vuln.cve_check import CveCheckTool


def test_cve_check_extracts_cve_identifiers(tmp_path) -> None:
    tool = CveCheckTool(tmp_path, tmp_path)
    result = RunResult(json.dumps({
        "template-id": "CVE-2024-12345",
        "host": "https://app.example.com",
        "matched-at": "https://app.example.com/login",
        "info": {
            "name": "Example vulnerability",
            "severity": "high",
            "classification": {"cve-id": ["CVE-2024-12345"]},
        },
    }), "", 0, 0)

    rows = tool.parse(result, "example.com")

    assert rows[0]["cve_ids"] == ["CVE-2024-12345"]
    assert rows[0]["state"] == "cve_detected"
    assert rows[0]["url"] == "https://app.example.com/login"


def test_shodan_requires_saved_api_key(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert "not configured" in ShodanTool(tmp_path, tmp_path).availability_error()
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")
    assert ShodanTool(tmp_path, tmp_path).availability_error() is None


def test_shodan_parser_rejects_out_of_scope_hosts(tmp_path) -> None:
    tool = ShodanTool(tmp_path, tmp_path)
    payload = {"matches": [
        {"ip_str": "192.0.2.1", "port": 443, "hostnames": ["app.example.com"], "product": "nginx", "vulns": ["CVE-2023-0001"]},
        {"ip_str": "192.0.2.2", "port": 443, "hostnames": ["example.com.attacker.test"], "product": "nginx"},
    ]}

    rows = tool.parse(RunResult(json.dumps(payload), "", 0, 0), "example.com")

    assert len(rows) == 1
    assert rows[0]["host"] == "app.example.com"
    assert rows[0]["vulnerabilities"] == ["CVE-2023-0001"]


def test_shodan_cves_become_normalized_findings() -> None:
    result = ToolResult(
        scan_id="scan-1", project_id="project-1", tool="shodan",
        category=ToolCategory.ASSET, domain="example.com", data=[{
            "host": "app.example.com", "ip": "192.0.2.1", "port": 443,
            "service": "nginx", "vulnerabilities": ["CVE-2023-0001"],
            "state": "shodan_observed",
        }],
    )

    snapshot = build_inventory("scan-1", "project-1", ["example.com"], [result])

    assert snapshot.findings[0].title == "Shodan reported CVE-2023-0001"
    assert snapshot.findings[0].tool == "shodan"
