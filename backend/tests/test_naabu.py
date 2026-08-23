"""Regression tests for Naabu target and port result parsing."""
from __future__ import annotations

from pathlib import Path

from tools.base import RunResult
from tools.http.naabu import NaabuTool


def test_parse_preserves_target_port_and_service(tmp_path: Path) -> None:
    """Each open port must remain associated with the target that exposed it."""
    tool = NaabuTool(output_dir=tmp_path, data_dir=tmp_path)
    result = RunResult(
        "app.example.com:443\napp.example.com:8443\napi.example.com:22\n",
        "",
        0,
        0.1,
    )

    assert tool.parse(result, "example.com") == [
        {
            "host": "app.example.com",
            "port": 443,
            "service": "HTTPS",
            "state": "tcp_reachable",
            "source": "naabu",
        },
        {
            "host": "app.example.com",
            "port": 8443,
            "service": "HTTPS-Alt",
            "state": "tcp_reachable",
            "source": "naabu",
        },
        {
            "host": "api.example.com",
            "port": 22,
            "service": "SSH",
            "state": "tcp_reachable",
            "source": "naabu",
        },
    ]


def test_parse_ignores_lines_without_numeric_ports(tmp_path: Path) -> None:
    """Malformed scanner output must not produce misleading port rows."""
    tool = NaabuTool(output_dir=tmp_path, data_dir=tmp_path)
    result = RunResult("app.example.com:not-a-port\nnoise\n", "", 0, 0.1)

    assert tool.parse(result, "example.com") == []
