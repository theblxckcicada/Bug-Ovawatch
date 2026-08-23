"""Canonical target and scan-workspace helpers.

All externally supplied targets cross this module before they are persisted or
used to construct filesystem paths. ShadowGrid currently scans DNS names, so
the accepted grammar is intentionally narrower than a general URL parser.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from pydantic import TypeAdapter


_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str, *, allow_wildcard: bool = False) -> str:
    """Return a canonical ASCII DNS name or raise ``ValueError``.

    URL components, filesystem separators, ports, IP literals, and single-label
    names are rejected. Out-of-scope entries may use one leading ``*.`` only.
    """
    candidate = (value or "").strip().lower().rstrip(".")
    wildcard = candidate.startswith("*.")
    if wildcard:
        if not allow_wildcard:
            raise ValueError("Wildcards are only allowed for out-of-scope targets")
        candidate = candidate[2:]

    if not candidate or any(char in candidate for char in "/\\:@?#%\x00"):
        raise ValueError("Target must be a DNS name, not a URL, path, IP, or host:port")

    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Target is not a valid internationalized DNS name") from exc

    if len(ascii_name) > 253 or "." not in ascii_name:
        raise ValueError("Target must be a fully-qualified DNS name")
    labels = ascii_name.split(".")
    if any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Target contains an invalid DNS label")
    if labels[-1].isdigit() or len(labels[-1]) < 2:
        raise ValueError("Target must end in a valid public-style suffix")
    return f"*.{ascii_name}" if wildcard else ascii_name


def scan_workspace(output_dir: Path, project_id: str, scan_id: str) -> Path:
    """Return the confined, immutable workspace root for one scan."""
    uuid_adapter = TypeAdapter(str)
    safe_project = uuid_adapter.validate_python(project_id).strip()
    safe_scan = uuid_adapter.validate_python(scan_id).strip()
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", safe_project):
        raise ValueError("Invalid project identifier")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", safe_scan):
        raise ValueError("Invalid scan identifier")

    base = output_dir.resolve()
    workspace = (base / "projects" / safe_project / "scans" / safe_scan / "assets").resolve()
    if base not in workspace.parents:
        raise ValueError("Scan workspace escaped the configured output directory")
    return workspace


def scope_fingerprint(domains: list[str], oos: list[str], tools: list[str], wordlist: str | None) -> str:
    """Create a deterministic fingerprint for scope-sensitive result reuse."""
    payload = {
        "domains": sorted(domains),
        "oos": sorted(oos),
        "tools": sorted(set(tools)),
        "wordlist": wordlist or "",
        "schema": 1,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
