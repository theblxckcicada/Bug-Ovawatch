"""Safe assessment-level HTTP identity and header handling."""
from __future__ import annotations

import re
from typing import Mapping

DEFAULT_USER_AGENT = "ShadowGrid/3.1"
MAX_CUSTOM_HEADERS = 20
MAX_HEADER_VALUE_LENGTH = 2048
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
BLOCKED_HEADERS = {
    "connection", "content-length", "expect", "host", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade", "user-agent",
}


def validate_user_agent(value: str) -> str:
    """Validate and normalize an assessment User-Agent value."""
    normalized = str(value or DEFAULT_USER_AGENT).strip()
    if not normalized or len(normalized) > 512 or "\r" in normalized or "\n" in normalized:
        raise ValueError("User-Agent must be 1-512 characters without line breaks")
    return normalized


def validate_custom_headers(value: Mapping[str, str] | None) -> dict[str, str]:
    """Validate custom end-to-end request headers and reject request smuggling primitives."""
    if not value:
        return {}
    if len(value) > MAX_CUSTOM_HEADERS:
        raise ValueError(f"At most {MAX_CUSTOM_HEADERS} custom headers are allowed")
    normalized: dict[str, str] = {}
    seen: set[str] = set()
    for raw_name, raw_value in value.items():
        name = str(raw_name).strip()
        header_value = str(raw_value).strip()
        lowered = name.lower()
        if not HEADER_NAME_RE.fullmatch(name):
            raise ValueError(f"Invalid HTTP header name: {name!r}")
        if lowered in BLOCKED_HEADERS:
            raise ValueError(f"Header {name!r} is managed by ShadowGrid and cannot be overridden")
        if lowered in seen:
            raise ValueError(f"Duplicate HTTP header: {name!r}")
        if not header_value or len(header_value) > MAX_HEADER_VALUE_LENGTH:
            raise ValueError(f"Header {name!r} must contain 1-{MAX_HEADER_VALUE_LENGTH} characters")
        if "\r" in header_value or "\n" in header_value or "\x00" in header_value:
            raise ValueError(f"Header {name!r} contains prohibited control characters")
        seen.add(lowered)
        normalized[name] = header_value
    return normalized


def target_request_headers(user_agent: str, custom_headers: Mapping[str, str]) -> dict[str, str]:
    """Build the headers sent only to assessment targets."""
    return {"User-Agent": validate_user_agent(user_agent), **validate_custom_headers(custom_headers)}
