"""Normalize tool-centric results into an evidence-backed asset inventory."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field

from models import ResultSeverity, ToolCategory, ToolResult
from scope import normalize_domain


class AssetType(str, Enum):
    """Canonical asset types currently derived from reconnaissance evidence."""

    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    URL = "url"
    SERVICE = "service"
    TECHNOLOGY = "technology"


class InventoryAsset(BaseModel):
    """One stable asset aggregated from one or more tool observations."""

    id: str
    type: AssetType
    value: str
    states: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime
    last_seen: datetime


class AssetObservation(BaseModel):
    """Evidence that a tool observed an asset in a specific state."""

    id: str
    asset_id: str
    tool: str
    state: str
    evidence_hash: str
    observed_at: datetime


class AssetRelationship(BaseModel):
    """A directed relationship between two normalized assets."""

    id: str
    source_asset_id: str
    target_asset_id: str
    type: str
    sources: list[str] = Field(default_factory=list)


class InventoryFinding(BaseModel):
    """Stable finding identity used for new/fixed/regressed comparisons."""

    id: str
    asset_id: str
    tool: str
    title: str
    severity: ResultSeverity = ResultSeverity.UNKNOWN
    evidence_hash: str
    data: dict[str, Any] = Field(default_factory=dict)


class InventorySnapshot(BaseModel):
    """Immutable normalized inventory generated from one completed scan."""

    scan_id: str
    project_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    assets: list[InventoryAsset] = Field(default_factory=list)
    observations: list[AssetObservation] = Field(default_factory=list)
    relationships: list[AssetRelationship] = Field(default_factory=list)
    findings: list[InventoryFinding] = Field(default_factory=list)


class InventoryDelta(BaseModel):
    """Material changes between two normalized inventory snapshots."""

    scan_id: str
    previous_scan_id: str | None = None
    added_assets: list[InventoryAsset] = Field(default_factory=list)
    removed_assets: list[InventoryAsset] = Field(default_factory=list)
    changed_assets: list[dict[str, Any]] = Field(default_factory=list)
    new_findings: list[InventoryFinding] = Field(default_factory=list)
    resolved_findings: list[InventoryFinding] = Field(default_factory=list)


def _stable_id(namespace: str, *parts: str) -> str:
    payload = "\x1f".join((namespace, *(part.strip().lower() for part in parts)))
    return hashlib.sha256(payload.encode()).hexdigest()


def _evidence_hash(data: Any) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _canonical_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, parsed.query, ""))


def _canonical_host(value: str) -> str | None:
    candidate = (value or "").strip()
    if not candidate:
        return None
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    candidate = candidate.split("/", 1)[0]
    if candidate.count(":") == 1:
        candidate = candidate.rsplit(":", 1)[0]
    try:
        return normalize_domain(candidate, allow_wildcard=False)
    except ValueError:
        return None


def _canonical_ip(value: Any) -> str | None:
    if isinstance(value, list):
        value = value[0] if value else ""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _severity(value: Any) -> ResultSeverity:
    try:
        return ResultSeverity(str(value or "unknown").lower())
    except ValueError:
        return ResultSeverity.UNKNOWN


def build_inventory(scan_id: str, project_id: str, roots: Iterable[str],
                    results: Iterable[ToolResult]) -> InventorySnapshot:
    """Build one deterministic normalized inventory from stored tool results."""
    now = datetime.now(timezone.utc)
    assets: dict[str, InventoryAsset] = {}
    observations: dict[str, AssetObservation] = {}
    relationships: dict[str, AssetRelationship] = {}
    findings: dict[str, InventoryFinding] = {}

    def upsert_asset(asset_type: AssetType, value: str, tool: str, state: str,
                     attributes: dict[str, Any] | None = None) -> InventoryAsset:
        asset_id = _stable_id("asset", asset_type.value, value)
        asset = assets.get(asset_id)
        if asset is None:
            asset = InventoryAsset(
                id=asset_id, type=asset_type, value=value, first_seen=now,
                last_seen=now, states=[], sources=[], attributes={},
            )
            assets[asset_id] = asset
        asset.last_seen = now
        if state and state not in asset.states:
            asset.states.append(state)
        if tool and tool not in asset.sources:
            asset.sources.append(tool)
        if attributes:
            asset.attributes.update({key: val for key, val in attributes.items() if val not in (None, "", [])})
        return asset

    def observe(asset: InventoryAsset, tool: str, state: str, row: dict[str, Any]) -> None:
        evidence = _evidence_hash(row)
        observation_id = _stable_id("observation", scan_id, asset.id, tool, state, evidence)
        observations[observation_id] = AssetObservation(
            id=observation_id, asset_id=asset.id, tool=tool, state=state,
            evidence_hash=evidence, observed_at=now,
        )

    def relate(source: InventoryAsset, target: InventoryAsset, relation_type: str, tool: str) -> None:
        relationship_id = _stable_id("relationship", source.id, target.id, relation_type)
        relationship = relationships.get(relationship_id)
        if relationship is None:
            relationship = AssetRelationship(
                id=relationship_id, source_asset_id=source.id,
                target_asset_id=target.id, type=relation_type, sources=[],
            )
            relationships[relationship_id] = relationship
        if tool not in relationship.sources:
            relationship.sources.append(tool)

    root_assets: dict[str, InventoryAsset] = {}
    for root in roots:
        normalized = normalize_domain(root)
        root_assets[normalized] = upsert_asset(AssetType.DOMAIN, normalized, "scope", "authorized")

    for result in results:
        default_state = {
            ToolCategory.SUBDOMAIN: "discovered",
            ToolCategory.DNS: "dns_observed",
            ToolCategory.HTTP: "http_observed",
            ToolCategory.PORT: "tcp_observed",
            ToolCategory.URL: "url_observed",
            ToolCategory.TECH: "technology_observed",
            ToolCategory.VULN: "finding_observed",
        }.get(result.category, "observed")

        root_asset = root_assets.get(_canonical_host(result.domain) or "")
        for row in result.data:
            state = str(row.get("state") or default_state)
            host_value = row.get("host") or row.get("domain") or row.get("subdomain")
            host = _canonical_host(str(host_value or ""))
            host_asset = upsert_asset(AssetType.HOSTNAME, host, result.tool, state) if host else None
            if host_asset:
                observe(host_asset, result.tool, state, row)
                if root_asset and host_asset.id != root_asset.id:
                    relate(root_asset, host_asset, "contains_hostname", result.tool)

            ip = _canonical_ip(row.get("ip") or row.get("a"))
            if ip:
                ip_asset = upsert_asset(AssetType.IP_ADDRESS, ip, result.tool, "ip_observed")
                observe(ip_asset, result.tool, "ip_observed", row)
                if host_asset:
                    relate(host_asset, ip_asset, "resolves_to", result.tool)

            canonical_url = _canonical_url(str(row.get("url") or row.get("matched_at") or ""))
            url_asset = None
            if canonical_url:
                url_asset = upsert_asset(AssetType.URL, canonical_url, result.tool, state)
                observe(url_asset, result.tool, state, row)
                url_host = _canonical_host(canonical_url)
                if url_host:
                    url_host_asset = upsert_asset(AssetType.HOSTNAME, url_host, result.tool, state)
                    relate(url_asset, url_host_asset, "served_by", result.tool)
                    host_asset = host_asset or url_host_asset

            service_asset = None
            port = row.get("port")
            if host_asset and port not in (None, ""):
                try:
                    port_number = int(port)
                except (TypeError, ValueError):
                    port_number = 0
                if 1 <= port_number <= 65535:
                    service_asset = upsert_asset(
                        AssetType.SERVICE, f"{host_asset.value}:{port_number}", result.tool, state,
                        {"port": port_number, "service": row.get("service", "")},
                    )
                    observe(service_asset, result.tool, state, row)
                    relate(service_asset, host_asset, "runs_on", result.tool)

            technologies = row.get("tech") or row.get("technologies") or []
            if isinstance(technologies, str):
                technologies = [technologies]
            if host_asset and isinstance(technologies, list):
                for technology in technologies:
                    name = str(technology).strip()
                    if not name:
                        continue
                    tech_asset = upsert_asset(AssetType.TECHNOLOGY, name, result.tool, "detected")
                    relate(host_asset, tech_asset, "uses_technology", result.tool)

            reported_vulnerabilities = row.get("vulnerabilities") or []
            if isinstance(reported_vulnerabilities, str):
                reported_vulnerabilities = [reported_vulnerabilities]
            if isinstance(reported_vulnerabilities, list):
                affected = service_asset or host_asset or root_asset
                for vulnerability in reported_vulnerabilities:
                    cve = str(vulnerability).strip().upper()
                    if not affected or not cve:
                        continue
                    finding_id = _stable_id("finding", affected.id, result.tool, cve)
                    findings[finding_id] = InventoryFinding(
                        id=finding_id,
                        asset_id=affected.id,
                        tool=result.tool,
                        title=f"Shodan reported {cve}",
                        severity="unknown",
                        evidence_hash=_evidence_hash(row),
                        data={"cve": cve, "source": "shodan", "service": row},
                    )

            if result.category in {ToolCategory.VULN, ToolCategory.WORDPRESS}:
                affected = url_asset or host_asset or root_asset
                if affected:
                    title = str(row.get("name") or row.get("title") or row.get("template_id") or result.tool)
                    identity = str(row.get("template_id") or row.get("id") or title)
                    finding_id = _stable_id("finding", affected.id, result.tool, identity)
                    findings[finding_id] = InventoryFinding(
                        id=finding_id, asset_id=affected.id, tool=result.tool,
                        title=title, severity=_severity(row.get("severity")),
                        evidence_hash=_evidence_hash(row), data=row,
                    )

    for collection in (assets.values(), relationships.values()):
        for item in collection:
            if hasattr(item, "states"):
                item.states.sort()
            if hasattr(item, "sources"):
                item.sources.sort()

    return InventorySnapshot(
        scan_id=scan_id, project_id=project_id,
        assets=sorted(assets.values(), key=lambda item: (item.type.value, item.value)),
        observations=sorted(observations.values(), key=lambda item: item.id),
        relationships=sorted(relationships.values(), key=lambda item: item.id),
        findings=sorted(findings.values(), key=lambda item: item.id),
    )


def compare_inventories(current: InventorySnapshot,
                        previous: InventorySnapshot | None) -> InventoryDelta:
    """Return material asset and finding changes between two snapshots."""
    if previous is None:
        return InventoryDelta(
            scan_id=current.scan_id,
            added_assets=current.assets,
            new_findings=current.findings,
        )

    current_assets = {asset.id: asset for asset in current.assets}
    previous_assets = {asset.id: asset for asset in previous.assets}
    current_findings = {finding.id: finding for finding in current.findings}
    previous_findings = {finding.id: finding for finding in previous.findings}

    changed: list[dict[str, Any]] = []
    for asset_id in current_assets.keys() & previous_assets.keys():
        before = previous_assets[asset_id]
        after = current_assets[asset_id]
        if before.states != after.states or before.attributes != after.attributes:
            changed.append({"asset": after, "before": {"states": before.states, "attributes": before.attributes}})

    return InventoryDelta(
        scan_id=current.scan_id,
        previous_scan_id=previous.scan_id,
        added_assets=[current_assets[key] for key in sorted(current_assets.keys() - previous_assets.keys())],
        removed_assets=[previous_assets[key] for key in sorted(previous_assets.keys() - current_assets.keys())],
        changed_assets=changed,
        new_findings=[current_findings[key] for key in sorted(current_findings.keys() - previous_findings.keys())],
        resolved_findings=[previous_findings[key] for key in sorted(previous_findings.keys() - current_findings.keys())],
    )
