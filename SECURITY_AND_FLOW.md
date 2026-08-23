# ShadowGrid Security and Recon Flow

## Safe deployment defaults

- Docker publishes the UI on port `8080` so it is reachable across a VM/LAN.
  Set `SHADOWGRID_BIND_ADDRESS=127.0.0.1` to restore VM-local binding.
- The runtime runs as `www-data`, drops all Linux capabilities, and enables
  `no-new-privileges`.
- Put a TLS reverse proxy or private VPN in front of ShadowGrid before allowing
  remote access.
- CORS defaults to `*` because authentication uses explicit bearer tokens, not
  browser cookies. Set `CORS_ORIGINS` to a comma-separated origin allowlist when
  deploying beyond a trusted VM or LAN.
- Authentication and tool API keys are stored in the mandatory local SQLite
  database and are never sent to an external storage service.
- Provider API keys remain optional. Every included scanner is open source;
  paid provider subscriptions are not required for the default pipeline.

## Implemented flow

1. Validate and canonicalize authorized DNS targets.
2. Create an isolated, scan-owned evidence workspace.
3. Run passive asset and subdomain discovery.
4. Merge, de-duplicate, and apply out-of-scope rules.
5. Resolve DNS and separate verified names from probe candidates.
6. Validate HTTP, TLS, and approved TCP ports.
7. Discover and revalidate URLs.
8. Run evidence-selected vulnerability, WordPress, screenshot, takeover, and
   analysis tools.
   - `cve_check` runs CVE-tagged Nuclei templates only against verified alive URLs.
   - `shodan` runs only when explicitly selected and a saved API key is available;
     returned hostnames are filtered back to the authorized root domain.
9. Correlate tool output into stable assets, relationships, observations, and findings.
10. Persist the normalized snapshot, scope fingerprint, and hashed execution manifest.
11. Compare the snapshot with the preceding completed assessment.
12. Delete the complete workspace when a scan is cancelled or removed.

## Evidence layout

```text
output/
  shadowgrid.db
  projects/<project-id>/
    scans/<scan-id>/
      assets/<canonical-domain>/
        subdomains_merged.txt
        resolved_subdomains.txt
        probe_candidates.txt
        alive_urls.txt
        <tool artifacts>
      _manifest.json
```

On upgrade, the previous `output/.meta/` JSON metadata is imported into SQLite
once and retained as a recovery copy. All subsequent metadata operations use SQL.

## Local operational endpoints

- `GET /api/ready` is an unauthenticated container readiness check.
- `GET /api/metrics` emits Prometheus text and requires authentication.
- `GET /api/inventory/{scan-id}` returns a normalized snapshot.
- `GET /api/inventory/{scan-id}/delta` compares it with the preceding completed scan.

## Remaining free/open-source roadmap

The current implementation intentionally works without a paid service. Larger
self-hosted options include PostgreSQL for multi-user deployments, Redis with
Dramatiq/Celery for durable distributed jobs, OpenTelemetry for tracing, and
Open Policy Agent for centrally managed scope policies. These are deployment
choices, not requirements for the local single-container workflow.

Future discovery plugins such as `alterx`, JavaScript endpoint extraction, and
API-schema discovery should emit the normalized inventory contracts rather than
introducing new tool-specific result shapes.
