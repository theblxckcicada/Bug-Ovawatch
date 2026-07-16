<div align="center">

<img src="frontend/src/assets/shadow-grid-icon.png" width="132" alt="ShadowGrid logo">

# ShadowGrid

**Automated attack-surface reconnaissance — light up what's exposed before someone else does.**

![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi&logoColor=white)
![Angular](https://img.shields.io/badge/Frontend-Angular%2017-DD0031?logo=angular&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Tools](https://img.shields.io/badge/recon%20tools-20%2B-00e87a)

</div>

---

## Overview

**ShadowGrid** is a full-stack reconnaissance automation framework that orchestrates 20+ best-in-class open-source recon tools into a single, phased, parallelised pipeline behind a clean web UI.

You define a **project** and its in-scope (and out-of-scope) targets, choose your tools, and launch a **scan**. ShadowGrid walks the engagement through six deterministic phases — asset discovery, subdomain enumeration, DNS resolution, HTTP probing & port scanning, URL discovery, and vulnerability scanning / screenshots / dorking / AI analysis — running independent tools in parallel, streaming **live progress over SSE**, and collecting every finding into a unified results dashboard.

It's built for **bug-bounty hunters, penetration testers, and security teams** who want repeatable, resumable external recon without hand-wiring a dozen CLIs and reconciling their output by hand.

> The name says what it does: a **grid** of recon nodes mapping a target's attack surface — everything sits in **shadow** until a scan lights it up, with a live reticle locked on the host being probed (exactly what the logo depicts).

### Why ShadowGrid

- **One pipeline, many tools** — subfinder, amass, httpx, naabu, nuclei, katana, gowitness and more, coordinated so each phase hands clean artifacts to the next.
- **Phase gating** — a phase never starts until the previous one has fully drained and written its hand-off files (e.g. merged subdomains → alive hosts → alive URLs), so downstream tools always get real input.
- **Live, resumable, cancellable** — watch every tool report in real time, stop a run mid-flight (in-flight processes are terminated), or resume a project and reuse prior successful results instead of re-running finished work.
- **Scope-aware** — out-of-scope patterns (incl. wildcards) are filtered at every stage, so results stay inside your authorisation.
- **Bring your own storage** — always-on local JSON/file storage, with optional mirroring to Azure Table Storage.

---

## Quick Start (Docker)

```bash
git clone https://github.com/ovawatch-sec/shadow-grid.git
cd shadow-grid

docker compose -f docker/docker-compose.yml up --build -d
```

Open **http://localhost:8080**, then:

1. **Set a password** (required on first visit) and log in.
2. **Create a project** and **add targets** (mark any out-of-scope domains).
3. **Select tools** and **launch a scan** — watch live progress, then open the results dashboard.

---

## First Run & Authentication

ShadowGrid uses single-password auth — no default credentials ever exist. On first visit the UI forces you to set a password; every project, scan, and settings page is locked behind login. Tokens are HMAC-signed and expire after 7 days.

**Forgot the password?** Reset it offline with the bundled script (it lives in the same Docker volume as the app data):

```bash
# Interactive prompt inside the running container
docker exec -it shadowgrid python3 /app/backend/reset_password.py

# …or via the convenience wrapper
./docker/reset-password.sh
```

By default the reset rotates the token-signing secret (logging out all sessions). Pass `--keep-sessions` to preserve existing logins. See `--help` for all options.

---

## Architecture

```
┌─────────────────────────────────────────┐
│  Browser (Angular 17)                    │
│  - Project & target management           │
│  - Scan config + tool selection          │
│  - Live progress (Server-Sent Events)    │
│  - Results dashboard (multi-tab)         │
└────────────────┬─────────────────────────┘
                 │ HTTP / SSE   (nginx reverse proxy)
┌────────────────▼─────────────────────────┐
│  FastAPI Backend (Python 3.12)           │
│  - REST API: projects / scans / results  │
│  - Async phased + parallel scan engine   │
│  - Pluggable tool abstraction layer      │
│  - Single-password auth (bearer tokens)  │
└────────────────┬─────────────────────────┘
                 │
┌────────────────▼─────────────────────────┐
│  Storage Layer                           │
│  ├─ File storage (always on)             │
│  │    output/<domain>/<tool>_output.txt  │
│  │    output/.meta/{projects,scans,…}    │
│  └─ Azure Table Storage (optional)       │
│       shadowgrid{Projects|Targets|Scans| │
│                  Results|Config}         │
└──────────────────────────────────────────┘
```

The whole stack ships as a **single container** — Angular build, FastAPI backend, ~20 compiled Go/Ruby recon binaries, and nginx — built via a multi-stage Dockerfile.

---

## Scan Phases (parallel execution)

| Phase | Tools | Execution |
|-------|-------|-----------|
| 1 — Asset Discovery | `whois`, `asnmap` | parallel |
| 2 — Subdomain Enumeration | `crtsh`, `assetfinder`, `subfinder`, `amass`, `shuffledns` | **all parallel** |
| 3 — DNS Resolution | `dnsx`, `dns_records`, `zone_transfer` | parallel |
| 4 — HTTP Probing & Ports | `httpx`, `naabu` | parallel |
| 5 — URL Discovery | `waybackurls`, `gau`, `katana`, `urlfinder` | **all parallel** |
| 6 — Vuln · Takeover · Screenshots · Dorks · AI | `nuclei`, `subdomain_takeover`, `gowitness`, `whatweb`, `google_dorks`, `ai_analysis` | parallel (AI runs last) |

Between phases, ShadowGrid writes canonical hand-off artifacts — `subdomains_merged.txt` → `alive_subdomains.txt` → `alive_urls.txt` — so each phase feeds the next with clean, de-duplicated, in-scope input.

**Notes**
- **Cancel:** a running scan can be stopped from the live progress page; the backend kills in-flight tool processes.
- **Resume vs. fresh:** launching a scan on a project that already has results lets you continue from prior results or start clean.
- **Google dorking** executes generated dorks live — via Google Programmable Search (CSE) when an API key + engine ID are saved in Settings, otherwise a DuckDuckGo fallback.
- **Subdomain takeover** hunts dangling/claimable subdomains (nuclei takeover templates, plus `subzy` when available).
- **AI analysis** summarises findings when an AI provider key (OpenAI / Anthropic / Google / DeepSeek / Groq) is configured in Settings.

---

## Pre-installed Tools

| Tool | Purpose |
|------|---------|
| assetfinder | Passive subdomain discovery |
| subfinder | Multi-source passive subdomain enumeration |
| amass | OWASP passive subdomain enumeration |
| shuffledns | Active DNS bruteforce (via massdns) |
| crt.sh | Certificate-transparency lookup (HTTP) |
| dnsx | DNS resolution + record lookups |
| httpx | HTTP probing + tech detection |
| naabu | Port scanning |
| nuclei | Template-based vulnerability scanning |
| subzy | Subdomain-takeover detection (secondary engine) |
| gowitness | Web screenshots |
| whatweb | Technology fingerprinting |
| waybackurls | Historical URLs from the Wayback Machine |
| gau | GetAllURLs (Wayback + CommonCrawl + OTX) |
| katana | Active web crawler |
| urlfinder | Passive URL discovery |
| asnmap | ASN + IP-range discovery |
| whois | WHOIS lookups |
| dig | DNS record queries |

> A tool that isn't installed (or is missing an API key) is cleanly **skipped** and reported in progress — it never breaks a scan.

---

## CLI Usage (no Docker required)

```bash
cd shadow-grid
pip install -r backend/requirements.txt

# Full scan
python3 recon.py -d example.com

# Passive only
python3 recon.py -d example.com --passive-only

# Specific tools
python3 recon.py -d example.com --tools crtsh,subfinder,httpx,nuclei

# Multiple targets + out-of-scope patterns
python3 recon.py -d example.com shop.example.com --oos "*.internal.example.com"

# Custom output / data directories
python3 recon.py -d example.com --output-dir ./output --data-dir ./data

# With Azure storage
python3 recon.py -d example.com --azure-conn "DefaultEndpointsProtocol=https;..."

# List all tools and their availability
python3 recon.py -d x --list-tools
```

> The CLI shares the exact same scan engine and tool layer as the web app — only the entry point differs.

---

## Docker Commands

```bash
# Build & start (detached)
docker compose -f docker/docker-compose.yml up --build -d

# Follow logs
docker logs -f shadowgrid

# Shell into the container
docker exec -it shadowgrid bash

# Stop
docker compose -f docker/docker-compose.yml down
```

---

## Azure Table Storage (optional)

1. Create an Azure Storage account.
2. In the web UI → **Settings** → enable **Azure Table Storage**.
3. Paste your connection string (or account name + key) — tables are created automatically.

Or configure it via environment in `docker/docker-compose.yml`:

```env
AZURE_STORAGE_ENABLED=true
AZURE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=...
```

Local file storage is always active; Azure is mirrored on top of it.

---

## Adding a New Tool

ShadowGrid's tool layer is pluggable — adding a tool touches two files:

1. Create `backend/tools/<category>/mytool.py`.
2. Subclass `BaseTool`; set `name`, `category`, `description`, `parallel_group`.
3. Implement `run()` (invoke the binary) and `parse()` (raw output → `list[dict]`).
4. Add one line to `backend/tools/registry.py`.

That's it — the scan engine, API, and UI pick it up automatically.

---

## Project Structure

```
shadow-grid/
├── backend/            FastAPI app, scan engine, tool layer, storage, auth
│   ├── scan_engine.py      phased + parallel orchestration
│   ├── tools/              one module per recon tool (+ registry.py)
│   ├── storage/            file + Azure dual storage
│   └── reset_password.py   offline password-reset utility
├── frontend/           Angular 17 SPA (projects, scans, live progress, results)
├── docker/             Dockerfile, docker-compose.yml, nginx.conf, entrypoint.sh
├── data/               wordlists, resolvers and other tool data
└── recon.py            CLI entry point (same engine as the web app)
```

---

## Legal & Ethical Use

ShadowGrid is intended for **authorised security testing only** — your own assets, or targets you have explicit written permission to assess (e.g. an in-scope bug-bounty program or a signed engagement). Active modules (port scanning, DNS bruteforce, crawling, vulnerability templates) generate real traffic against targets. Scanning systems without authorisation may be illegal. **You are responsible for how you use this tool.**
