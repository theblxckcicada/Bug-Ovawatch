# ═══════════════════════════════════════════════════════════════════
# Shadow-Grid — Dockerfile  (validated)
# Stage 1 : Build Angular frontend
# Stage 2 : Compile Go recon tools  (Go 1.24 — required by PD tools)
# Stage 3 : Final runtime image
# ═══════════════════════════════════════════════════════════════════

# ── Stage 1: Angular Build ──────────────────────────────────────
FROM node:20.19.4-alpine3.22 AS frontend-build

WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
# Production build has Angular font inlining disabled; Docker builds must not depend on Google Fonts.
RUN npm run build


# ── Stage 2: Go Tools Builder ───────────────────────────────────
# Go 1.24 required — ProjectDiscovery tools (subfinder v2.14+, httpx, nuclei v3, etc.)
# all mandate go >= 1.24 as of 2024-2025.
FROM golang:1.26.3-bookworm AS go-builder

# libpcap-dev: required at compile time for naabu CGO linkage
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Staging dir — all successfully built binaries land here.
# Each tool is its own RUN layer for clear failure attribution.
# || true on optional tools means the build keeps going.
RUN mkdir -p /staging

# shuffledns is only a wrapper; it requires the massdns binary at runtime.
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && make -C /tmp/massdns \
    && cp /tmp/massdns/bin/massdns /staging/

# ── Subdomain enumeration ────────────────────────────────────────
RUN go install github.com/tomnomnom/assetfinder@latest \
    && cp /go/bin/assetfinder /staging/

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0 \
    && cp /go/bin/subfinder /staging/

RUN go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.2.1 \
    && cp /go/bin/shuffledns /staging/

# ── DNS ──────────────────────────────────────────────────────────
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.0 \
    && cp /go/bin/dnsx /staging/

# ── HTTP & Ports ─────────────────────────────────────────────────
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0 \
    && cp /go/bin/httpx /staging/pd-httpx

RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 \
    && cp /go/bin/naabu /staging/

RUN go install github.com/projectdiscovery/tlsx/cmd/tlsx@v1.3.0 \
    && cp /go/bin/tlsx /staging/

RUN go install github.com/ffuf/ffuf/v2@v2.1.0 \
    && cp /go/bin/ffuf /staging/

# ── Vuln & Screenshots ───────────────────────────────────────────
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.8.0 \
    && cp /go/bin/nuclei /staging/

# subzy — secondary subdomain-takeover engine (nuclei takeover templates are primary)
RUN go install github.com/PentestPad/subzy@latest \
    && cp /go/bin/subzy /staging/ \
    || echo "WARN: subzy build failed — takeover detection still works via nuclei"

RUN go install github.com/sensepost/gowitness@latest \
    && cp /go/bin/gowitness /staging/

# ── Crawling ─────────────────────────────────────────────────────
RUN go install github.com/projectdiscovery/katana/cmd/katana@v1.7.0 \
    && cp /go/bin/katana /staging/

# ── URL discovery ────────────────────────────────────────────────
RUN go install github.com/lc/gau/v2/cmd/gau@latest \
    && cp /go/bin/gau /staging/

RUN go install github.com/tomnomnom/waybackurls@latest \
    && cp /go/bin/waybackurls /staging/

# urlfinder — try current path; fallback if module path changed
RUN go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@v0.0.3 \
    && cp /go/bin/urlfinder /staging/ \
    || echo "WARN: urlfinder not available"

# ── ASN ──────────────────────────────────────────────────────────
RUN go install github.com/projectdiscovery/asnmap/cmd/asnmap@v1.1.1 \
    && cp /go/bin/asnmap /staging/

# ── Amass (optional — large, slow to compile) ────────────────────
RUN go install github.com/owasp-amass/amass/v4/...@v4.2.0 \
    && cp /go/bin/amass /staging/ \
    || echo "WARN: amass build failed — passive subdomain tools still work"

# Final inventory
RUN echo "=== Staged binaries ===" && ls -lh /staging/


# ── Stage 3: Final Runtime Image ─────────────────────────────────
FROM python:3.12.10-slim-bookworm

LABEL org.opencontainers.image.title="Shadow-Grid"
LABEL org.opencontainers.image.version="3.1.0"
LABEL org.opencontainers.image.description="Automated recon framework — Angular + FastAPI + Docker"

# System packages — no inline # comments (apt-get treats them as package names)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    whois \
    netbase \
    dnsutils \
    curl \
    wget \
    git \
    ruby \
    ruby-dev \
    build-essential \
    chromium \
    ca-certificates \
    libpcap0.8 \
    libpcap-dev \
    procps \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# WhatWeb (Ruby gem)
RUN gem install whatweb --no-document 2>&1 \
    || echo "WARN: whatweb gem install failed — tool will be skipped"

# WPScan (Ruby gem) — WordPress vulnerability scanner
RUN gem install wpscan --no-document 2>&1 \
    || echo "WARN: wpscan gem install failed — tool will be skipped"

# Python backend
WORKDIR /app
COPY backend/ ./backend/
RUN pip3 install --no-cache-dir -r backend/requirements.txt
RUN pip3 install --no-cache-dir wafw00f==2.3.2

# All Go binaries from staging. Copy after pip install so Python console scripts
# cannot overwrite ProjectDiscovery binaries such as httpx. The PD binary is
# intentionally named pd-httpx to avoid the Python httpx CLI name collision.
COPY --from=go-builder /staging/ /usr/local/bin/
RUN chmod +x /usr/local/bin/* 2>/dev/null || true

# Angular frontend — Angular 17 application builder outputs to dist/<name>/browser/
COPY --from=frontend-build /build/frontend/dist/shadowgrid/ ./frontend/dist/shadowgrid/

# Nginx config
COPY docker/nginx.conf /etc/nginx/sites-enabled/default

# Data directories
RUN mkdir -p /app/output /app/data/wordlists
COPY data/ /app/data/

# Entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /app/runtime-home /var/cache/nginx /var/lib/nginx /var/log/nginx /run \
    && usermod -d /app/runtime-home www-data \
    && chown -R www-data:www-data /app/output /app/data /app/runtime-home /var/cache/nginx /var/lib/nginx /var/log/nginx /run

# The entrypoint starts as root only long enough to repair ownership on mounted
# persistent volumes, then permanently drops to www-data for backend and nginx.
USER root

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
