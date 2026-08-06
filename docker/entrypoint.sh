#!/bin/bash
set -e

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         Shadow-Grid  v1.0  Startup       ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Tool availability check
echo "[ Tool availability ]"
for t in assetfinder subfinder amass shuffledns dnsx pd-httpx naabu nuclei subzy \
          gowitness whatweb waybackurls gau katana urlfinder asnmap massdns whois dig; do
    if command -v "$t" &>/dev/null; then
        echo "  ✓  $t"
    else
        echo "  ✗  $t (not installed — will be skipped)"
    fi
done
if command -v asnmap &>/dev/null && [ -z "${PDCP_API_KEY:-}" ]; then
    echo "  !  asnmap installed but PDCP_API_KEY is empty — asnmap will be skipped unless configured in Settings"
fi
if [ -z "${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}${GOOGLE_AI_API_KEY:-}${DEEPSEEK_API_KEY:-}${GROQ_API_KEY:-}" ]; then
    echo "  !  AI Analysis disabled until an AI API key is saved in Settings"
fi
echo ""

# Fetch nuclei templates in background (non-blocking, best-effort)
if command -v nuclei &>/dev/null; then
    echo "[ Updating nuclei templates in background ]"
    nuclei -update-templates -silent &>/dev/null &
fi

# Start FastAPI backend
echo "[ Starting backend on :8000 ]"
cd /app/backend
python3 -m uvicorn main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --log-level warning &
BACKEND_PID=$!

# Wait up to 30s for backend
echo "[ Waiting for backend... ]"
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8000/api/health > /dev/null 2>&1; then
        echo "[ Backend ready ]"
        break
    fi
    sleep 1
done

if ! kill -0 $BACKEND_PID 2>/dev/null; then
    echo "ERROR: Backend failed to start. Printing logs..."
    exit 1
fi

echo "[ Starting Nginx on :80 ]"
echo "[ Web UI → http://localhost:8080 (mapped from container :80) ]"
echo ""
exec nginx -g "daemon off;"
