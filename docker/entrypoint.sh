#!/bin/bash
set -e

# Named volumes may have been created by an older root-running release. Image
# ownership does not apply after Docker mounts those volumes, so migrate them on
# every startup before dropping privileges. This operation is idempotent.
if [ "$(id -u)" -eq 0 ]; then
    chown -R www-data:www-data /app/output /app/data
    RUN_AS=(gosu www-data)
else
    RUN_AS=()
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         ShadowGrid  v3.1  Startup        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Tool availability check
echo "[ Tool availability ]"
for t in assetfinder subfinder amass shuffledns dnsx pd-httpx naabu tlsx nuclei subzy \
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
    "${RUN_AS[@]}" nuclei -update-templates -silent &>/dev/null &
fi

# Start FastAPI backend
echo "[ Starting backend on :8000 ]"
cd /app/backend
"${RUN_AS[@]}" python3 -m uvicorn main:app \
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

echo "[ Starting Nginx on :8080 ]"
echo "[ Web UI → http://localhost:8080 ]"
echo ""
exec "${RUN_AS[@]}" nginx -g "daemon off;"
