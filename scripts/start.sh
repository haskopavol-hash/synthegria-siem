#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# scripts/start.sh — Production entrypoint for the Synthegria SIEM API
#
# Environment variables (all optional except STRIPE_SECRET_KEY):
#
#   STRIPE_SECRET_KEY   Required. Stripe secret key (sk_live_... or sk_test_...).
#   PORT                TCP port to bind (default: 8000).
#   WEB_CONCURRENCY     Number of uvicorn worker processes (default: 1).
#                       Set to 1 when running inside a container and scale
#                       horizontally at the orchestrator level instead.
#                       For bare-metal / VM deployment use: 2 * nproc + 1
#   LOG_LEVEL           uvicorn log level: debug|info|warning|error (default: info)
#   FORWARDED_ALLOW_IPS Comma-separated IPs/CIDRs trusted for X-Forwarded-For
#                       (default: * — trusts all proxies; restrict in production
#                       to your load-balancer CIDR for added safety).
# ─────────────────────────────────────────────────────────────────────────────

set -e

# ── Required secrets check ────────────────────────────────────────────────────
if [ -z "${STRIPE_SECRET_KEY}" ]; then
  echo "ERROR: STRIPE_SECRET_KEY environment variable is not set." >&2
  echo "       Set it with: -e STRIPE_SECRET_KEY=sk_live_..." >&2
  exit 1
fi

# ── Defaults ──────────────────────────────────────────────────────────────────
PORT="${PORT:-8000}"
WEB_CONCURRENCY="${WEB_CONCURRENCY:-1}"
LOG_LEVEL="${LOG_LEVEL:-info}"
FORWARDED_ALLOW_IPS="${FORWARDED_ALLOW_IPS:-*}"

echo "Synthegria SIEM API starting"
echo "  port             : ${PORT}"
echo "  workers          : ${WEB_CONCURRENCY}"
echo "  log_level        : ${LOG_LEVEL}"
echo "  stripe_mode      : $(echo "${STRIPE_SECRET_KEY}" | grep -q '^sk_live_' && echo LIVE || echo TEST)"

# ── Launch uvicorn ────────────────────────────────────────────────────────────
# --proxy-headers          trust X-Forwarded-For/Proto headers from load balancers
# --forwarded-allow-ips    which upstream IPs are trusted to set those headers
# --no-access-log          suppress uvicorn's built-in access log — the app's
#                          AuditLogMiddleware emits structured JSON instead
# --timeout-graceful-shutdown  allow in-flight requests to finish before exit
exec uvicorn main:app \
  --host 0.0.0.0 \
  --port "${PORT}" \
  --workers "${WEB_CONCURRENCY}" \
  --proxy-headers \
  --forwarded-allow-ips "${FORWARDED_ALLOW_IPS}" \
  --log-level "${LOG_LEVEL}" \
  --no-access-log \
  --timeout-graceful-shutdown 30
