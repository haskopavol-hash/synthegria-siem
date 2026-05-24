# ─────────────────────────────────────────────────────────────────────────────
# Synthegria SIEM — Log Ingestion API
# Production Dockerfile
#
# Build:  docker build -t synthegria-api .
# Run:    docker run -e STRIPE_SECRET_KEY=sk_... -p 8000:8000 synthegria-api
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

# ── System setup ─────────────────────────────────────────────────────────────
# Create a non-root user and group for the application process.
RUN groupadd --system appgroup && \
    useradd --system --gid appgroup --home /app --shell /sbin/nologin appuser

# ── Install uv (fast Python package manager) ─────────────────────────────────
# Pin the version so the build is reproducible.
RUN pip install --no-cache-dir uv==0.7.6

# ── Python dependencies ───────────────────────────────────────────────────────
# Copy lock files first so Docker cache is reused on code-only changes.
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# ── Application source ────────────────────────────────────────────────────────
COPY main.py ./
COPY utils/  ./utils/

# ── Production entrypoint ─────────────────────────────────────────────────────
COPY scripts/start.sh /start.sh
RUN chmod 755 /start.sh

# ── Runtime environment ───────────────────────────────────────────────────────
# Activate the uv virtual-env by prepending its bin directory to PATH.
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ── Drop privileges ───────────────────────────────────────────────────────────
RUN chown -R appuser:appgroup /app
USER appuser

# ── Networking ────────────────────────────────────────────────────────────────
# Expose the default port.  Override at runtime with -e PORT=<n>.
EXPOSE 8000

# ── Container liveness probe ──────────────────────────────────────────────────
# Mirrors the API's own /healthz endpoint.
# --start-period gives uvicorn time to initialise before checks begin.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c \
      "import urllib.request, os; \
       urllib.request.urlopen( \
         'http://localhost:' + os.environ.get('PORT', '8000') + '/healthz' \
       )"

# ── Start ─────────────────────────────────────────────────────────────────────
ENTRYPOINT ["/start.sh"]
