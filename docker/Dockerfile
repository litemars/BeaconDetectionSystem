# ──────────────────────────────────────────────────────────────────────────────
# Control Plane — Beacon Detection System
# ──────────────────────────────────────────────────────────────────────────────
#
# This image runs the pure-Python control plane (HTTP API, detector, analyzer,
# alert manager).  It does NOT require eBPF or elevated privileges.
#
# The DATA PLANE (data_plane/collector.py) must run on the host or in a
# privileged container with host networking and eBPF access — see the
# deployment notes in docker-compose.yml.
# ──────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

LABEL maintainer="beacon-detect"
LABEL description="Beacon Detection System — Control Plane"

# ── System dependencies ────────────────────────────────────────────────────
# gcc is required so that numpy/scipy can build any C extensions if pre-built
# wheels are not available for the target platform.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python dependencies ────────────────────────────────────────────────────
# Copy only requirements first to exploit Docker layer cache.
COPY requirements.txt .

# bcc is a kernel-space library and not needed in the control plane image.
# Install the remaining packages; ignore the bcc line which will fail silently.
RUN grep -v '^bcc' requirements.txt > /tmp/cp_requirements.txt \
    && pip install --no-cache-dir -r /tmp/cp_requirements.txt

# ── Application code ───────────────────────────────────────────────────────
COPY control_plane/ ./control_plane/
COPY config/        ./config/

# ── Runtime ───────────────────────────────────────────────────────────────
# Create the log directory used by the default file-alert handler.
RUN mkdir -p /var/log/beacon-detect

# Expose the control plane API port.
EXPOSE 9090

# Health check: poll /api/v1/health every 30 s.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:9090/api/v1/health | grep -q '"status": "healthy"' \
    || exit 1

# Default config path (override with -c or a bind-mount).
ENV BEACON_CONFIG=/app/config/config.yaml

ENTRYPOINT ["python3", "-m", "control_plane.server"]
CMD ["-c", "/app/config/config.yaml"]
