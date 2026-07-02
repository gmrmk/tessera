# dle-govern - agent-governance & safety webhook server.
# Build:  docker build -t dle-govern reference-impl
# Run:    docker run -p 8765:8765 -v dle-data:/data -e DLE_GOV_TOKEN=... dle-govern
FROM python:3.12-slim
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# The SQLite file IS the tamper-evident audit trail - persist it on a volume.
ENV DLE_GOV_DB=/data/governance.db
VOLUME ["/data"]

# Bind on all interfaces inside the container; map the port at `docker run`.
ENV DLE_GOV_HOST=0.0.0.0 DLE_GOV_PORT=8765
EXPOSE 8765

# Set DLE_GOV_TOKEN to require an X-DLE-Token header (strongly recommended).
# Terminate TLS in front of this (reverse proxy / load balancer).
CMD ["python", "-m", "dual_log_engine.governance.server"]
