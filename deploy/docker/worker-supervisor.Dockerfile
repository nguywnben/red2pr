# syntax=docker/dockerfile:1.7

FROM python:3.12-slim-bookworm AS runtime
LABEL org.opencontainers.image.title="Red2PR Worker Supervisor" \
      org.opencontainers.image.description="Red2PR isolated Z3 sandbox worker supervisor (zero control-plane imports)" \
      org.opencontainers.image.source="https://github.com/nguywnben/red2pr" \
      org.opencontainers.image.url="https://github.com/nguywnben/red2pr" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN groupadd --gid 10001 red2pr \
    && useradd --uid 10001 --gid 10001 --home-dir /tmp --shell /usr/sbin/nologin --no-create-home red2pr

WORKDIR /app
COPY LICENSE README.md ./
COPY packages/py-contracts ./packages/py-contracts
COPY apps/worker-supervisor ./apps/worker-supervisor

RUN python -m venv /app/.venv \
    && /app/.venv/bin/pip install --no-cache-dir --upgrade pip "hatchling>=1.25.0" "editables>=0.5" \
    && /app/.venv/bin/pip install --no-cache-dir --no-build-isolation \
        -e ./packages/py-contracts \
        -e ./apps/worker-supervisor \
    && chmod -R a+rX /app

ENV PATH="/app/.venv/bin:${PATH}" \
    HOME="/tmp" \
    RED2PR_WORKER_STATE_DIR="/tmp/red2pr-worker/state" \
    RED2PR_WORKER_SCRATCH_DIR="/tmp/red2pr-worker/scratch" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONUNBUFFERED="1"

USER 10001:10001
ENTRYPOINT ["red2pr-worker"]
