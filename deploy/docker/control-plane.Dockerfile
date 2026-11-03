# syntax=docker/dockerfile:1.7

FROM node:22-bookworm-slim AS web-builder
WORKDIR /workspace
RUN npm install -g pnpm@9.15.9
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY packages/ts-client ./packages/ts-client
COPY apps/web ./apps/web
COPY contracts/openapi ./contracts/openapi
RUN pnpm install --frozen-lockfile && pnpm run quickstart:web

FROM python:3.12-slim-bookworm AS runtime
LABEL org.opencontainers.image.title="Red2PR Control Plane" \
      org.opencontainers.image.description="Red2PR self-hosted FastAPI control plane and Meta Astryx web console (Z1/Z2)" \
      org.opencontainers.image.source="https://github.com/nguywnben/red2pr" \
      org.opencontainers.image.url="https://github.com/nguywnben/red2pr" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN groupadd --gid 10001 red2pr \
    && useradd --uid 10001 --gid 10001 --home-dir /tmp --shell /usr/sbin/nologin --no-create-home red2pr

WORKDIR /app
COPY LICENSE README.md ./
COPY packages/py-contracts ./packages/py-contracts
COPY apps/control-plane ./apps/control-plane
COPY apps/cli ./apps/cli
COPY --from=web-builder /workspace/apps/web/dist ./apps/web/dist

RUN python -m venv /app/.venv \
    && /app/.venv/bin/pip install --no-cache-dir --upgrade pip "hatchling>=1.25.0" \
    && /app/.venv/bin/pip install --no-cache-dir --no-build-isolation \
        -e ./packages/py-contracts \
        -e ./apps/control-plane \
        -e ./apps/cli \
    && chmod -R a+rX /app

ENV PATH="/app/.venv/bin:${PATH}" \
    HOME="/tmp" \
    RED2PR_DATA_DIR="/tmp/red2pr-data" \
    RED2PR_WEB_DIST_DIR="/app/apps/web/dist" \
    RED2PR_BIND_HOST="0.0.0.0" \
    RED2PR_HTTP_PORT="8080" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONUNBUFFERED="1"

EXPOSE 8080 8443
USER 10001:10001
ENTRYPOINT ["red2pr-control"]
