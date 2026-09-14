# stdio MCP server image. Credentials are never baked in — pass them at run time:
#   docker run -i --rm --env-file .env ghcr.io/dr-stutters/cnc-mcp:latest
# (or `make docker-build` for a local `cnc-mcp` image).
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

LABEL org.opencontainers.image.title="cnc-mcp" \
      org.opencontainers.image.description="MCP server for Cisco Crosswork Network Controller" \
      org.opencontainers.image.source="https://github.com/dr-stutters/cnc-mcp" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install dependencies first for layer caching (lockfile optional in template)
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-install-project --no-dev

# Copies the build context. .dockerignore keeps .env / .env.* (except
# .env.example), the private smoke plan, .venv, tests, scripts, .git and
# tooling caches out of the context, so they cannot land in the image — keep
# it that way when adding files to the repository.
COPY . .
RUN uv sync --no-dev

ENTRYPOINT ["uv", "run", "--no-dev", "cnc-mcp"]
