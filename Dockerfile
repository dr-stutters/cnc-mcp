# stdio MCP server image. Run with:
#   docker run -i --rm --env-file .env cnc-mcp
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

# Install dependencies first for layer caching (lockfile optional in template)
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-install-project --no-dev

COPY . .
RUN uv sync --no-dev

ENTRYPOINT ["uv", "run", "--no-dev", "cnc-mcp"]
