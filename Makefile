.PHONY: install test lint fmt run inspect cli build docker-build rbac rbac-fetch rbac-check

# Arguments for `make cli`, e.g.:
#   make cli ARGS="list"
#   make cli ARGS="schema cnc_list_devices"
#   make cli ARGS="call cnc_list_devices '{\"page_size\": 5}'"
#   make cli ARGS="list --writes"
ARGS ?= list

install:
	uv sync

test:
	uv run pytest -q

lint:
	uv run ruff check src tests

fmt:
	uv run ruff format src tests
	uv run ruff check --fix src tests

run:
	uv run cnc-mcp

inspect:
	npx @modelcontextprotocol/inspector uv run cnc-mcp

# Drive the server over the real MCP stdio protocol (scripts/mcp_cli.py).
cli:
	uv run python scripts/mcp_cli.py $(ARGS)

# RBAC map (src/cnc_mcp/data/rbac_map.json), docs/RBAC.md and the docs/rbac/*.role.json
# bodies, regenerated from the tool source (scripts/rbac_map.py). `rbac` works offline
# from the catalogue embedded in the committed map; `rbac-fetch` re-reads the gateway's
# secured-API catalogue from the live instance in .env; `rbac-check` exits 1 when the
# committed files are stale (for CI).
rbac:
	uv run python scripts/rbac_map.py --offline

rbac-fetch:
	uv run python scripts/rbac_map.py

rbac-check:
	uv run python scripts/rbac_map.py --check

# Wheel + sdist into dist/.
build:
	uv build

docker-build:
	docker build -t cnc-mcp .
