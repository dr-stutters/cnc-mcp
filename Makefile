.PHONY: install test lint fmt run inspect cli build docker-build

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

# Wheel + sdist into dist/.
build:
	uv build

docker-build:
	docker build -t cnc-mcp .
