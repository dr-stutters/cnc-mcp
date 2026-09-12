.PHONY: install test lint fmt run inspect docker-build

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

docker-build:
	docker build -t cnc-mcp .
