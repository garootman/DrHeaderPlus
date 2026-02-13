.PHONY: test lint sast typecheck format format-check check

test:
	uv run pytest --cov=drheader --cov-fail-under=80

lint:
	uv run ruff check .

sast:
	uv run ruff check ./drheader --select S

typecheck:
	uv run ty check

format:
	uv run ruff format .

format-check:
	uv run ruff format --check .

check: lint sast format-check typecheck test
