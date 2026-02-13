.PHONY: test lint sast check

test:
	uv run pytest --cov=drheader --cov-fail-under=80

lint:
	uv run ruff check .

sast:
	uv run ruff check ./drheader --select S

check: lint sast test
