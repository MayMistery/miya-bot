#!/usr/bin/env bash
set -euo pipefail

# Ensure uv is available
if ! command -v uv &>/dev/null; then
    echo "Error: uv not found. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Sync deps (installs if needed)
uv sync --extra dev

CMD="${1:-help}"
shift 2>/dev/null || true

BRANCH="${MIYA_BRANCH:-main}"

case "$CMD" in
    test)      uv run pytest -v "$@" ;;
    test-unit) uv run pytest tests/unit -v "$@" ;;
    test-int)  uv run pytest tests/integration -v "$@" ;;
    test-e2e)  uv run pytest tests/e2e -v "$@" ;;
    test-cov)  uv run pytest --cov=miya --cov-report=term-missing "$@" ;;
    lint)      uv run ruff check miya tests "$@" ;;
    fmt)       uv run ruff format miya tests "$@" ;;
    run)       uv run miya "$@" ;;
    update)
        echo "[miya] Pulling latest from origin/$BRANCH..."
        git fetch origin "$BRANCH"
        git reset --hard "origin/$BRANCH"
        uv sync --extra dev
        echo "[miya] Updated to $(git rev-parse --short HEAD)"
        ;;
    help)
        echo "Usage: ./run.sh <command> [args...]"
        echo ""
        echo "Commands:"
        echo "  test       Run all tests"
        echo "  test-unit  Run unit tests"
        echo "  test-int   Run integration tests"
        echo "  test-e2e   Run e2e tests"
        echo "  test-cov   Run tests with coverage"
        echo "  lint       Run ruff linter"
        echo "  fmt        Auto-format code"
        echo "  run        Run miya CLI"
        echo "  update     Pull latest from GitHub + re-sync deps"
        ;;
    *)
        echo "Unknown command: $CMD"
        exit 1
        ;;
esac
