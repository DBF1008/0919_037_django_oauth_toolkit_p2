#!/usr/bin/env bash
#
# test.sh - Run the OIDC Session Management / Front-Channel Logout unit tests.
#
# This script is intended to be invoked manually:
#
#     ./test.sh                      # run the new session-management tests
#     ./test.sh --all                # run the full test suite
#     ./test.sh --lint               # run ruff lint + format checks
#     ./test.sh --migrations         # verify migrations are in sync
#     ./test.sh path/to/test.py      # forward extra args to pytest
#
set -euo pipefail

cd "$(dirname "$0")"

# Handle --help before any interpreter is required.
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n "2,11p" "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

# Pick a Python interpreter that has the project test dependencies available.
PYTHON_BIN="${PYTHON:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
    for candidate in .venv/bin/python python3 python; do
        if command -v "${candidate}" >/dev/null 2>&1 && \
           "${candidate}" -c "import django, pytest, oauthlib, jwcrypto" >/dev/null 2>&1; then
            PYTHON_BIN="${candidate}"
            break
        fi
    done
fi

if [[ -z "${PYTHON_BIN}" ]]; then
    echo "error: no Python with django/pytest/oauthlib/jwcrypto found." >&2
    echo "       create the environment first, e.g. 'uv sync --all-groups'." >&2
    exit 1
fi

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-tests.settings}"

SESSION_TESTS="tests/test_oidc_session_management.py"
RELATED_TESTS=(
    "${SESSION_TESTS}"
    tests/test_oidc_views.py
    tests/test_models.py
    tests/test_commands.py
    tests/test_settings.py
)

mode="session"
if [[ $# -gt 0 ]]; then
    case "$1" in
        --all)
            mode="all"
            shift
            ;;
        --session)
            mode="session"
            shift
            ;;
        --related)
            mode="related"
            shift
            ;;
        --lint)
            mode="lint"
            shift
            ;;
        --migrations)
            mode="migrations"
            shift
            ;;
        *)
            # Everything else is passed straight to pytest.
            mode="custom"
            ;;
    esac
fi

echo "Using Python: $("${PYTHON_BIN}" -c 'import django,sys;print(sys.executable, "Django", django.get_version())')"

case "${mode}" in
    all)
        "${PYTHON_BIN}" -m pytest tests/ -o addopts="" "$@"
        ;;
    related)
        "${PYTHON_BIN}" -m pytest "${RELATED_TESTS[@]}" -o addopts="" "$@"
        ;;
    session)
        "${PYTHON_BIN}" -m pytest "${SESSION_TESTS}" -v -o addopts="" "$@"
        ;;
    custom)
        "${PYTHON_BIN}" -m pytest -o addopts="" "$@"
        ;;
    lint)
        ruff check oauth2_provider tests "${@}"
        ruff format --check oauth2_provider tests
        ;;
    migrations)
        "${PYTHON_BIN}" -m django makemigrations --check --dry-run
        ;;
esac
