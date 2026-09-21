#!/usr/bin/env bash
#
# Manual test script for the OIDC Session Management feature.
#
# Runs lint/format checks, the new OIDC Session Management unit tests and
# the related existing test modules. Requires the test dependencies to be
# installed, e.g.:
#
#     pip install -e ".[test]"
#
# Usage:
#     ./test.sh            # run everything
#     ./test.sh -k sid     # pass extra args through to pytest

set -euo pipefail

cd "$(dirname "$0")"

export DJANGO_SETTINGS_MODULE=tests.settings
export PYTHONPATH=.

echo "==> ruff lint"
ruff check oauth2_provider/ tests/

echo "==> ruff format check"
ruff format --check oauth2_provider/ tests/

echo "==> migration check"
python -c "
import django
django.setup()
from django.core.management import call_command
call_command('makemigrations', 'oauth2_provider', check=True, dry_run=True, verbosity=1)
"

echo "==> OIDC Session Management unit tests"
pytest -p no:cacheprovider --no-cov tests/test_oidc_session_management.py -v "$@"

echo "==> related existing tests (OIDC views, models, cleartokens command)"
pytest -p no:cacheprovider --no-cov \
    tests/test_oidc_views.py \
    tests/test_models.py \
    tests/test_commands.py \
    "$@"

echo "==> all checks passed"
