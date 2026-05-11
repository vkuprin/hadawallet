#!/usr/bin/env bash
# test.sh — build and run the hadawallet test suite.
#
# Exit code = number of vector failures (0 = all green).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Building hadawallet (main library)"
alr build

echo "==> Building test driver"
alr exec -- gprbuild -P tests/tests.gpr -q

echo "==> Running tests"
./tests/bin/hadawallet-tests
