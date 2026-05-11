#!/usr/bin/env bash
# Wire up the in-repo .githooks directory.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true

echo "OK: core.hooksPath -> .githooks"
echo "    pre-commit will run ./scripts/lint.sh on Ada/.gpr/.toml changes."
