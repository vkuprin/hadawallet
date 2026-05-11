#!/usr/bin/env bash
# Apply gnatformat to all Ada sources in the project.
# JS-community analogue: `prettier --write .`
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

export PATH="$HOME/.alire/bin:$PATH"

if ! command -v gnatformat >/dev/null 2>&1; then
  echo "gnatformat not found on PATH." >&2
  echo "Install with: alr install gnatformat" >&2
  exit 127
fi

exec alr -n exec -- gnatformat -P hadawallet.gpr --charset utf-8 "$@"
