#!/usr/bin/env bash
# Generate API documentation from SPARK specs using gnatdoc.
# JS-community analogue: `typedoc` / `jsdoc`.
#
# Output: ./docs/index.html (and supporting files)
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

export PATH="$HOME/.alire/bin:$PATH"

if ! command -v gnatdoc >/dev/null 2>&1; then
  echo "gnatdoc not found on PATH." >&2
  echo "Install with: alr install gnatdoc_bin" >&2
  exit 127
fi

rm -rf docs
mkdir -p docs

exec alr -n exec -- gnatdoc \
  -P hadawallet.gpr \
  -O docs \
  --backend html \
  --generate public \
  "$@"
