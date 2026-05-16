#!/usr/bin/env bash
# Lint the project. Passes:
#   1. gnatformat --check        formatter dry-run    (Prettier `--check`)
#   2. gprbuild -gnatyy -gnatwa -gnatwe   GNAT style + warnings-as-errors
#                                (ESLint-equivalent; swap to gnatcheck when
#                                 AdaCore ships it as an Alire crate)
#   3. shellcheck on scripts/ + .githooks (skipped if not installed)
#   4. actionlint on .github/workflows  (skipped if not installed)
#   5. markdownlint on **/*.md   (via npx, skipped if no node)
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

export PATH="$PATH:$HOME/.alire/bin"

if ! command -v gnat >/dev/null 2>&1; then
  tool_path="$(find "$HOME/.local/share/alire/toolchains" \
    -path '*/bin/gnat' -type f -print -quit 2>/dev/null || true)"
  if [ -n "$tool_path" ]; then
    PATH="$(dirname "$tool_path"):$PATH"
  fi
fi

if command -v alr >/dev/null 2>&1; then
  if ! command -v gprbuild >/dev/null 2>&1; then
    tool_path="$(alr -n exec -- which gprbuild 2>/dev/null || true)"
    if [ -n "$tool_path" ]; then
      PATH="$(dirname "$tool_path"):$PATH"
    fi
  fi
  export PATH
fi

fail=0

echo "==> tool paths"
echo "gnat: $(command -v gnat || echo missing)"
echo "gcc: $(command -v gcc || echo missing)"
echo "gprbuild: $(command -v gprbuild || echo missing)"
echo "gnatformat: $(command -v gnatformat || echo missing)"

echo "==> gnatformat --check"
if command -v gnatformat >/dev/null 2>&1; then
  if ! gnatformat -P hadawallet.gpr --charset utf-8 --check; then
    echo "FAIL: formatting drift. Apply with: ./scripts/fmt.sh" >&2
    fail=1
  fi
else
  echo "FAIL: gnatformat not installed. Run: alr install gnatformat" >&2
  fail=1
fi

echo "==> gprbuild -gnatyy -gnatwa -gnatwe (style + warnings-as-errors)"
if ! gprbuild -P hadawallet.gpr -p -q \
       -cargs:Ada -gnatyy -gnatwa -gnatwe; then
  echo "FAIL: style or warning issues" >&2
  fail=1
fi

echo "==> shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  if ! shellcheck scripts/*.sh .githooks/*; then
    fail=1
  fi
else
  echo "(shellcheck not installed; install with 'brew install shellcheck' to enable)"
fi

echo "==> actionlint"
if command -v actionlint >/dev/null 2>&1; then
  if ! actionlint; then
    fail=1
  fi
else
  echo "(actionlint not installed; install with 'brew install actionlint' to enable)"
fi

echo "==> markdownlint (via npx)"
if command -v npx >/dev/null 2>&1; then
  if ! npx -y --silent markdownlint-cli2 2>&1; then
    echo "FAIL: markdownlint issues" >&2
    fail=1
  fi
else
  echo "(node/npx not installed; install Node.js to enable markdownlint)"
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "OK: lint clean"
