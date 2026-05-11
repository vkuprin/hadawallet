# Suggested Commands

System: **Darwin (macOS arm64)**, shell: zsh. Most commands also work on Linux CI.

## Build / prove / run

```bash
# Build with Alire (compiles to bin/hadawallet)
alr build

# Baseline SPARK proof — currently passing at level=1 (no runtime errors)
PATH="$HOME/.alire/bin:$PATH" alr exec -- gnatprove -P hadawallet.gpr --level=1 --report=fail

# Full proof (week 4 target) — level=4 with all checks
PATH="$HOME/.alire/bin:$PATH" alr exec -- gnatprove -P hadawallet.gpr --level=4 --report=all

# Run the smoke-test binary
./bin/hadawallet

# Tests — not yet wired up (planned week 2+)
alr test

# E2E demo with bitcoind regtest — not yet present (planned week 4)
./scripts/demo.sh
```

**PATH gotcha:** `gnatprove` lives at `~/.alire/bin/gnatprove` but is NOT on
`alr exec`'s default PATH. Always prefix prove runs with
`PATH="$HOME/.alire/bin:$PATH"`. CI handles this by appending
`$HOME/.alire/bin` to `$GITHUB_PATH`.

## Toolchain locations

- `alr` 2.1.0 → `~/.local/bin/alr`
- `gnat_native` 15.1.2, `gprbuild` 25.0.1 (via Alire toolchain)
- `gnatprove` 15.1.0 → `~/.alire/bin/gnatprove`

## Git / GitHub

```bash
git status                       # working-tree status
git log --oneline -20            # recent history
gh pr create                     # create PR (use HEREDOC for body)
gh pr view                       # view current PR
```

## Darwin-specific utilities

Standard BSD-flavor coreutils. Common variations to remember:
- `find . -type f` (GNU `-printf` is NOT available; use `-exec`)
- `sed -i ''` requires an empty backup arg on macOS (vs. `sed -i` on GNU)
- `ls -la`, `grep -R`, `head`, `tail` work as expected
- Prefer `rg` (ripgrep) for fast content search if installed

## Tooling discipline (from CLAUDE.md)

For code discovery/edits, **MCP servers come first**:
- Serena `search_for_pattern` / `find_symbol` / `replace_symbol_body` — primary code intelligence.
  - Ada/SPARK IS supported (the user contributed a merged PR adding `Language.ADA` via
    AdaCore's Ada Language Server). Project config: `.serena/project.yml` → `languages: [ada]`.
  - The `languages` setting is read at MCP server startup; if you change it, restart Serena
    for symbolic tools to start working on `.ads`/`.adb` files.
- ACI — disabled (no Ada tree-sitter grammar yet).
- Context7 — library docs.
- Sequential Thinking — multi-step planning.
