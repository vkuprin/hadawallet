# hadawallet — project conventions

## CRITICAL: MCP-First Tool Usage

**ALWAYS use MCP tools before falling back to built-in tools. This is mandatory, not optional.**

- **Discovery/exploration** → Serena `search_for_pattern` FIRST. Do NOT use Grep/Glob to explore unfamiliar code. (ACI is disabled here — no Ada/SPARK tree-sitter support yet.)
- **Understanding symbols** → Serena `find_symbol`/`get_symbols_overview` FIRST. Do NOT use Read to scan entire files.
- **Finding references** → Serena `find_referencing_symbols` FIRST. Do NOT grep for function names.
- **Editing code** → Serena `replace_symbol_body` for whole symbols. Only use Edit for small inline changes.
- **Library docs** → Context7 FIRST. Do NOT web search for API references.

Built-in tools (Grep, Glob, Read, Edit) are **fallbacks only** — use them when MCP tools are unavailable, return errors, or when the task is trivially simple (e.g., reading a known file path the user gave you).

## MCP Servers & Plugins

### Serena (Primary Code Intelligence)

- **Understanding code**: Use `get_symbols_overview` to explore files, `find_symbol` with `include_body=True` to read specific symbols
- **Finding code**: Use `search_for_pattern` for regex search, `find_symbol` with `substring_matching=True` for fuzzy symbol lookup
- **References**: Use `find_referencing_symbols` to trace usage across the codebase
- **Editing**: Use `replace_symbol_body`, `rename_symbol`, `insert_after_symbol` for precise refactors
- **Memory**: Use Serena memories to persist project context between conversations
- Prefer Serena's symbolic tools over raw file reads and grep — they understand code structure

### ACI — disabled for this project

ACI's tree-sitter pipeline does not yet support Ada/SPARK, so semantic search would
return no useful chunks for this codebase. Do NOT call `mcp__aci__*` tools here —
use Serena (`search_for_pattern`, `find_symbol`) for all discovery and navigation.
Revisit if/when ACI ships an Ada grammar.

### Context7

- Use `resolve-library-id` + `query-docs` to fetch up-to-date docs for any dependency
- Prefer over web search when you need API references or usage examples

### Sequential Thinking

- **Purpose**: Structured multi-step reasoning for complex decisions and planning
- **When to use**: Architecture decisions, multi-file refactors, debugging complex issues, evaluating trade-offs
- **How it works**: Breaks problems into numbered thought steps, can revise and branch reasoning
- Use before jumping into code when the task involves: choosing between approaches, understanding side effects of a change, planning a multi-step feature, or debugging something non-obvious
- Especially useful in plan mode — think through the approach first, then execute

### Tool Selection Priority

1. **"Where is X?" / understanding code** → Serena `find_symbol`, `get_symbols_overview`, `search_for_pattern`
2. **Broad discovery / "how does X work?"** → Serena `search_for_pattern` with broad regex (ACI is disabled for Ada/SPARK)
3. **Symbol lookup / references / renaming** → Serena `find_referencing_symbols`, `rename_symbol`
4. **Exact text search** → Serena `search_for_pattern` (preferred) or built-in Grep as fallback
5. **Complex decisions / planning / debugging** → Sequential Thinking
6. **Library docs** → Context7
7. **Quick file reads/edits** → built-in Read/Edit tools

### Typical Workflow

1. **Discover** — Serena: `search_for_pattern` with broad regex, or `get_symbols_overview` on a likely file
2. **Think** — Sequential Thinking: plan the approach, evaluate trade-offs, identify affected areas
3. **Navigate** — Serena: `find_symbol` → `find_referencing_symbols` → understand the dependency chain
4. **Learn** — Context7: fetch latest docs for any libraries involved
5. **Edit** — Serena: `replace_symbol_body`, `insert_after_symbol` for precise changes
6. **Verify** — `alr build` + `gnatprove --level=1 --report=fail` (see Build section)

## What this is

Formally verified Bitcoin hardware wallet firmware in SPARK/Ada. Headline claim:
"the private key never leaves the signing module" via SPARK flow analysis.

## Build / prove / test / lint

```bash
alr build                                                       # GNAT build
alr exec -- gnatprove -P hadawallet.gpr --level=1 --report=fail # baseline (v0.1)
alr exec -- gnatprove -P hadawallet.gpr --level=4 --report=all  # full proofs (v0.2)
alr test                                                         # unit tests (week 2+)
./scripts/demo.sh                                                # E2E with bitcoind regtest (week 4)

./scripts/fmt.sh                                                 # apply gnatformat (Prettier equivalent)
./scripts/lint.sh                                                # format check + -gnatyy -gnatwa -gnatwe (ESLint equivalent)
./scripts/install-hooks.sh                                       # one-time: wire .githooks/pre-commit
```

## Formatting & linting

- **Formatter**: `gnatformat` (AdaCore's opinionated Prettier-style formatter).
  Installed via `alr install gnatformat`; same pattern as `gnatprove`.
- **Linter**: GNAT built-in `-gnatyy` (style) + `-gnatwa -gnatwe` (all warnings,
  as errors) invoked separately from the normal build so dev compilation isn't
  blocked. `gnatcheck` would be the ideal ESLint analogue but isn't in Alire
  yet — revisit when AdaCore ships `lkql-jit` / `gnatcheck` as a crate.
- **Pre-commit**: `./scripts/install-hooks.sh` sets `core.hooksPath=.githooks`;
  the hook only fires when `.adb` / `.ads` / `.gpr` / `.toml` files are staged.
- **CI**: lint runs before build/prove in `.github/workflows/ci.yml`.

## Architecture invariants — DO NOT BREAK

1. **`Signing` is the only module that holds private-key bytes.** No public API of
   `Signing` returns key bytes. No other module imports key buffers.
2. **`Comm` is the only boundary module.** Stdin/stdout I/O lives there only.
   Other modules MUST NOT import `Ada.Text_IO`, `Ada.Streams.Stream_IO`, or any
   network/filesystem package directly.
3. **`Signing` is the ONLY module that talks to libsecp256k1** (when bound in week 3).
   The C-binding contamination is contained.

## Scope discipline (v0.1–v0.2)

- **In**: BTC, secp256k1, P2WPKH, bech32, PSBT, stdin/stdout, native binary, optional STM32.
- **Out**: altcoins, multisig, taproot, USB, BLE, GUI, secure boot, hardware hardening.

If asked to add anything in the "Out" list, push back and reference the launch strategy
in project memory: speed-to-public-artifact is the strategic priority through week 4.

## SPARK targets per module

| Module           | Target                            |
|------------------|-----------------------------------|
| `Signing`        | Platinum (functional correctness) |
| `Key_Derivation` | Gold                              |
| `Hashing`        | Gold                              |
| `Address`        | Gold                              |
| `Transaction`    | Silver (no runtime errors)        |
| `Comm`           | Silver                            |

Bodies currently use `SPARK_Mode => Off`; flip to `On` per procedure as real
implementations replace stubs.

## secp256k1 strategy

- **v0.1 (now)**: stubbed. No real signing yet.
- **v0.2 (week 3)**: C binding to libsecp256k1 (Bitcoin Core ref impl). Curve math
  NOT proven; flow claim still holds because `Signing` passes key to C, gets sig back,
  no other SPARK module sees the key.
- **v0.3+ (post-launch)**: pure-SPARK secp256k1.

## Don't

- Don't claim "math-proven secp256k1" or "fully verified curve math" before pure-SPARK
  port lands. Community will catch the overclaim and credibility tanks.
- Don't add a second I/O surface (USB / BLE) — single-boundary architecture is what
  makes the flow proof meaningful.
- Don't broaden PSBT support beyond P2WPKH single-sig before v0.3 — keep proof envelope tight.

## Tooling

`alr` 2.1.0, `gnat_native` 15.1.2, `gprbuild` 25.0.1, and `gnatprove` 15.1.0
are installed locally (macOS arm64). Local `alr build` and
`gnatprove --level=1 --report=fail` are green as of 2026-05-08.

`gnatprove` lives at `~/.alire/bin/gnatprove` and is NOT on `alr exec`'s PATH
by default — prefix runs with `PATH="$HOME/.alire/bin:$PATH"`:

```bash
PATH="$HOME/.alire/bin:$PATH" alr exec -- gnatprove -P hadawallet.gpr --level=1 --report=fail
```

CI (`.github/workflows/ci.yml`, `alire-project/setup-alire@v3`) is still
authoritative for cross-platform validation.
