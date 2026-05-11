# MCP Tooling Notes for hadawallet

The project's `CLAUDE.md` enforces an MCP-first policy. Quick map for this codebase:

## Serena — primary code intelligence

- Language identifier: `ada` (set in `.serena/project.yml` → `languages: [ada]`).
  Backed by AdaCore's Ada Language Server (ALS), auto-downloaded by Serena.
- Symbolic tools (`get_symbols_overview`, `find_symbol`, `find_referencing_symbols`,
  `replace_symbol_body`) work on `.ads`/`.adb` files once the `ada` language is
  active.
- `search_for_pattern` is LSP-independent — use it for fast project-wide regex
  searches even if the ALS isn't running.
- **Restart caveat:** the `languages` config is read at MCP server startup.
  Changing it requires restarting Serena (e.g., restart Claude Code / Cursor /
  the Serena MCP server itself) before symbolic tools start working.

## ACI — DISABLED for this project

ACI's tree-sitter pipeline does not yet support Ada/SPARK, so semantic
search would return no useful chunks. Do NOT call `mcp__aci__*` tools here.
Revisit if/when ACI ships an Ada grammar.

## Context7 — library docs

Use `resolve-library-id` + `query-docs` when researching:
- libsecp256k1 (when binding it in week 3)
- bitcoind RPC / regtest (week 4 E2E)
- any future native deps

## Sequential Thinking — multi-step planning

Use for: choosing between approaches, planning a multi-file refactor,
debugging a non-obvious proof failure, evaluating trade-offs.

## Fallback policy

Built-in Read/Edit/Grep/Glob are fallbacks. Use them when:
- A specific file path is known and you just need its bytes.
- The MCP tool errored or is unavailable.
- The change is trivially small (one-line edit).

Otherwise: Serena first, every time.
