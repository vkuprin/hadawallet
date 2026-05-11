# Contributing to hadawallet

Thanks for your interest. `hadawallet` is a pre-release SPARK/Ada Bitcoin
hardware wallet firmware aiming for formal-verification guarantees. The
contribution surface is small on purpose during v0.1–v0.2.

## Before you start

1. Read **`CLAUDE.md`** in the repo root. It documents:
   - The locked v0.1–v0.2 scope.
   - The non-negotiable architecture invariants (key isolation,
     single I/O boundary, `Signing` as the only secp256k1 caller).
   - The build / prove / lint commands.
2. Skim **`SECURITY.md`**. Anything that affects the key-isolation
   invariant goes through that channel, not a public PR.

## Local setup

```bash
# Toolchain (one-time):
alr install gnatprove gnatformat gnatdoc_bin gnatcov_bin

# Build, prove, lint:
alr build
alr exec -- gnatprove -P hadawallet.gpr --level=1 --report=fail
./scripts/lint.sh
./scripts/fmt.sh          # apply formatter

# Wire up the pre-commit hook (one-time):
./scripts/install-hooks.sh
```

Optional tools (`shellcheck`, `actionlint`, Node.js for `markdownlint`)
will be skipped by the lint script if not installed, but CI runs all
of them — install locally if you want a green CI on the first push.

## What we accept

We're prioritising:

- Proof improvements: tightening contracts on existing specs,
  raising a module from Bronze → Silver → Gold (target levels are
  in `CLAUDE.md`).
- Test coverage for code already in the v0.1 skeleton.
- Documentation that improves the formal-verification story for
  external readers (especially the architecture diagram and
  `Signing` contracts).
- CI hardening (reproducible builds, SBOM, signed releases).

We're **not** accepting in v0.1–v0.2:

- New coins or signature schemes (BTC + secp256k1 + P2WPKH only).
- Multisig, taproot, SLIP-39, etc.
- USB / BLE / GUI surfaces (single-boundary architecture is what
  makes the key-isolation proof meaningful).
- A second I/O surface of any kind.

Read the "Scope discipline" section of `CLAUDE.md` before opening
an issue or PR for something that might be out of scope.

## How to propose a change

1. **Open an issue first** for anything larger than a typo or a
   single proof-tightening. We may close PRs that bypass discussion
   on architecture changes.
2. Fork, branch from `main`, keep commits focused.
3. Use [Conventional Commits](https://www.conventionalcommits.org/)
   in commit messages: `feat:`, `fix:`, `chore:`, `docs:`,
   `proof:` (for SPARK changes), `ci:`, `refactor:`, `test:`.
4. Ensure `./scripts/lint.sh` and the SPARK proof are green before
   opening the PR. The pre-commit hook will catch most lint drift
   if you ran `./scripts/install-hooks.sh`.
5. Sign your commits if you can (`git commit -S`). We will require
   signed commits on protected branches from v0.2 onwards.

## Code style

- Formatting is enforced by `gnatformat` (run `./scripts/fmt.sh`).
  Don't argue with the formatter — file an upstream issue if you
  think a choice is wrong.
- Style/warning lint is enforced by `gprbuild -gnatyy -gnatwa
  -gnatwe`. Suppressions need a comment explaining why (see the
  `Stored_Key` example in `src/signing.adb`).
- Comments answer "why", not "what". The code already says "what".

## Licensing

By contributing you agree your contribution is licensed under the
repository's `AGPL-3.0-or-later` license. Commercial dual-licensing
is administered by the maintainer; significant contributors will be
asked to sign a CLA when that program goes live.
