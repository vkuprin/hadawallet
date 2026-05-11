## Summary

<!-- 1-3 sentences: what does this PR do and why? -->

## Scope check

- [ ] This change is in-scope per `CLAUDE.md` ("Scope discipline").
- [ ] If out-of-scope, I opened an issue first and got a maintainer 👍.

## Architecture invariants

- [ ] No public API of `Signing` returns private-key bytes.
- [ ] No new module imports key buffers other than `Signing`.
- [ ] No new I/O surface added (`Comm` remains the only boundary).
- [ ] Only `Signing` talks to `libsecp256k1` (if applicable).

## Verification

- [ ] `./scripts/lint.sh` is green.
- [ ] `alr build` is green.
- [ ] `alr exec -- gnatprove -P hadawallet.gpr --level=1 --report=fail` is green.
- [ ] If contracts changed, I ran `--level=4 --report=all` and pasted the
      diff in proof results below.

## Proof results (if applicable)

<!-- Paste the `gnatprove` summary table here so reviewers can see
     which checks moved from unproved → proved. -->

## Related

<!-- Closes #issue, references #issue, links to RFC, etc. -->
