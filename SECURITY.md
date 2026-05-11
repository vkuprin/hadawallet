# Security Policy

`hadawallet` is a pre-release Bitcoin hardware wallet firmware.
**Do not use it to secure real funds yet.** v0.1–v0.2 are skeleton releases
intended for evaluation, formal-verification review, and contribution.

This document explains how to report vulnerabilities and what is in scope.

## Reporting a vulnerability

**Do not open public GitHub issues for security problems.**

Use one of:

1. **GitHub Private Vulnerability Reporting** — preferred.
   Open `Security` → `Advisories` → `Report a vulnerability` on
   <https://github.com/vkuprins/hadawallet>.
2. **Encrypted email** to `vkuprins97@gmail.com` with subject
   `[hadawallet security]`. Request the maintainer's GPG key in the same
   email if you don't already have it; an encrypted reply will follow.

Please include:

- A description of the issue and the impact you believe it has.
- Reproduction steps or a proof-of-concept (PSBT input, key material if
  contrived, expected vs. observed output).
- The commit SHA or release tag you were testing against.
- Whether you would like credit in the advisory.

## Response timeline

| Phase                            | Target                           |
|----------------------------------|----------------------------------|
| Initial acknowledgement          | within 72 hours                  |
| Triage and severity assignment   | within 7 days                    |
| Fix or mitigation                | depends on severity (see below)  |
| Coordinated disclosure           | within 90 days of report         |

Severity guidance for fixes:

- **Critical** (key extraction, remote code execution, signature
  forgery) — patched and released within 14 days.
- **High** (PSBT parser memory safety, address-encoding mismatch) —
  within 30 days.
- **Medium** (denial-of-service, information leak that doesn't
  compromise key material) — within 60 days.
- **Low** — bundled into the next regular release.

## Scope

In scope:

- Anything in `src/` that ships in a release binary.
- The PSBT parser surface (`Transaction`, `Comm`).
- The key-isolation architectural invariant: any path by which a public
  API exposes private-key bytes is a critical finding, even if it
  appears benign.
- SPARK contracts that are claimed in `*.ads` but not actually proven
  (proof-gap reports are welcome).
- The build pipeline (gnatformat / gnatprove / gnatcov configuration)
  if it can be made to silently accept unsafe code.

Out of scope:

- Bugs in `libsecp256k1` itself (report upstream:
  <https://github.com/bitcoin-core/secp256k1>).
- Issues only reproducible against a test private key the reporter
  controls (we use the constant `16#42#` placeholder in smoke tests
  — that is not a real key).
- Hardware side-channels prior to STM32 target landing
  (timing/EM/power analysis on an MCU we don't yet support).
- Social-engineering scenarios that assume an attacker can replace
  the firmware binary out-of-band; flashing-supply-chain hardening
  is a v0.4+ goal.

## What we do not offer (yet)

- **No bug bounty.** This is a pre-release, solo-maintained project.
  We will credit reporters in advisories and release notes unless
  you ask us not to.
- **No legal safe harbor language** beyond "we won't pursue
  good-faith research against the public testnet/regtest demo".

## Verifying the maintainer

The GPG key used to sign releases and security responses is published
in this repository under `keys/maintainer.asc` (added in v0.2). Until
then, fingerprints can be confirmed via direct contact.

## Cryptographic posture

- secp256k1 curve math is provided by the upstream Bitcoin Core
  reference implementation (`libsecp256k1`) in v0.2. The pure-SPARK
  port is a v0.3+ goal — until then, "verified math" claims are not
  accurate and should not appear in security messaging.
- The key-isolation flow contract (`Signing` does not return raw
  private-key bytes through any public API) is enforced by SPARK
  flow analysis, not by encryption or hardware. It assumes the
  attacker cannot read process memory directly.

## Acknowledgements

Reporters credited in advisories (none yet — be the first).
