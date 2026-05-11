# hadawallet

 every other hardware wallet asks you to trust the vendor's process; this one ships machine-checkable artifact that says the worst-case bad thing can't happen

> Formally verified Bitcoin hardware wallet firmware in SPARK/Ada.

**Status**: v0.1-dev — module skeleton with isolated signing API. Build + level-1 SPARK proof passes in CI.

**Roadmap**:

| Week | Milestone |
|---|---|
| 1 | Skeleton + module specs + CI baseline |
| 2 | Pure-SPARK SHA-256 / HMAC-SHA512, BIP32/39/44 derivation, flow contracts on `Signing` |
| 3 | PSBT (BIP174) parsing, libsecp256k1 binding, bech32 addresses, end-to-end signing |
| 4 | bitcoind regtest validation, README polish, **HN launch** |

## The claim

The headline guarantee is **"the private key never leaves the signing module"**, enforced
by SPARK flow analysis, not by code review or testing.

In plain English: the rest of the firmware — the I/O code that talks to the outside
world — has no path to read private key bytes, by construction. SPARK's static flow
analyzer proves this at every call site. If a future change ever introduces such a
path, the build fails.

This is a strong claim, but a narrow one — see [`proofs/README.md`](proofs/README.md)
for the precise proof boundary.

## Quickstart

```bash
# Install Alire (https://alire.ada.dev/), then:
alr build
./bin/hadawallet      # v0.1 smoke test
```

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│  Comm (stdin/stdout I/O loop)              [boundary]        │
│   ↓ psbt_bytes                ↑ signature_bytes              │
├──────────────────────────────────────────────────────────────┤
│  Transaction (PSBT parse + serialize)      [SPARK Silver]    │
│   ↓ tx_digest, sighash                                       │
├──────────────────────────────────────────────────────────────┤
│  Address (bech32 encode)                   [SPARK Gold]      │
├──────────────────────────────────────────────────────────────┤
│  Key_Derivation (BIP32/39/44 + HMAC-SHA512) [SPARK Gold]     │
│   ↓ derived_privkey  (never crosses module boundary)         │
├──────────────────────────────────────────────────────────────┤
│  Signing (secp256k1 ECDSA)                 [SPARK Gold+]     │
│   ←  privkey, digest                                         │
│   →  signature_bytes  (no privkey output by contract)        │
└──────────────────────────────────────────────────────────────┘
```

## Scope

**In v0.1–v0.2**: BTC only, secp256k1, P2WPKH segwit v0, bech32, PSBT (BIP174),
stdin/stdout PSBT I/O, native binary (QEMU-equivalent), STM32 Nucleo-F4 conditional
on launch traction.

**Not in v0.1–v0.2**: altcoins, multisig, taproot, USB HID, BLE, GUI, secure boot,
side-channel hardening, pure-SPARK secp256k1.

## License

AGPL-3.0-or-later for the open-source release — see [LICENSE](LICENSE).

Commercial licensing is available for OEMs and product integrations
that cannot meet AGPL source-disclosure obligations. Contact the
maintainer (see `alire.toml`) to discuss terms.
