# Changelog

All notable changes to `hadawallet` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-17

First public release as a complete terminal Bitcoin signer. The headline
SPARK proof (`Signing` key-isolation, 22/22 checks at `gnatprove --level=4`)
is unchanged from v0.1; the work in this release is the rest of the wallet
around that proof.

### Added

- **BIP39 mnemonic support.** PBKDF2-HMAC-SHA512 (2048 iterations,
  64-byte output) per RFC 8018, reading the mnemonic from
  `$HADAWALLET_MNEMONIC_FILE` (default `~/.hadawallet/mnemonic.txt`).
  English wordlist + ASCII passphrase only (UTF-8 NFKD normalization
  deferred to v0.3).
- **BIP32 hierarchical deterministic key derivation.** Master key from
  seed (`HMAC-SHA512("Bitcoin seed", seed)`) and CKDpriv for hardened
  and non-hardened paths. Default path BIP84 `m/84'/0'/0'/0/0`,
  overridable via `$HADAWALLET_PATH`.
- **bech32 P2WPKH addresses (BIP173)** for mainnet, testnet, and
  regtest via `hadawallet --address [NET]`.
- **PSBT v0 (BIP174) parse / sighash / serialize.** P2WPKH single-sig
  only, ≤16 inputs/outputs. BIP143 segwit v0 sighash (SIGHASH_ALL
  hard-wired). `partial_sig` roundtrip wired to BIP174 input key 0x02.
- **Dual signing backend.** `BACKEND=c` (default) links Bitcoin Core's
  libsecp256k1 via FFI for production; `BACKEND=ada` uses the in-tree
  pure-SPARK implementation under `src/secp256k1/` (no C dependency).
  Both backends pass `scripts/demo-offline.sh` end-to-end.
- **Pure-SPARK secp256k1 (Phase D complete).**
  - `Secp256k1.Field`: add, sub, mul (8×8 schoolbook), sqr, inv (Fermat)
    over `p = 2^256 − 2^32 − 977`, with 8×U32 limb representation.
  - `Secp256k1.Scalar`: add, sub, mul (with bit-by-bit mod-n reduction),
    inv (Fermat) over the curve order `n`.
  - `Secp256k1.Group`: affine addition / doubling, double-and-add scalar
    multiplication, SEC1 compressed encode/decode (sqrt mod p via Fermat).
  - `Secp256k1.Ecdsa`: RFC 6979 deterministic signing (HMAC-SHA512 nonce),
    `Pubkey_From_Privkey`, `Tweak_Add_Scalar` (BIP32 non-hardened helper).
  - `Secp256k1.Der`: minimal-DER ECDSA signature encoding (BIP66 + SEC1
    §C.5; caller responsible for BIP62 low-s normalization).
- **CLI surface.** `--version`, `--help`/`-h`, `--smoke` (FIPS/RFC/BIP
  vector smoke tests), `--fixture` (emit unsigned demo PSBT),
  `--address [mainnet|testnet|regtest]`, default sign-mode
  (stdin PSBT → stdout signed PSBT).
- **End-to-end demos.** `scripts/demo-offline.sh` (offline; generates
  ephemeral key, signs fixture, verifies BIP174 partial_sig present);
  `scripts/demo.sh` (regtest round-trip against `bitcoind`, soft-skips
  if `bitcoind`/`bitcoin-cli`/`jq` absent).
- **STM32F411 Nucleo scaffolding.** `hadawallet_stm32.gpr` cross-compiles
  a Cortex-M4F firmware with USART2 boot banner and SHA-256 self-test.
  Scaffolding only — not yet validated on real hardware.
- **User-facing documentation.** `docs/usage.md` (mnemonic provisioning,
  signing workflow, mainnet safety checklist); `docs/stm32-quickstart.md`
  (cross-compile guide). README rewritten with a five-minute Quickstart.
- **SPARK proof extensions.** `Signing.Pubkey_From_Privkey` and
  `Signing.Tweak_Add_Scalar` now carry `Global`/`Depends` contracts so
  `Key_Derivation` can call them without violating key isolation.
  Coverage at `gnatprove --level=4` grew from 15/15 (v0.1) to 22/22.
- **`CHANGELOG.md`** (this file).
- **Pre-commit hook** (`./scripts/install-hooks.sh`) wiring `gnatformat`
  on `.adb`/`.ads`/`.gpr`/`.toml` stages.
- **CI lint pipeline.** `gnatformat --check`, `-gnatyy`, `-gnatwa`,
  `-gnatwe`, `shellcheck`, `actionlint`, `markdownlint`.
- **CI BACKEND=ada exercise.** Builds with `BACKEND=ada`, runs
  `--smoke` and `scripts/demo-offline.sh`. `--smoke` exits non-zero
  if `Signing.Sign` returns `Length := 0`, so a regression that
  silently breaks the pure-Ada signing path now fails CI.
- **CI STM32 cross-build job.** `hadawallet_stm32.gpr` is cross-compiled
  on Ubuntu with the FSF GNAT arm-eabi toolchain (continue-on-error
  until validated on hardware; gracefully reports a compiler ICE).

### Changed

- README restructured: five-minute Quickstart and Documentation index
  at the top; Phase D status table updated to reflect completion.
- `Signing` spec gained `Pubkey_From_Privkey` and `Tweak_Add_Scalar` so
  `Key_Derivation` can perform BIP32 derivation without importing
  libsecp256k1 directly (preserves the "Signing is the only module
  that talks to libsecp256k1" invariant).

### Fixed

- PSBT `partial_sig` serialization corrected for BIP174 compliance: the
  signer's pubkey is now written into the input key field (type 0x02 +
  33-byte pubkey) alongside the DER signature value.

### Known limitations

- UTF-8 NFKD normalization is **not** applied to BIP39 mnemonics or
  passphrases — ASCII-only inputs (deferred to v0.3). For English BIP39
  with an ASCII passphrase this is transparent; non-ASCII inputs will
  not interoperate with other wallets.
- STM32F411 firmware cross-compiles but has not been validated on real
  hardware — signing on hardware requires further work (see
  `docs/stm32-quickstart.md`).
- `BACKEND=ada` signatures verify against the correct pubkey but are
  not byte-identical to libsecp256k1 output (different RFC 6979 nonce
  hash family: HMAC-SHA512 vs HMAC-SHA256). `BACKEND=c` remains the
  default; making `BACKEND=ada` the default after full parity is
  post-MVP.
- No BIP39 mnemonic **generator** is shipped on purpose — see
  `docs/usage.md` §1 for the recommended external workflows. Generation
  is a separate threat-model and folding it into the SPARK-verified
  signer would dilute the proof envelope.

## [0.1.0] - 2026-05-08

Initial public skeleton.

### Added

- Module specifications with SPARK contracts for `Signing`,
  `Key_Derivation`, `Hashing`, `Address`, `Transaction`, `Comm`.
- `Signing` body with `SPARK_Mode => On` and `Refined_State` mapping
  for `Key_State`. `gnatprove --level=1` (and `--level=4` for the
  flow contract) green: 15/15 checks proved on `Signing`.
- Real Bitcoin Core libsecp256k1 FFI as the `Signing` body for
  ECDSA, public-key derivation, and scalar tweak.
- Real SHA-256, SHA-512, RIPEMD-160, HMAC-SHA512, and Hash160
  primitives in `Hashing` (test-vector verified).
- bech32 P2WPKH encoder in `Address`.
- BIP174 PSBT skeleton in `Transaction` with BIP143 sighash.
- `Comm` stdin/stdout loop (boundary I/O).
- AGPL-3.0-or-later license, CONTRIBUTING, SECURITY, proofs/README.
- GitHub Actions CI: build + `gnatprove --level=1 --report=fail` +
  smoke test.

[Unreleased]: https://github.com/vkuprins/hadawallet/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/vkuprins/hadawallet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vkuprins/hadawallet/releases/tag/v0.1.0
