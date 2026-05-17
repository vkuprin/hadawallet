# hadawallet

Every other hardware wallet asks you to trust the vendor's process. This one ships a machine-checkable artifact that says the worst-case bad thing can't happen.

> Formally verified Bitcoin hardware wallet firmware in SPARK/Ada.

**Status**: v0.2-dev — end-to-end PSBT signing works, BIP39 mnemonic + BIP32
derivation lands. `gnatprove --level=4` reports **22 / 22 (100%)** checks
proved on `Signing` — the key-isolation flow contract is verified by SPARK,
not aspirational.

## Quickstart (5 minutes)

```bash
# 1. Install Alire (https://alire.ada.dev), then build:
alr build

# 2. Try it without a key (offline PSBT signing demo):
./scripts/demo-offline.sh

# 3. Provision a BIP39 mnemonic. See docs/usage.md for safe ways
#    to generate one; for a quick test you can use the canonical
#    Trezor vector (DO NOT use this for real funds):
mkdir -p ~/.hadawallet
printf '%s\n' \
  "abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon about" \
  > ~/.hadawallet/mnemonic.txt

# 4. Derive your first BIP84 P2WPKH address:
./bin/hadawallet --address mainnet
# bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu

# 5. Sign a fixture PSBT (replace --fixture with your own PSBT on stdin):
./bin/hadawallet --fixture | ./bin/hadawallet > /tmp/signed.psbt

# 6. What next?
./bin/hadawallet --help              # full mode reference
# docs/usage.md                       # mainnet usage, safety checklist
# proofs/README.md                    # what's proven, what's trusted
```

## Documentation

- **Usage guide** — [docs/usage.md](docs/usage.md): how to provision a
  mnemonic, sign PSBTs, derive addresses, mainnet safety checklist.
- **Proof model** — [proofs/README.md](proofs/README.md): what's proven,
  what's trusted, the precise boundary.
- **STM32 quickstart** — [docs/stm32-quickstart.md](docs/stm32-quickstart.md):
  cross-compile for Nucleo-F411 (scaffolding).
- **Contributing** — [CONTRIBUTING.md](CONTRIBUTING.md).
- **Security** — [SECURITY.md](SECURITY.md).
- **Changelog** — [CHANGELOG.md](CHANGELOG.md).

## The claim

The headline guarantee is **"the private key never leaves the signing
module"**, enforced by SPARK flow analysis, not by code review or testing.

Concretely: the `Signing` package declares `Abstract_State => Key_State` and
every other procedure declares `Global` / `Depends` against it. SPARK
mechanically verifies that no flow exists from `Key_State` to any output of
any other module. `Comm` (the I/O boundary) writes signature bytes to stdout;
the flow analyzer can prove that those bytes are functionally derived from
the key, but the key bytes themselves never reach the byte stream — by
construction.

If a future change ever introduces such a path, the build fails. The claim is
strong but narrow — see [`proofs/README.md`](proofs/README.md) for the precise
proof boundary.

## Architecture

Each module's SPARK status as of v0.2-dev:

```text
┌────────────────────────────────────────────────────────────────────┐
│ Comm (stdin/stdout I/O loop)                  [boundary, Off]      │
│   ↓ psbt_bytes                ↑ signed_psbt                        │
├────────────────────────────────────────────────────────────────────┤
│ Transaction (BIP174 PSBT + BIP143 sighash)    [Off, contracted]    │
│   ↓ sighash_digest                                                 │
├────────────────────────────────────────────────────────────────────┤
│ Address (BIP173 bech32 P2WPKH)                [Off, contracted]    │
│ Hashing (SHA256, SHA512, RIPEMD160, HMAC512)  [Off, contracted]    │
├────────────────────────────────────────────────────────────────────┤
│ Signing (secp256k1 ECDSA via libsecp256k1)    [On, Platinum-flow]  │
│   ←  privkey (loaded once, isolated)                               │
│   →  DER signature bytes                                           │
└────────────────────────────────────────────────────────────────────┘
```

`Hashing`, `Address`, and `Transaction` have SPARK contracts on their specs
(`Global => null`, `Depends` per input/output) so callers can prove their own
flow against them, but their bodies are `SPARK_Mode => Off` — runtime-error
freedom on the bit-level loops is established by bounded indexing, not by
SMT solver. Functional correctness is established against published BIP /
FIPS / RFC test vectors.

`Signing` is the only module where the body is `SPARK_Mode => On`, and the
flow proof closes the loop: no path from `Key_State` reaches any output
except via `Sign`, whose declared dependency is `(Signature, Length) =>
(Key_State, Digest)`.

## What's proven, what's trusted

### Proven by SPARK

- Key isolation: no path from the private-key buffer to any non-`Signing`
  output. Verified at `gnatprove --level=4` with zero unproved obligations.
- Initialization of all output parameters across `Signing` (no read of
  uninitialized state).

### Verified by test vector (not by SMT proof)

- `SHA-256("abc")` matches the FIPS 180-4 vector.
- `RIPEMD-160("abc")` matches the RIPEMD-160 specification vector.
- `HMAC-SHA512` RFC 4231 Test Case 1.
- `bech32` BIP173 example: `Hash160(G)` →
  `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`.
- ECDSA signing produces well-formed DER signatures (71 bytes typical) for
  the canonical privkey.

### Trusted (not proven)

- `libsecp256k1` — the Bitcoin Core reference C implementation of the
  curve math. Pure-SPARK port is on the v0.3 roadmap.
- The Ada runtime, GNAT compiler, GNATprove toolchain, libc, and OS.
- Hardware (when ported to STM32 — that work is v0.2+).

### Not in scope for v0.1–v0.2

- Side-channel resistance (timing, power, EM). Hardware-phase concern.
- Glitching / fault injection.
- Supply-chain compromise of the toolchain — reproducible builds are
  roadmap.

## Scope

**In v0.1–v0.2**: BTC only, secp256k1, P2WPKH segwit v0, bech32, PSBT v0
(BIP174) restricted to ≤ 16 inputs/outputs, stdin/stdout PSBT I/O, native
binary, BIP39 + BIP32 + BIP84 key derivation (mnemonic file at
`$HADAWALLET_MNEMONIC_FILE`, path at `$HADAWALLET_PATH`, default
`m/84'/0'/0'/0/0`). Raw-key fallback at `$HADAWALLET_PRIVKEY_FILE` retained
for demos. STM32 Nucleo-F4 conditional on launch traction.

**Not in v0.1–v0.2**: altcoins, multisig, taproot, USB HID, BLE, GUI, secure
boot, side-channel hardening, pure-SPARK secp256k1, UTF-8 NFKD
normalization of non-ASCII mnemonics (English BIP39 wordlist + ASCII
passphrase only).

## Backends

`hadawallet.gpr` exposes a `BACKEND` scenario variable:

- `BACKEND=c` (default) — `Signing` body is the libsecp256k1 FFI at
  [src/backend_c/signing.adb](src/backend_c/signing.adb). This is the
  production path; SPARK level-4 reports 22/22.
- `BACKEND=ada` — `Signing` body is the in-tree
  [src/backend_ada/signing.adb](src/backend_ada/signing.adb) which
  delegates to a pure-Ada secp256k1 in [src/secp256k1/](src/secp256k1/).
  No `libsecp256k1` link.

```bash
alr build                          # BACKEND=c (default), links libsecp256k1
BACKEND=ada alr build              # no C library linked; pure-Ada path
```

**Pure-Ada secp256k1 status (Phase D complete):**

| Operation                     | Status                                |
|-------------------------------|---------------------------------------|
| `Field.{Add,Sub,Mul,Sqr,Inv}` | ✅ Working, vector-tested             |
| `Scalar.{Add,Sub,Mul,Inv}`    | ✅ Working, vector-tested             |
| `Group.Generator`             | ✅                                    |
| `Group.{To,From}_Compressed`  | ✅ Working (sqrt mod p via Fermat)    |
| `Group.Scalar_Mul`            | ✅ Working (affine double-and-add)    |
| `Ecdsa.Pubkey_From_Privkey`   | ✅ Working (calls Group.Scalar_Mul)   |
| `Ecdsa.Tweak_Add_Scalar`      | ✅ Working (BIP32 non-hardened)       |
| `Ecdsa.Sign`                  | ✅ Working (RFC 6979 deterministic)   |
| `Der.Encode_Signature`        | ✅ Working (BIP66 minimal DER)        |

**Cross-backend equality verified**: BIP84 derivation
`m/84'/0'/0'/0/0` from the canonical "abandon × 11 + about" mnemonic
produces the identical address `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`
under both backends. BACKEND=ada signing is functional but stays
opt-in for v0.2 — BACKEND=c (libsecp256k1) is the default
production path. Full byte-for-byte signature parity validation
(BACKEND=ada becomes default) is post-MVP.

## STM32F411 Nucleo (scaffolding)

`hadawallet_stm32.gpr` cross-compiles a Cortex-M4F firmware that
prints a boot banner over USART2 and runs the SHA-256 FIPS-180-4
self-test. See [docs/stm32-quickstart.md](docs/stm32-quickstart.md)
for the toolchain + flashing procedure. **Status: scaffolding** —
not yet validated on real hardware, and signing on hardware is
blocked on Phase D's pure-SPARK secp256k1.

## License

AGPL-3.0-or-later for the open-source release — see [LICENSE](LICENSE).

Commercial licensing is available for OEMs and product integrations that
cannot meet AGPL source-disclosure obligations. Contact the maintainer (see
`alire.toml`) to discuss terms.
