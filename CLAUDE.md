# hadawallet — project conventions

## What this is

Formally verified Bitcoin hardware wallet firmware in SPARK/Ada. Headline claim:
"the private key never leaves the signing module" via SPARK flow analysis.

## Build / prove / test

```bash
alr build                                                       # GNAT build
alr exec -- gnatprove -P hadawallet.gpr --level=1 --report=fail # baseline (v0.1)
alr exec -- gnatprove -P hadawallet.gpr --level=4 --report=all  # full proofs (v0.2)
alr test                                                         # unit tests (week 2+)
./scripts/demo.sh                                                # E2E with bitcoind regtest (week 4)
```

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
