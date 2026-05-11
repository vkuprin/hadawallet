# Architecture Invariants — DO NOT BREAK

These are load-bearing for the headline marketing claim and the SPARK flow
proof. Violating them silently invalidates the "private key never leaves
the signing module" claim.

## 1. `Signing` is the only module that holds private-key bytes

- No public API of `Signing` returns key bytes (only `Signature_Bytes` or `Boolean`).
- No other module imports or declares a `Privkey_Bytes` buffer except
  `Key_Derivation`, whose single output path is consumed directly by
  `Signing.Load_Privkey`.
- Week 2 milestone: wire `Abstract_State => Key_State` on the package spec,
  with explicit `Global` / `Depends` contracts on `Sign` and `Wipe`. This
  is what SPARK flow analysis verifies.

## 2. `Comm` is the only boundary module

- Stdin/stdout I/O lives ONLY in `Comm`.
- Other modules MUST NOT import:
  - `Ada.Text_IO`
  - `Ada.Streams.Stream_IO`
  - any network or filesystem package
- `main.adb` currently imports `Ada.Text_IO` for the smoke-test banner —
  that's acceptable because `main` isn't part of the proof envelope; it
  exists only to demonstrate that `Signing.Has_Key` flips. Once the real
  `Comm.Run` loop is in place, the banner prints should move (or stay
  out of the proof scope).

## 3. `Signing` is the ONLY module that talks to libsecp256k1 (week 3 onwards)

- When the C binding to `libsecp256k1` lands in week 3, it lives inside the
  `Signing` body only.
- The C-binding "contamination" (`Convention => C`, `Import => True`, raw
  pointer params) is contained to one module.
- Flow claim still holds: `Signing` passes the key to C, gets a signature
  back; no other SPARK module sees the key.

## What to push back on

If asked to add anything in the "Out of scope" list (altcoins, multisig,
taproot, USB, BLE, GUI, secure boot, hardware hardening, broader PSBT
support before v0.3), say no and reference:
- `CLAUDE.md` → "Scope discipline (v0.1–v0.2)"
- Auto-memory → `project_mvp_scope.md`, `project_launch_strategy.md`
- The strategic priority is speed-to-public-artifact through week 4.

## What NOT to claim publicly

- Do NOT claim "math-proven secp256k1" or "fully verified curve math"
  before the pure-SPARK secp256k1 port lands (v0.3+). v0.1–v0.2 uses the
  C binding to Bitcoin Core's libsecp256k1; curve math is NOT proven.
  The flow claim (key isolation) is what's proven and that's what to
  advertise.
- Do NOT add a second I/O surface (USB / BLE) — single-boundary
  architecture is what makes the flow proof meaningful.
