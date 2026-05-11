# Codebase Structure

```
hadawallet/
├── alire.toml              # Alire manifest (deps: gnat>=12, Ada2022, contracts)
├── hadawallet.gpr          # GNAT project file (Source_Dirs=src, Exec_Dir=bin, prove switches)
├── CLAUDE.md               # Project conventions (MCP-first rules, build/prove, invariants)
├── LICENSE                 # AGPL-3.0-or-later
├── src/                    # All Ada source
│   ├── hadawallet.ads      # Root Pure package: shared types (U8/U32/U64, Byte_Array,
│   │                       #   Privkey_Bytes, Pubkey_Bytes, Digest_Bytes, Network, …)
│   ├── signing.{ads,adb}   # secp256k1 ECDSA — Load_Privkey/Has_Key/Sign/Wipe. ONLY module
│   │                       #   that holds private-key bytes. Body SPARK_Mode=Off (stub).
│   ├── key_derivation.{ads,adb}  # BIP32/39/44 (spec only in v0.1)
│   ├── hashing.{ads,adb}   # SHA-256, HMAC-SHA512, RIPEMD-160, Hash160 (spec only)
│   ├── address.{ads,adb}   # bech32 P2WPKH encoding (spec only)
│   ├── transaction.{ads,adb}     # PSBT parse/sighash/serialize (opaque type, spec only)
│   ├── comm.{ads,adb}      # Boundary I/O loop (stdin/stdout). The ONLY I/O surface.
│   └── main.adb            # Entry point — v0.1 smoke test (loads test key, prints Has_Key)
├── proofs/                 # SPARK proof artifacts (README stub for now)
├── .github/workflows/ci.yml # GitHub Actions: setup-alire → install gnatprove → build → prove
├── obj/, bin/, alire/, config/ # build artifacts (gitignored)
└── .serena/                # Serena project config
```

**Module dependency graph (intended):**
```
main → Comm, Signing, Hadawallet
Comm → Transaction, Signing  (boundary I/O)
Signing → Hadawallet  (+ libsecp256k1 binding from week 3)
Key_Derivation → Hadawallet, Hashing
Address → Hadawallet, Hashing
Transaction → Hadawallet, Hashing
Hashing → Hadawallet
Hadawallet → (Pure, nothing)
```

**Important architectural facts encoded in specs:**
- `Signing` is the only module that holds private-key bytes (no public API returns them).
- `Comm` is the only module allowed to `with Ada.Text_IO` or any other I/O package.
- `Key_Derivation` is the only OTHER module besides `Signing` that handles raw privkey bytes — and it has a single output path (Privkey + Chain_Code) consumed by `Signing.Load_Privkey`.
