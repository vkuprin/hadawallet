# hadawallet — Project Overview

**What:** Formally verified Bitcoin hardware wallet firmware in SPARK/Ada.

**Headline claim:** "The private key never leaves the signing module" — proven via SPARK flow analysis.

**Current state (v0.1-dev, May 2026):**
- Module skeleton: SPARK-enabled specs (`with SPARK_Mode => On`) + stubbed bodies (`SPARK_Mode => Off`).
- `alr build` and `gnatprove --level=1 --report=fail` are green locally and in CI.
- No real cryptography yet — `Signing.Sign` is a stub returning zeros.

**Roadmap (4-week MVP):**
- Week 1 (now): Skeleton + native build + level-1 proof baseline.
- Week 2: Pure-SPARK `Hashing` (SHA-256, HMAC-SHA512, RIPEMD-160), `Key_Derivation` (BIP32/39/44), `Signing` `Abstract_State`/flow contracts.
- Week 3: `libsecp256k1` C binding inside `Signing`, `Address` bech32, `Transaction` PSBT (P2WPKH only), `Comm` stdin/stdout loop.
- Week 4: Level-4 proofs, key-isolation flow assertion, E2E demo with `bitcoind` regtest, HN launch.

**Strategy:** speed-to-public-artifact > scope. QEMU/native first, STM32 only after traction signal. License is AGPL-3.0-or-later (dual-license revenue model).

**Out of scope (v0.1–v0.2):** altcoins, multisig, taproot, USB, BLE, GUI, secure boot, hardware hardening. Push back if asked to add these.

**Repo:** https://github.com/vkuprins/hadawallet
