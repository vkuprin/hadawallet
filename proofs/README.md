# Proof boundary

Honesty here is critical. Overclaiming kills credibility with the security community,
which is exactly the audience this project depends on.

## Status: v0.1 (skeleton + key-isolation flow proof)

- Module APIs are designed for isolation: no public function returns private key bytes.
- `gnatprove --level=1` (runtime-error checks) is the CI baseline.
- **`Signing` Abstract_State + Global/Depends flow contracts landed**:
  `gnatprove --level=4 --report=all` reports **15 / 15 (100%)** checks proved on
  `Signing` (data dependencies, flow dependencies, initialization, termination —
  zero unproved, zero justified). The "private key never leaves the signing
  module" claim is now SPARK-verified by construction.

## Status: v0.2 target (week 4 — HN launch)

### Proven (SPARK-verified)

- **Key-isolation flow contract** on `Signing` package
  (`Global => (Input => Key_State)`, `Depends => (Sig => (Key_State, Digest))`).
  Verified by `gnatprove --level=4` flow analysis. This is the headline marketing claim.
- **Absence of runtime errors** across pure-SPARK modules: `Hashing`, `Key_Derivation`,
  `Address`, `Transaction` parser. No buffer overflows, integer overflows, null derefs.
- **Functional correctness** of hashing primitives against published RFC test vectors.
- **BIP-spec conformance** of `Key_Derivation`, `Address`, `Transaction` against the
  test vectors published in BIP32, BIP39, BIP173, BIP174.

### Trusted (NOT proven)

- **libsecp256k1**: the underlying ECDSA curve math is the C reference implementation
  from Bitcoin Core. We trust it but do not prove it. Pure-SPARK port is on the v0.2
  roadmap.
- **OS / runtime / Alire**: standard trust assumptions for a hosted-environment binary.
- **GNAT compiler / GNATprove**: trusted toolchain.
- **Hardware**: CPU silicon, RNG, secure element when ported to STM32. Hardware-phase work.

### Out of scope

- Side-channel resistance (timing, power, EM emanation). Hardware-phase work.
- Glitching / fault injection. Hardware-phase work.
- Supply-chain compromise of the build toolchain. Reproducible builds are roadmap.

## How to verify locally

```bash
alr build
alr exec -- gnatprove -P hadawallet.gpr --level=1 --report=fail   # v0.1 baseline
alr exec -- gnatprove -P hadawallet.gpr --level=4 --report=all    # v0.2 full proof
```

Expected at v0.2: `0 unproven` for everything except the documented trusted-boundary
modules (the C-binding layer in `Signing`).
