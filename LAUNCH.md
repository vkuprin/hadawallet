# Launch playbook — v0.1 Show HN

This file is the launch checklist for the v0.1 public release. It is
internal-facing — feel free to delete before the public push, or keep as a
record.

## Pre-flight

- [ ] `alr build` clean on macOS arm64 + Linux x64.
- [ ] `alr test` passes 26/26 vectors.
- [ ] `gnatprove --level=4 --report=fail` reports 22/22 (100%) on `Signing`.
- [ ] `./scripts/demo-offline.sh` produces a signed PSBT with `partial_sig`.
- [ ] CI green on `main`.
- [ ] README accurately enumerates proven vs. trusted (no overclaims).
- [ ] `proofs/README.md` matches current `gnatprove` summary.

## asciinema recording (offline demo)

```bash
asciinema rec hadawallet-demo.cast --command "./scripts/demo-offline.sh && \
  PATH=\$HOME/.alire/bin:\$PATH alr exec -- \
    gnatprove -P hadawallet.gpr --level=4 --report=all 2>&1 | tail -25"
```

Target length: < 60 seconds. Two visible sections:

1. `demo-offline.sh` running end-to-end, showing the hex-dumped signed PSBT.
2. `gnatprove --level=4` running, showing the 22/22 (100%) line.

Upload to asciinema.org, embed link in HN post.

## HN post

**Title** (max 80 chars):

> Show HN: Formally verified Bitcoin hardware wallet firmware in SPARK/Ada

**Body**:

```text
hadawallet is a Bitcoin signing module whose headline claim — "the private
key never leaves the signing module" — is enforced by SPARK flow analysis,
not by code review or testing.

Concretely: the Signing package declares Abstract_State => Key_State and
every other procedure declares Global / Depends against it. gnatprove
--level=4 reports 22/22 (100%) checks proved: data dependencies, flow
dependencies, initialization, termination. If a future change ever
introduces a path from the key buffer to any output of any other module,
the build fails.

v0.1 ships:
  - Pure-Ada SHA-256 / SHA-512 / RIPEMD-160 / HMAC-SHA512
    (FIPS 180-4 + RFC 4231 vector-verified)
  - BIP173 bech32 P2WPKH encoder
  - BIP174 PSBT parser + serializer
  - BIP143 segwit v0 sighash
  - ECDSA signing via libsecp256k1
  - stdin/stdout PSBT signing loop

What's proven:        key-isolation flow contract on Signing.
What's tested:        26 vector checks (FIPS / RFC / BIP).
What's trusted:       libsecp256k1 (Bitcoin Core ref impl), GNAT runtime, OS.
What's NOT in scope:  altcoins, multisig, taproot, BIP39/32 (next), USB, BLE,
                      side-channel resistance, fault injection.

Try it:
  git clone https://github.com/vkuprins/hadawallet
  cd hadawallet && alr build
  ./scripts/demo-offline.sh

asciinema: <link>
proof boundary: https://github.com/vkuprins/hadawallet/blob/main/proofs/README.md

License is AGPL-3.0-or-later with commercial dual-licensing for OEMs.

Happy to take feedback on the proof envelope, the BIP174 parser scope, the
ergonomics of the SPARK contracts, or anything else.
```

**Window**: Tue–Thu, 9–11am ET. Don't post on Friday.

**Comment seeds** (paste yourself within the first hour to keep the thread
on-track):

- Q: "Why not pure-SPARK secp256k1?" — A: planned for v0.3; the flow proof
  holds either way because Signing is the only module that imports the C
  binding.
- Q: "What stops me from extracting the key via a side channel?" — A:
  nothing in v0.1 — that's the hardware phase. Software-only flow proof is
  the artifact today. v0.2 explores STM32 + secure-element bindings if
  there's signal.
- Q: "How is this different from a normal hardware wallet with audited
  firmware?" — A: audit ≠ proof. An audit gives you "we read the code and
  didn't see a leak path." This gives you "the SMT solver, GNAT runtime,
  and libsecp256k1 are the entire trust base — modulo those, the leak path
  cannot exist."

## Cross-posts

After HN traction or 24h, also:

- [ ] r/Bitcoin (technical-discussions friendly hours)
- [ ] r/Ada
- [ ] r/cryptography
- [ ] lobste.rs (separate account, different framing)
- [ ] Bitcoin-Dev mailing list (only if HN hits front page)

## Traction signal

> 500★ on GitHub OR 3+ OEM conversations within 14 days

If met: greenlight STM32 phase (weeks 5–8).
If not: pivot or kill.
