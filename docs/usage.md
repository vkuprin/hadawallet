# hadawallet usage guide

Practical guide for using `hadawallet` as a personal Bitcoin signer from the
terminal. Pair this with [`../README.md`](../README.md) (claim + architecture)
and [`../proofs/README.md`](../proofs/README.md) (what is and isn't proven).

> **Status note.** `hadawallet` is research-grade software. The SPARK proof
> covers key isolation only — it does not certify the curve math, the runtime,
> the OS, or your hardware. Use testnet/regtest first. Move only amounts you
> can afford to lose.

## 1. Provisioning a mnemonic

`hadawallet` deliberately does **not** generate mnemonics. Entropy collection
is a separate, sensitive concern with its own threat model (RNG quality,
side-channels in word selection), and folding it into a SPARK-verified signer
would dilute the proof envelope without adding meaningful safety. The signer
should sign; another tool should generate.

Pick one of the following.

### 1a. A dedicated hardware generator (recommended)

Use any of: **Coldcard**, **Trezor**, **SeedSigner**, **Krux**, **BitBox02**,
or a Tails-booted offline laptop running a vetted BIP39 generator. Write the
24 words down on paper, then transcribe them into the mnemonic file
(see §2). Treat the paper as a single point of failure — store it the way
you'd store the password to your life.

### 1b. Dice + SHA-256 (no devices, all paper)

128 dice rolls give you 256 bits of entropy (each roll is ~2.585 bits). Map
1–6 to 1–6, concatenate into a long decimal string, SHA-256 it, take the
first 256 bits, then convert to a BIP39 mnemonic using any offline BIP39
encoder. The [Coldcard "Roll Your Own"
guide](https://coldcard.com/docs/verifying-dice-roll-math/) walks through
the math; do this work fully offline.

### 1c. A trusted host-side library (development only)

For *development and testing*, a one-shot Python invocation is fine:

```bash
python3 -c '
import secrets, hashlib
ent = secrets.token_bytes(32)               # 256 bits of entropy
csum = hashlib.sha256(ent).digest()[0] >> 0  # 8-bit checksum
bits = "".join(f"{b:08b}" for b in ent) + f"{csum:08b}"
print(" ".join(bits[i:i+11] for i in range(0, len(bits), 11)))
' \
  | awk 'BEGIN{
      while ((getline line < "english.txt") > 0) words[NR-1] = line
    } {
      for (i = 1; i <= NF; i++) printf "%s%s", words[strtonum("0b" $i)], (i<NF?" ":"\n")
    }'
```

`english.txt` is the [BIP39 English wordlist](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt).

**Never use this method for real funds.** A long-lived Bitcoin seed should
come from hardware you control, not a script in your shell history.

## 2. Mnemonic file format

`hadawallet` reads the mnemonic from the path in
`$HADAWALLET_MNEMONIC_FILE` (default `~/.hadawallet/mnemonic.txt`):

- Plain text, UTF-8 encoded.
- One mnemonic per file — words separated by single spaces or newlines;
  surrounding whitespace is trimmed.
- 12, 15, 18, 21, or 24 words (BIP39 standard lengths).
- **ASCII only** for both the mnemonic and the optional passphrase. UTF-8
  NFKD normalization is **not** applied in v0.2 (deferred to v0.3 — see
  the comment in [`../src/key_derivation.adb`](../src/key_derivation.adb)
  near the top of the body). For English mnemonics with ASCII passphrases
  this matches every other BIP39 implementation; for non-ASCII words or
  passphrases, your derived addresses will not interoperate.

Recommended permissions:

```bash
mkdir -p ~/.hadawallet
chmod 700 ~/.hadawallet
chmod 600 ~/.hadawallet/mnemonic.txt
```

## 3. Environment variables

| Variable                    | Default                          | Purpose                                                |
|-----------------------------|----------------------------------|--------------------------------------------------------|
| `HADAWALLET_MNEMONIC_FILE`  | `~/.hadawallet/mnemonic.txt`     | BIP39 mnemonic file (primary key source).              |
| `HADAWALLET_PRIVKEY_FILE`   | `~/.hadawallet/key.bin`          | Raw 32-byte privkey file (fallback if mnemonic absent).|
| `HADAWALLET_PATH`           | `m/84'/0'/0'/0/0`                | BIP32 derivation path (BIP84 first receive address).   |

The privkey-file fallback is intended for demo/test material, not for
production. If `$HADAWALLET_MNEMONIC_FILE` exists it always wins.

## 4. Deriving an address

```bash
./bin/hadawallet --address mainnet
# bc1q...
./bin/hadawallet --address testnet
# tb1q...
./bin/hadawallet --address regtest
# bcrt1q...
```

To derive a different path, override `HADAWALLET_PATH`:

```bash
# Second receive address on the first account:
HADAWALLET_PATH="m/84'/0'/0'/0/1" ./bin/hadawallet --address mainnet

# Hardened-only path (account-level):
HADAWALLET_PATH="m/84'/0'/0'" ./bin/hadawallet --address mainnet
```

**Verify the derived address against a second wallet** before sending funds.
Use Sparrow, Electrum, or any BIP84 watch-only wallet seeded from your
mnemonic to confirm the address matches. If it doesn't match — stop, do not
fund.

## 5. Signing a PSBT

`hadawallet` is a PSBT signer with a single contract: PSBT in on stdin,
signed PSBT out on stdout. Construct the PSBT with any other tool
(Bitcoin Core, Sparrow, electrum, your own scripts).

### 5a. Regtest (recommended — practice here first)

The full end-to-end flow against a local Bitcoin Core regtest node lives in
[`../scripts/demo.sh`](../scripts/demo.sh). It will:

1. Spin up a temporary `bitcoind` in regtest mode.
2. Fund the address derived from your mnemonic.
3. Construct a PSBT spending one of those UTXOs.
4. Pipe the PSBT through `hadawallet` for signing.
5. Finalize, broadcast, and confirm.

```bash
./scripts/demo.sh
```

The script self-skips with exit 0 if `bitcoind`, `bitcoin-cli`, or `jq`
are not installed.

### 5b. Mainnet

The mainnet flow is **identical** to regtest — same binary, same stdin
contract. The differences are entirely in how you construct the PSBT and
how you broadcast the signed result. A typical sequence:

```bash
# 1. Construct the PSBT in your watch-only wallet (Sparrow shown):
#    File > Create transaction > inputs/outputs > Save PSBT to disk.

# 2. Transfer the PSBT to the machine running hadawallet.
#    For an offline signer: SD card / QR code / USB stick — never network.

# 3. Sign:
./bin/hadawallet < unsigned.psbt > signed.psbt

# 4. Transfer signed.psbt back to your online machine.

# 5. Finalize and broadcast from the watch-only wallet.
```

### 5c. Offline-only demo

For a self-contained signing demo with no external state, use the offline
script — it generates a temporary key, builds a synthetic PSBT, signs it,
and confirms the signature is present:

```bash
./scripts/demo-offline.sh
```

## 6. Mainnet safety checklist

Before any mainnet transaction, walk through:

- [ ] **Test on regtest first.** Run `./scripts/demo.sh` end-to-end with
  the same mnemonic file you'll use for mainnet (export
  `HADAWALLET_MNEMONIC_FILE` to point at the same path).
- [ ] **Verify your address in a second wallet.** Seed Sparrow/Electrum
  with the same mnemonic. Confirm `--address mainnet` (and any
  `HADAWALLET_PATH` override) matches.
- [ ] **Construct the PSBT in a watch-only wallet first.** Don't hand-roll
  the PSBT bytes. Use a tool that shows you destination, amount, fee,
  and change address in plain English before serializing.
- [ ] **Sign offline.** Run `hadawallet` on a machine without network
  access. Move PSBTs via SD card or QR, not over a socket.
- [ ] **Inspect the signed PSBT before broadcast.** Use `bitcoin-cli
  decodepsbt` or your watch-only wallet to confirm the signed PSBT
  matches what you intended.
- [ ] **Broadcast deliberately.** Have the destination wallet open to
  watch for confirmation.
- [ ] **Wipe ephemeral material.** If you used `$HADAWALLET_PRIVKEY_FILE`,
  `shred -u` it after signing.

## 7. CLI reference

```bash
./bin/hadawallet --help     # full mode reference
./bin/hadawallet --version  # version string
```

Modes:

| Mode                    | Purpose                                                |
|-------------------------|--------------------------------------------------------|
| *(no args)*             | Sign: read PSBT from stdin, write signed PSBT to stdout.|
| `--address [NET]`       | Print BIP84 P2WPKH address. NET ∈ {mainnet, testnet, regtest}.|
| `--fixture`             | Emit an unsigned demo PSBT to stdout.                  |
| `--smoke`               | Run module smoke tests against FIPS/RFC/BIP vectors.   |
| `--version`             | Print version and exit.                                |
| `--help`, `-h`          | Print full help and exit.                              |

## 8. Exit codes

| Code | Meaning                                                            |
|------|--------------------------------------------------------------------|
| 0    | Success.                                                           |
| 1    | Bad arguments, missing mnemonic/privkey, or signing/encode failure.|

Diagnostic output (sighash hex, signature length, parse errors) goes to
**stderr**. Signed PSBT bytes and address strings go to **stdout**. Pipe
accordingly.

## 9. Troubleshooting

**`hadawallet: --address pubkey derivation failed`**
The mnemonic file was unreadable, empty, or contained non-ASCII characters.
Check `$HADAWALLET_MNEMONIC_FILE`, file permissions, and that every word is
plain ASCII.

**`hadawallet: unknown argument "..."`**
Run `./bin/hadawallet --help` for the full mode reference.

**Address from `hadawallet` doesn't match Sparrow/Electrum.**
Most common causes: (1) different `HADAWALLET_PATH`, (2) different BIP39
passphrase (hadawallet uses no passphrase by default — currently no env
var for it; deferred to v0.3 alongside NFKD), (3) different network
selected (`mainnet` vs `testnet`).

**Signing exits 0 but the PSBT looks the same.**
`hadawallet` writes the signed PSBT to *stdout*. If you ran it without
redirecting, the signed bytes printed to your terminal and were lost in
the scrollback. Redirect: `./bin/hadawallet > signed.psbt`.

**`alr build` fails on macOS arm64.**
The default `BACKEND=c` requires `libsecp256k1` to be installed
(`brew install libsecp256k1`). If you can't install it, use the pure-Ada
backend: `BACKEND=ada alr build` (see [`../README.md`](../README.md) for
the parity caveat).

## 10. Where to go next

- [`../proofs/README.md`](../proofs/README.md) — the proof boundary and
  what's actually guaranteed.
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — how to contribute.
- [`../SECURITY.md`](../SECURITY.md) — vulnerability disclosure.
- [`stm32-quickstart.md`](stm32-quickstart.md) — STM32F411 firmware build
  (scaffolding; not yet validated on real hardware).
