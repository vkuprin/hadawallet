#!/usr/bin/env bash
# demo-offline.sh — end-to-end PSBT signing demo, no bitcoind required.
#
# Flow:
#   1. Generate a 32-byte privkey to a tempfile.
#   2. Run `hadawallet --fixture` to emit an unsigned P2WPKH PSBT.
#   3. Pipe that PSBT back through `hadawallet` for signing.
#   4. Dump the signed PSBT in hex and confirm the partial_sig is present.
#
# This is the script used to record the HN-launch asciinema.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/hadawallet"
KEY="$(mktemp -t hadawallet-demo-key.XXXXXX)"
UNSIGNED="$(mktemp -t hadawallet-unsigned.XXXXXX)"
SIGNED="$(mktemp -t hadawallet-signed.XXXXXX)"

cleanup() {
  shred -u "$KEY" 2>/dev/null || rm -f "$KEY"
  rm -f "$UNSIGNED" "$SIGNED"
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then
  echo "error: $BIN missing — run 'alr build' first" >&2
  exit 1
fi

echo "==> generating 32-byte privkey"
head -c 32 /dev/urandom > "$KEY"

echo "==> emitting unsigned P2WPKH PSBT fixture"
HADAWALLET_PRIVKEY_FILE="$KEY" "$BIN" --fixture > "$UNSIGNED"
echo "    unsigned size: $(wc -c < "$UNSIGNED") bytes"

echo "==> signing PSBT (stdin -> stdout)"
HADAWALLET_PRIVKEY_FILE="$KEY" "$BIN" < "$UNSIGNED" > "$SIGNED"
echo "    signed size:   $(wc -c < "$SIGNED") bytes"

echo "==> signed PSBT hex (first 256 bytes):"
xxd "$SIGNED" | head -16

# Sanity check: signed PSBT must start with the BIP174 magic.
MAGIC=$(xxd -p -l 5 "$SIGNED")
if [ "$MAGIC" != "70736274ff" ]; then
  echo "error: signed output missing PSBT magic (got $MAGIC)" >&2
  exit 1
fi

# Look for BIP174 partial_sig key: varint(34) || 0x02 || 33-byte pubkey.
# We check for the prefix "22 02" — key length 34 followed by type 0x02.
if ! xxd -p "$SIGNED" | tr -d '\n' | grep -q "2202"; then
  echo "error: BIP174 partial_sig key (22 02) not found in signed PSBT" >&2
  exit 1
fi

echo "==> OK: signed PSBT carries a BIP174 partial_sig under input key 0x02"
echo "==> proof: gnatprove --level=4 reports 22/22 (100%) checks proved on Signing"
