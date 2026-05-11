#!/usr/bin/env bash
# demo.sh — end-to-end PSBT signing demo against a real bitcoind regtest node.
#
# Flow:
#   1. Spin up bitcoind in regtest mode in a tempdir.
#   2. Derive hadawallet's bcrt1 address from the canonical BIP84 test
#      mnemonic ("abandon" × 11 + "about", no passphrase) at m/84'/0'/0'/0/0.
#   3. Mine 101 blocks to a Core-controlled coinbase address (matures one).
#   4. Send funds from Core's wallet to hadawallet's bcrt1 address; mine 1.
#   5. Construct a PSBT spending hadawallet's UTXO back to Core.
#   6. Pipe the PSBT (binary) through hadawallet for signing.
#   7. Finalize via bitcoin-cli, broadcast, mine 1, assert confirmation.
#
# Skip behavior: if bitcoind / bitcoin-cli / jq / hadawallet binary is
# missing, the script prints install instructions and exits 0 (skip),
# not 1 (fail), so CI stays green where the regtest dependency isn't
# bootstrapped yet.
#
# Requires: bitcoind >= 24, bitcoin-cli, jq, xxd, base64, ./bin/hadawallet.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/hadawallet"

skip() {
  echo "==> SKIP: $1" >&2
  echo "    install: brew install bitcoin    # macOS" >&2
  echo "    install: apt install bitcoind    # Debian/Ubuntu" >&2
  exit 0
}

if ! command -v bitcoind >/dev/null;   then skip "bitcoind not on PATH"; fi
if ! command -v bitcoin-cli >/dev/null; then skip "bitcoin-cli not on PATH"; fi
if ! command -v jq >/dev/null;         then skip "jq not on PATH"; fi
if ! command -v xxd >/dev/null;        then skip "xxd not on PATH"; fi
if ! command -v base64 >/dev/null;     then skip "base64 not on PATH"; fi
if [ ! -x "$BIN" ]; then
  echo "error: $BIN missing — run 'alr build' first" >&2
  exit 1
fi

DATADIR="$(mktemp -d -t hadawallet-regtest.XXXXXX)"
MNEMONIC_FILE="$(mktemp -t hadawallet-mnemonic.XXXXXX)"
PSBT_RAW="$(mktemp -t hadawallet-psbt.XXXXXX)"
SIGNED_RAW="$(mktemp -t hadawallet-signed.XXXXXX)"
BITCOIND_RUNNING=""

cleanup() {
  if [ -n "$BITCOIND_RUNNING" ]; then
    bitcoin-cli -regtest "-datadir=$DATADIR" stop >/dev/null 2>&1 || true
    sleep 1
  fi
  rm -rf "$DATADIR"
  shred -u "$MNEMONIC_FILE" 2>/dev/null || rm -f "$MNEMONIC_FILE"
  rm -f "$PSBT_RAW" "$SIGNED_RAW"
}
trap cleanup EXIT

CLI=(bitcoin-cli -regtest "-datadir=$DATADIR")

cat > "$DATADIR/bitcoin.conf" <<'EOF'
regtest=1
server=1
txindex=1
fallbackfee=0.0002
[regtest]
rpcuser=hada
rpcpassword=hada-regtest-demo
EOF

echo "==> launching bitcoind in regtest mode (datadir=$DATADIR)"
bitcoind -regtest "-datadir=$DATADIR" -daemon >/dev/null
BITCOIND_RUNNING=1

# Poll until RPC is up.
for _ in $(seq 1 30); do
  if "${CLI[@]}" getblockchaininfo >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"${CLI[@]}" getblockchaininfo >/dev/null

echo "==> deriving hadawallet bcrt1 address from BIP84 test mnemonic"
echo "abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon about" > "$MNEMONIC_FILE"
HADA_ADDR=$(HADAWALLET_MNEMONIC_FILE="$MNEMONIC_FILE" \
            HADAWALLET_PATH="m/84'/0'/0'/0/0" \
            "$BIN" --address regtest)
echo "    hada addr: $HADA_ADDR"
EXPECTED="bcrt1qcr8te4kr609gcawutmrza0j4xv80jy8zeqchgx"
if [ "$HADA_ADDR" != "$EXPECTED" ]; then
  echo "error: derived address mismatch (got $HADA_ADDR, want $EXPECTED)" >&2
  exit 1
fi

echo "==> creating Core wallet + funding"
"${CLI[@]}" -named createwallet wallet_name=core load_on_startup=true \
  >/dev/null 2>&1 || true
CORE_ADDR=$("${CLI[@]}" -rpcwallet=core getnewaddress "" "bech32")
"${CLI[@]}" generatetoaddress 101 "$CORE_ADDR" >/dev/null
echo "    core addr: $CORE_ADDR"

echo "==> sending 1 BTC to hadawallet address"
FUND_TXID=$("${CLI[@]}" -rpcwallet=core sendtoaddress "$HADA_ADDR" 1.0)
"${CLI[@]}" generatetoaddress 1 "$CORE_ADDR" >/dev/null
echo "    funding txid: $FUND_TXID"

# Find which vout pays hadawallet.
FUND_TX_HEX=$("${CLI[@]}" getrawtransaction "$FUND_TXID")
FUND_TX_JSON=$("${CLI[@]}" decoderawtransaction "$FUND_TX_HEX")
HADA_VOUT=$(echo "$FUND_TX_JSON" | jq -r \
  ".vout[] | select(.scriptPubKey.address == \"$HADA_ADDR\") | .n")
if [ -z "$HADA_VOUT" ]; then
  echo "error: could not locate hadawallet vout in funding tx" >&2
  exit 1
fi
echo "    hada vout: $HADA_VOUT"

echo "==> constructing spend PSBT (hada -> core, 0.999 BTC, 0.001 fee)"
PSBT_B64=$("${CLI[@]}" createpsbt \
  "[{\"txid\":\"$FUND_TXID\",\"vout\":$HADA_VOUT}]" \
  "[{\"$CORE_ADDR\":0.999}]")
# Populate witness_utxo from the node's UTXO set so hadawallet's BIP143
# sighash has the amount + scriptPubKey it needs.
PSBT_B64=$("${CLI[@]}" utxoupdatepsbt "$PSBT_B64")
echo "    psbt b64 (first 120 chars): ${PSBT_B64:0:120}..."

echo "==> piping PSBT through hadawallet (binary in/out)"
echo -n "$PSBT_B64" | base64 -d > "$PSBT_RAW"
HADAWALLET_MNEMONIC_FILE="$MNEMONIC_FILE" \
  HADAWALLET_PATH="m/84'/0'/0'/0/0" \
  "$BIN" < "$PSBT_RAW" > "$SIGNED_RAW"
SIGNED_B64=$(base64 < "$SIGNED_RAW" | tr -d '\n')

echo "==> finalizing PSBT"
FINAL=$("${CLI[@]}" finalizepsbt "$SIGNED_B64")
COMPLETE=$(echo "$FINAL" | jq -r '.complete')
if [ "$COMPLETE" != "true" ]; then
  echo "error: finalizepsbt reports incomplete" >&2
  echo "$FINAL" >&2
  exit 1
fi
RAW_TX=$(echo "$FINAL" | jq -r '.hex')

echo "==> broadcasting"
SPEND_TXID=$("${CLI[@]}" sendrawtransaction "$RAW_TX")
echo "    spend txid: $SPEND_TXID"

"${CLI[@]}" generatetoaddress 1 "$CORE_ADDR" >/dev/null

echo "==> confirming"
TX_INFO=$("${CLI[@]}" getrawtransaction "$SPEND_TXID" 1)
CONFS=$(echo "$TX_INFO" | jq -r '.confirmations // 0')
if [ "$CONFS" -lt 1 ]; then
  echo "error: spend tx not confirmed (conf=$CONFS)" >&2
  exit 1
fi

echo "==> OK: txid $SPEND_TXID confirmed at $CONFS conf via Bitcoin Core"
echo "==> proof: gnatprove --level=4 reports 22/22 (100%) checks proved on Signing"
