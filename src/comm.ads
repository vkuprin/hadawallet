--  Comm — boundary I/O loop.
--
--  ARCHITECTURAL ROLE: Comm is the single boundary module. Stdin/stdout
--  I/O and filesystem/env access live ONLY here. This is what makes the
--  key-isolation flow proof meaningful: there is exactly one place where
--  bytes leave the firmware, and SPARK flow analysis confirms that no
--  path from Signing's key buffer reaches a Comm output.
--
--  Protocol: PSBT bytes via stdin/stdout (QR-equivalent on hardware).

with Hadawallet;

package Comm
  with SPARK_Mode => On
is

   --  Run the I/O loop once. Reads a PSBT from stdin, hands off to
   --  Signing, writes signed PSBT to stdout. Returns when stdin closes.
   procedure Run;

   --  Load the active private key per environment configuration:
   --    1. If $HADAWALLET_MNEMONIC_FILE (or ~/.hadawallet/mnemonic.txt)
   --       exists, derive the privkey at $HADAWALLET_PATH (default
   --       m/84'/0'/0'/0/0) via BIP39 + BIP32.
   --    2. Otherwise, read 32 raw bytes from $HADAWALLET_PRIVKEY_FILE
   --       (or ~/.hadawallet/key.bin).
   --  Body is SPARK_Mode => Off — file/env access is external state.
   procedure Load_Active_Privkey
     (Key : out Hadawallet.Privkey_Bytes; Ok : out Boolean)
   with Global => null;

end Comm;
