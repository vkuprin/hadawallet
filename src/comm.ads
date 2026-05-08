--  Comm — boundary I/O loop.
--
--  ARCHITECTURAL ROLE: Comm is the single boundary module. Stdin/stdout
--  I/O lives ONLY here. This is what makes the key-isolation flow proof
--  meaningful: there is exactly one place where bytes leave the firmware,
--  and SPARK flow analysis confirms that no path from Signing's key
--  buffer reaches a Comm output.
--
--  Protocol: PSBT bytes via stdin/stdout (QR-equivalent on hardware).
--  v0.1 stub: prints a banner and exits. Full loop lands week 3.

package Comm
  with SPARK_Mode => On
is

   --  Run the I/O loop once. Reads a PSBT from stdin, hands off to
   --  Signing, writes signed PSBT to stdout. Returns when stdin closes.
   procedure Run;

end Comm;
