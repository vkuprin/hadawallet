--  Signing — secp256k1 ECDSA module.
--
--  ARCHITECTURAL INVARIANT (the headline marketing claim):
--
--    No public API of this package returns or otherwise emits the
--    private key bytes. The only outputs are signatures and a
--    has-key boolean. The private key is loaded via Load_Privkey
--    and exits the firmware only as the implicit signing-key of a
--    produced signature — never as raw bytes.
--
--    SPARK enforcement (week 2 milestone):
--      - Abstract_State => Key_State (encapsulates the key buffer)
--      - Sign:    Global => Input  Key_State,  Depends => Sig => (Key_State, Digest)
--      - Wipe:    Global => Output Key_State
--
--  v0.1 ships the API shape. Flow contracts land in week 2 once
--  Abstract_State machinery is wired up.

with Hadawallet;

package Signing
  with SPARK_Mode => On
is

   --  Load a 32-byte private key into the module.
   --  Caller is responsible for wiping its own copy after this call.
   procedure Load_Privkey (Key : in Hadawallet.Privkey_Bytes);

   --  True iff a key has been loaded and not subsequently wiped.
   function Has_Key return Boolean;

   --  Compute deterministic ECDSA signature (RFC 6979) over Digest.
   --  Output is DER-encoded; Length indicates valid byte count.
   --  Length = 0 indicates an error (e.g., no key loaded).
   procedure Sign
     (Digest    : in     Hadawallet.Digest_Bytes;
      Signature :    out Hadawallet.Signature_Bytes;
      Length    :    out Hadawallet.Signature_Length);

   --  Securely wipe the loaded key.
   procedure Wipe;

end Signing;
