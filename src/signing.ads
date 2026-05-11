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
--  SPARK enforcement:
--    The private-key buffer is encapsulated in Abstract_State Key_State.
--    Every subprogram below declares its Global/Depends flow against
--    Key_State. No caller can extract key bytes by construction:
--      - Load_Privkey writes Key_State, depends on Key.
--      - Sign        reads  Key_State; Signature depends on
--                    (Key_State, Digest).
--      - Wipe        writes Key_State, depends on no input.
--      - Has_Key     reads  Key_State; returns a Boolean only.
--    Refined_State on the body ties Key_State to the hidden buffer +
--    loaded flag, so flow analysis can prove no other module reaches them.

with Hadawallet;

package Signing
  with SPARK_Mode => On, Abstract_State => Key_State, Initializes => Key_State
is

   --  Load a 32-byte private key into the module.
   --  Caller is responsible for wiping its own copy after this call.
   procedure Load_Privkey (Key : in Hadawallet.Privkey_Bytes)
   with Global => (Output => Key_State), Depends => (Key_State => Key);

   --  True iff a key has been loaded and not subsequently wiped.
   function Has_Key return Boolean
   with Global => (Input => Key_State);

   --  Compute deterministic ECDSA signature (RFC 6979) over Digest.
   --  Output is DER-encoded; Length indicates valid byte count.
   --  Length = 0 indicates an error (e.g., no key loaded).
   procedure Sign
     (Digest    : in Hadawallet.Digest_Bytes;
      Signature : out Hadawallet.Signature_Bytes;
      Length    : out Hadawallet.Signature_Length)
   with
     Global  => (Input => Key_State),
     Depends => ((Signature, Length) => (Key_State, Digest));

   --  Securely wipe the loaded key.
   procedure Wipe
   with Global => (Output => Key_State), Depends => (Key_State => null);

   --  BIP32 helper: scalar add modulo secp256k1 group order n.
   --  In-place: Scalar := (Scalar + Tweak) mod n.
   --  Ok = False if either operand is >= n or the result is zero.
   --
   --  Provided here because Signing is the only module that talks to
   --  libsecp256k1 (architecture invariant #3). Key_Derivation calls this
   --  to compute non-hardened BIP32 child privkeys. The operation touches
   --  caller-provided buffers only — Key_State is NOT read or written, so
   --  the key-isolation flow proof is unaffected.
   procedure Tweak_Add_Scalar
     (Scalar : in out Hadawallet.Privkey_Bytes;
      Tweak  : in Hadawallet.Privkey_Bytes;
      Ok     : out Boolean)
   with Global => null, Depends => ((Scalar, Ok) => (Scalar, Tweak));

   --  Derive the compressed (33-byte) public key for a caller-provided
   --  privkey via libsecp256k1. Public keys are public information; this
   --  does NOT read Key_State. Used by Key_Derivation for non-hardened
   --  BIP32 CKDpriv (which needs the parent's pubkey as HMAC input).
   procedure Pubkey_From_Privkey
     (Privkey : in Hadawallet.Privkey_Bytes;
      Pubkey  : out Hadawallet.Pubkey_Bytes;
      Ok      : out Boolean)
   with Global => null, Depends => ((Pubkey, Ok) => Privkey);

end Signing;
