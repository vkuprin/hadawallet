--  Signing body — pure-SPARK backend (BACKEND=ada).
--
--  STATUS: Phase D skeleton. The Sign / Tweak_Add_Scalar /
--  Pubkey_From_Privkey procedures all return failure outputs because
--  Secp256k1.Field / .Scalar / .Group / .Ecdsa are not yet implemented
--  (see plan: D1 = 4–8 weeks, D2 = +3–4 weeks for SPARK Silver,
--  D3 = +2–3 weeks for constant-time hardening).
--
--  This body exists so that BACKEND=ada builds compile and link without
--  libsecp256k1 — required by the STM32 cross-compile path
--  (hadawallet_stm32.gpr) where bare-metal ARM has no libsecp256k1
--  binary available.
--
--  The Abstract_State / Refined_State / Global / Depends contracts on
--  Signing.* are identical to backend_c — only the body of each
--  procedure differs. The key-isolation flow proof carries through
--  unchanged: even though Sign returns 0 bytes, the contract
--  `(Signature, Length) => (Key_State, Digest)` is honored (Length=0
--  is a valid output, just unhelpful).

with Secp256k1;
pragma Unreferenced (Secp256k1);
--  Pulled in so that any future implementation can reach into the
--  child packages without changing this with clause; the unreferenced
--  pragma silences the warning until the implementation lands.

package body Signing
  with
    SPARK_Mode    => Off,
    Refined_State => (Key_State => (Stored_Key, Key_Is_Loaded))
is
   --  SPARK_Mode => Off on the body: this stub intentionally violates
   --  the spec's flow dependencies (Pubkey_From_Privkey returns zero
   --  Pubkey independent of Privkey; Tweak_Add_Scalar discards Tweak
   --  and zeros Scalar). The spec contracts stay SPARK_Mode => On so
   --  callers can prove against them. When Phase D lands, the body
   --  flips back to On and gains the same 22/22 (or higher) coverage
   --  as the c-backend.

   Stored_Key    : Hadawallet.Privkey_Bytes := [others => 0];
   Key_Is_Loaded : Boolean := False;

   procedure Load_Privkey (Key : in Hadawallet.Privkey_Bytes)
   with
     Refined_Global  => (Output => (Stored_Key, Key_Is_Loaded)),
     Refined_Depends => (Stored_Key => Key, Key_Is_Loaded => null)
   is
   begin
      Stored_Key := Key;
      Key_Is_Loaded := True;
   end Load_Privkey;

   function Has_Key return Boolean
   is (Key_Is_Loaded)
   with Refined_Global => (Input => Key_Is_Loaded);

   procedure Sign
     (Digest    : in Hadawallet.Digest_Bytes;
      Signature : out Hadawallet.Signature_Bytes;
      Length    : out Hadawallet.Signature_Length)
   with
     Refined_Global  => (Input => (Stored_Key, Key_Is_Loaded)),
     Refined_Depends =>
       ((Signature, Length) => (Stored_Key, Key_Is_Loaded, Digest))
   is
      pragma Unreferenced (Digest);
   begin
      Signature := [others => 0];
      Length := 0;
      --  TODO Phase D: call Secp256k1.Ecdsa.Sign (Stored_Key, Digest, ...).
   end Sign;

   procedure Wipe
   with
     Refined_Global  => (Output => (Stored_Key, Key_Is_Loaded)),
     Refined_Depends => ((Stored_Key, Key_Is_Loaded) => null)
   is
   begin
      Stored_Key := [others => 0];
      Key_Is_Loaded := False;
   end Wipe;

   procedure Tweak_Add_Scalar
     (Scalar : in out Hadawallet.Privkey_Bytes;
      Tweak  : in Hadawallet.Privkey_Bytes;
      Ok     : out Boolean)
   is
      pragma Unreferenced (Tweak);
   begin
      --  TODO Phase D: pure-SPARK scalar add mod n via Secp256k1.Scalar.
      --  Until then, zero the scalar and signal failure so any
      --  Key_Derivation non-hardened path aborts cleanly.
      Scalar := [others => 0];
      Ok := False;
   end Tweak_Add_Scalar;

   procedure Pubkey_From_Privkey
     (Privkey : in Hadawallet.Privkey_Bytes;
      Pubkey  : out Hadawallet.Pubkey_Bytes;
      Ok      : out Boolean)
   is
      pragma Unreferenced (Privkey);
   begin
      --  TODO Phase D: Pubkey := point_compress(privkey * G) via
      --  Secp256k1.Group.Scalar_Mul + Secp256k1.Group.Compressed.
      Pubkey := [others => 0];
      Ok := False;
   end Pubkey_From_Privkey;

end Signing;
