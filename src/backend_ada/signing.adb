--  Signing body — pure-SPARK backend (BACKEND=ada).
--
--  Delegates the three cryptographic primitives to Secp256k1.Ecdsa.
--  Today Ecdsa.* are stubs (return failure outputs); when Phase D
--  lands, this body needs no further changes. The key-isolation
--  abstraction stays here: Stored_Key never leaves this package
--  body, and the only function that reads it is Sign.

with Secp256k1.Ecdsa;

package body Signing
  with
    SPARK_Mode    => Off,
    Refined_State => (Key_State => (Stored_Key, Key_Is_Loaded))
is
   --  SPARK_Mode => Off on the body until Phase D's curve math passes
   --  proof at Silver — see plan. Spec-level flow contracts remain
   --  SPARK_Mode => On so callers can prove against them today.

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
   begin
      Signature := [others => 0];
      if Key_Is_Loaded then
         Secp256k1.Ecdsa.Sign (Stored_Key, Digest, Signature, Length);
      else
         Length := 0;
      end if;
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
   begin
      Secp256k1.Ecdsa.Tweak_Add_Scalar (Scalar, Tweak, Ok);
   end Tweak_Add_Scalar;

   procedure Pubkey_From_Privkey
     (Privkey : in Hadawallet.Privkey_Bytes;
      Pubkey  : out Hadawallet.Pubkey_Bytes;
      Ok      : out Boolean)
   is
   begin
      Secp256k1.Ecdsa.Pubkey_From_Privkey (Privkey, Pubkey, Ok);
   end Pubkey_From_Privkey;

end Signing;
