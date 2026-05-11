--  Signing body — v0.1 (Phase 2: SPARK flow proof landed).
--
--  Body is SPARK_Mode => On so the Global/Depends contracts declared in
--  the spec are verified by gnatprove. The libsecp256k1 binding (Phase 5)
--  will replace the deterministic v0.1 "signature" below; the flow shape
--  (Signature depends on Stored_Key and Digest) is already correct, so
--  the FFI swap won't perturb the proof.

package body Signing
  with
    SPARK_Mode    => On,
    Refined_State => (Key_State => (Stored_Key, Key_Is_Loaded))
is

   use type Hadawallet.U8;

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
       (Signature => (Stored_Key, Key_Is_Loaded, Digest),
        Length    => Key_Is_Loaded)
   is
   begin
      Signature := [others => 0];
      if Key_Is_Loaded then
         --  v0.1 stub: deterministic non-cryptographic placeholder.
         --  Real ECDSA via libsecp256k1 lands in Phase 5; the flow
         --  contract (Signature depends on Stored_Key and Digest) is
         --  enforced *now* so swapping the body for the FFI call later
         --  is a one-place edit with no proof regression.
         for I in Stored_Key'Range loop
            Signature (I) := Stored_Key (I) xor Digest (I);
         end loop;
         Length := Stored_Key'Length;
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

end Signing;
