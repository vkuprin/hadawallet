--  Signing body — v0.1 stub.
--
--  SPARK_Mode is Off on the body until the libsecp256k1 binding lands
--  in week 3. The spec is SPARK_Mode On so callers are still proven
--  against the isolation API: no caller can extract key bytes from this
--  module by construction.

package body Signing
  with SPARK_Mode => Off
is

   use type Hadawallet.U8;

   Stored_Key    : Hadawallet.Privkey_Bytes := [others => 0];
   Key_Is_Loaded : Boolean                  := False;

   procedure Load_Privkey (Key : in Hadawallet.Privkey_Bytes) is
   begin
      Stored_Key    := Key;
      Key_Is_Loaded := True;
   end Load_Privkey;

   function Has_Key return Boolean is (Key_Is_Loaded);

   procedure Sign
     (Digest    : in     Hadawallet.Digest_Bytes;
      Signature :    out Hadawallet.Signature_Bytes;
      Length    :    out Hadawallet.Signature_Length)
   is
   begin
      --  STUB. Real implementation lands week 3 (libsecp256k1 binding).
      Signature := [others => 0];
      Length    := 0;
      --  Touch Digest to silence unused-warning until real impl lands.
      if Digest (Digest'First) = 0 then
         null;
      end if;
   end Sign;

   procedure Wipe is
   begin
      Stored_Key    := [others => 0];
      Key_Is_Loaded := False;
   end Wipe;

end Signing;
