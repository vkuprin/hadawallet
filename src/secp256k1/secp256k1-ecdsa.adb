--  Secp256k1.Ecdsa body — Phase D skeleton.

pragma Style_Checks ("-s");

package body Secp256k1.Ecdsa
  with SPARK_Mode => Off
is

   procedure Sign
     (Privkey : in     Hadawallet.Privkey_Bytes;
      Digest  : in     Hadawallet.Digest_Bytes;
      Sig     :    out Hadawallet.Signature_Bytes;
      Length  :    out Hadawallet.Signature_Length)
   is
      pragma Unreferenced (Privkey, Digest);
   begin
      Sig    := [others => 0];
      Length := 0;   --  TODO Phase D
   end Sign;

   procedure Pubkey_From_Privkey
     (Privkey : in     Hadawallet.Privkey_Bytes;
      Pubkey  :    out Hadawallet.Pubkey_Bytes;
      Ok      :    out Boolean)
   is
      pragma Unreferenced (Privkey);
   begin
      Pubkey := [others => 0];
      Ok     := False;   --  TODO Phase D
   end Pubkey_From_Privkey;

   procedure Tweak_Add_Scalar
     (Key   : in out Hadawallet.Privkey_Bytes;
      Tweak : in     Hadawallet.Privkey_Bytes;
      Ok    :    out Boolean)
   is
      pragma Unreferenced (Tweak);
   begin
      Key := [others => 0];
      Ok  := False;   --  TODO Phase D
   end Tweak_Add_Scalar;

end Secp256k1.Ecdsa;
