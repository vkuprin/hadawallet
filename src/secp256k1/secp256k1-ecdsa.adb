--  Secp256k1.Ecdsa body — partial Phase D.
--
--  Privkey validation (range [1, n-1]) IS implemented via Scalar —
--  the ada-backend now correctly REJECTS invalid keys even though it
--  cannot yet produce signatures. Sign / Pubkey_From_Privkey /
--  Tweak_Add_Scalar return failure outputs after validation; the
--  actual scalar multiplication and DER pipeline lands when
--  Secp256k1.Field.Mul / Sqr / Inv + Secp256k1.Group.Scalar_Mul ship.

pragma Style_Checks ("-s");

with Secp256k1.Scalar;
with Secp256k1.Group;

package body Secp256k1.Ecdsa
  with SPARK_Mode => Off
is

   --  Returns True iff Bytes encode a scalar in [1, n-1].
   function Privkey_In_Range (Bytes : Hadawallet.Byte_Array) return Boolean;
   function Privkey_In_Range (Bytes : Hadawallet.Byte_Array) return Boolean is
      S      : Secp256k1.Scalar.Scalar_Element;
      Ok     : Boolean;
   begin
      Secp256k1.Scalar.From_Be32 (Bytes, S, Ok);
      if not Ok then
         return False;   --  >= n
      end if;
      return Secp256k1.Scalar.In_Range_1_To_N_Minus_1 (S);
   end Privkey_In_Range;

   procedure Sign
     (Privkey : in     Hadawallet.Privkey_Bytes;
      Digest  : in     Hadawallet.Digest_Bytes;
      Sig     :    out Hadawallet.Signature_Bytes;
      Length  :    out Hadawallet.Signature_Length)
   is
      pragma Unreferenced (Digest);
   begin
      Sig := [others => 0];
      if not Privkey_In_Range (Hadawallet.Byte_Array (Privkey)) then
         Length := 0;
         return;
      end if;
      --  TODO Phase D: RFC 6979 nonce → Group.Scalar_Mul(k, G) →
      --  r = R.x mod n; s = k^{-1}(z + r·d) mod n; BIP62 low-s;
      --  Der.Encode_Signature (r_bytes, s_bytes, Sig, Length).
      Length := 0;
   end Sign;

   procedure Pubkey_From_Privkey
     (Privkey : in     Hadawallet.Privkey_Bytes;
      Pubkey  :    out Hadawallet.Pubkey_Bytes;
      Ok      :    out Boolean)
   is
      P    : Secp256k1.Group.Affine_Point;
      OkM  : Boolean;
      OkC  : Boolean;
   begin
      Pubkey := [others => 0];
      if not Privkey_In_Range (Hadawallet.Byte_Array (Privkey)) then
         Ok := False;
         return;
      end if;

      Secp256k1.Group.Scalar_Mul
        (Hadawallet.Byte_Array (Privkey), P, OkM);
      if not OkM then
         Ok := False;
         return;
      end if;

      Secp256k1.Group.To_Compressed
        (P, Hadawallet.Byte_Array (Pubkey), OkC);
      Ok := OkC;
   end Pubkey_From_Privkey;

   procedure Tweak_Add_Scalar
     (Key   : in out Hadawallet.Privkey_Bytes;
      Tweak : in     Hadawallet.Privkey_Bytes;
      Ok    :    out Boolean)
   is
      S_Key, S_Tweak, S_Sum : Secp256k1.Scalar.Scalar_Element;
      Key_Ok, Tweak_Ok      : Boolean;
   begin
      Secp256k1.Scalar.From_Be32 (Hadawallet.Byte_Array (Key), S_Key,
                                   Key_Ok);
      Secp256k1.Scalar.From_Be32 (Hadawallet.Byte_Array (Tweak), S_Tweak,
                                   Tweak_Ok);
      if not Key_Ok or not Tweak_Ok then
         Key := [others => 0];
         Ok := False;
         return;
      end if;

      Secp256k1.Scalar.Add (S_Key, S_Tweak, S_Sum);

      --  Result must remain in [1, n-1] per BIP32 §"Private parent ->
      --  private child key".
      if not Secp256k1.Scalar.In_Range_1_To_N_Minus_1 (S_Sum) then
         Key := [others => 0];
         Ok := False;
         return;
      end if;

      Secp256k1.Scalar.To_Be32 (S_Sum, Hadawallet.Byte_Array (Key));
      Ok := True;
   end Tweak_Add_Scalar;

end Secp256k1.Ecdsa;
