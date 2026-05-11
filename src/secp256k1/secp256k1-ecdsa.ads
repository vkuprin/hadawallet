--  Secp256k1.Ecdsa — sign + pubkey-from-priv.
--
--  STATUS: Phase D skeleton. RFC 6979 deterministic nonce + scalar mul
--  + DER encoding (the latter is real today — see Secp256k1.Der).

with Hadawallet;

package Secp256k1.Ecdsa
  with SPARK_Mode => On
is

   --  RFC 6979 deterministic ECDSA sign.
   --  Output is DER-encoded with BIP62 low-s normalization applied.
   --  Length = 0 indicates failure (privkey out of range, internal
   --  arithmetic failure, or backend stub).
   procedure Sign
     (Privkey : in     Hadawallet.Privkey_Bytes;
      Digest  : in     Hadawallet.Digest_Bytes;
      Sig     :    out Hadawallet.Signature_Bytes;
      Length  :    out Hadawallet.Signature_Length)
   with Global  => null,
        Depends => ((Sig, Length) => (Privkey, Digest));

   --  Derive compressed pubkey from privkey via Group.Scalar_Mul.
   procedure Pubkey_From_Privkey
     (Privkey : in     Hadawallet.Privkey_Bytes;
      Pubkey  :    out Hadawallet.Pubkey_Bytes;
      Ok      :    out Boolean)
   with Global  => null,
        Depends => ((Pubkey, Ok) => Privkey);

   --  Scalar tweak-add: Out_Key := (In_Key + Tweak) mod n. Used by
   --  BIP32 non-hardened CKDpriv.
   procedure Tweak_Add_Scalar
     (Key   : in out Hadawallet.Privkey_Bytes;
      Tweak : in     Hadawallet.Privkey_Bytes;
      Ok    :    out Boolean)
   with Global  => null,
        Depends => ((Key, Ok) => (Key, Tweak));

end Secp256k1.Ecdsa;
