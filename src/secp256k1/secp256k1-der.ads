--  Secp256k1.Der — ASN.1 DER encoding for ECDSA signatures.
--
--  Format per BIP66 / SEC1 §C.5:
--    0x30 || total_len || 0x02 || r_len || r || 0x02 || s_len || s
--
--  r and s are encoded as DER INTEGERs:
--    - Strip leading 0x00 bytes EXCEPT when the next byte's high bit
--      is set (would otherwise flip sign in two's-complement reading).
--    - Prepend 0x00 if the first remaining byte's high bit is set.
--
--  Caller must enforce BIP62 low-s before calling — Encode_Signature
--  does NOT mutate (r, s) to flip s into the lower half.

with Hadawallet;

package Secp256k1.Der
  with SPARK_Mode => On
is

   procedure Encode_Signature
     (R       : in     Hadawallet.Byte_Array;
      S       : in     Hadawallet.Byte_Array;
      DER_Out :    out Hadawallet.Signature_Bytes;
      Length  :    out Hadawallet.Signature_Length)
   with Pre     => R'Length = 32 and S'Length = 32,
        Global  => null,
        Depends => ((DER_Out, Length) => (R, S));

end Secp256k1.Der;
