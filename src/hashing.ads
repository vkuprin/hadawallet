--  Hashing — pure-SPARK cryptographic hash primitives.
--
--  v0.1: API only. Pure-SPARK implementations land week 2.
--
--  Implementations target SPARK Gold: functional contracts asserting
--  output equals the canonical algorithm spec on test vectors.

with Hadawallet;

package Hashing
  with SPARK_Mode => On
is

   --  SHA-256 of arbitrary-length input.
   procedure SHA256
     (Input    : in     Hadawallet.Byte_Array;
      Out_Hash :    out Hadawallet.Digest_Bytes);

   --  HMAC-SHA512 (RFC 4231).
   procedure HMAC_SHA512
     (Key : in     Hadawallet.Byte_Array;
      Msg : in     Hadawallet.Byte_Array;
      Mac :    out Hadawallet.Mac_Bytes_512);

   --  RIPEMD-160 — used only as the inner of Hash160.
   procedure RIPEMD160
     (Input    : in     Hadawallet.Byte_Array;
      Out_Hash :    out Hadawallet.Hash160_Bytes);

   --  Hash160(x) = RIPEMD-160(SHA-256(x)). Bitcoin pubkey hash.
   procedure Hash160
     (Input    : in     Hadawallet.Byte_Array;
      Out_Hash :    out Hadawallet.Hash160_Bytes);

end Hashing;
