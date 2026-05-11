--  Hashing — cryptographic hash primitives.
--
--  Spec is SPARK_Mode => On with explicit Global => null contracts so callers
--  can prove their own flow contracts against this module. Bodies are
--  SPARK_Mode => Off in v0.1 — the implementations are pure-Ada and pure
--  functions of their inputs (no hidden state), but SPARK Gold proofs on the
--  bit-twiddling loops are deferred. Functional correctness is established by
--  the test-vector suite in tests/test_hashing.adb.

with Hadawallet;

package Hashing
  with SPARK_Mode => On
is

   --  SHA-256 of arbitrary-length input.
   procedure SHA256
     (Input : in Hadawallet.Byte_Array; Out_Hash : out Hadawallet.Digest_Bytes)
   with Global => null, Depends => (Out_Hash => Input);

   --  HMAC-SHA512 (RFC 4231).
   procedure HMAC_SHA512
     (Key : in Hadawallet.Byte_Array;
      Msg : in Hadawallet.Byte_Array;
      Mac : out Hadawallet.Mac_Bytes_512)
   with Global => null, Depends => (Mac => (Key, Msg));

   --  RIPEMD-160 — used only as the inner of Hash160.
   procedure RIPEMD160
     (Input    : in Hadawallet.Byte_Array;
      Out_Hash : out Hadawallet.Hash160_Bytes)
   with Global => null, Depends => (Out_Hash => Input);

   --  Hash160(x) = RIPEMD-160(SHA-256(x)). Bitcoin pubkey hash.
   procedure Hash160
     (Input    : in Hadawallet.Byte_Array;
      Out_Hash : out Hadawallet.Hash160_Bytes)
   with Global => null, Depends => (Out_Hash => Input);

end Hashing;
