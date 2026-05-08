--  Hashing body — v0.1 stubs.
--  Pure-SPARK implementations land week 2.

package body Hashing
  with SPARK_Mode => Off
is

   procedure SHA256
     (Input    : in     Hadawallet.Byte_Array;
      Out_Hash :    out Hadawallet.Digest_Bytes)
   is
   begin
      Out_Hash := [others => 0];
      if Input'Length = 0 then
         null;
      end if;
   end SHA256;

   procedure HMAC_SHA512
     (Key : in     Hadawallet.Byte_Array;
      Msg : in     Hadawallet.Byte_Array;
      Mac :    out Hadawallet.Mac_Bytes_512)
   is
   begin
      Mac := [others => 0];
      if Key'Length + Msg'Length = 0 then
         null;
      end if;
   end HMAC_SHA512;

   procedure RIPEMD160
     (Input    : in     Hadawallet.Byte_Array;
      Out_Hash :    out Hadawallet.Hash160_Bytes)
   is
   begin
      Out_Hash := [others => 0];
      if Input'Length = 0 then
         null;
      end if;
   end RIPEMD160;

   procedure Hash160
     (Input    : in     Hadawallet.Byte_Array;
      Out_Hash :    out Hadawallet.Hash160_Bytes)
   is
      Inner : Hadawallet.Digest_Bytes;
   begin
      SHA256 (Input, Inner);
      RIPEMD160 (Inner, Out_Hash);
   end Hash160;

end Hashing;
