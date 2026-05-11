--  Secp256k1.Der body.

pragma Style_Checks ("-s");

package body Secp256k1.Der
  with SPARK_Mode => Off
is

   use type Hadawallet.U8;

   --  Compute (start_offset, length) of the minimal DER INTEGER body
   --  inside Buf (32 bytes, big-endian). Returned length includes the
   --  optional leading 0x00 padding byte.
   procedure Compute_Int
     (Buf      : in  Hadawallet.Byte_Array;
      Start    : out Natural;
      Pad_Zero : out Boolean;
      Body_Len : out Natural);
   procedure Compute_Int
     (Buf      : in  Hadawallet.Byte_Array;
      Start    : out Natural;
      Pad_Zero : out Boolean;
      Body_Len : out Natural)
   is
      I : Natural := Buf'First;
   begin
      --  Strip leading 0x00 bytes (but keep at least one).
      while I < Buf'Last and then Buf (I) = 0 loop
         I := I + 1;
      end loop;
      Start := I;
      Pad_Zero := Buf (I) >= 16#80#;
      Body_Len := Buf'Last - I + 1 + (if Pad_Zero then 1 else 0);
   end Compute_Int;

   procedure Encode_Signature
     (R       : in     Hadawallet.Byte_Array;
      S       : in     Hadawallet.Byte_Array;
      DER_Out :    out Hadawallet.Signature_Bytes;
      Length  :    out Hadawallet.Signature_Length)
   is
      R_Start, S_Start         : Natural;
      R_Pad,   S_Pad           : Boolean;
      R_Len,   S_Len           : Natural;
      Total                    : Natural;
      Idx                      : Positive;
   begin
      DER_Out := [others => 0];
      Length := 0;

      Compute_Int (R, R_Start, R_Pad, R_Len);
      Compute_Int (S, S_Start, S_Pad, S_Len);

      --  Sanity: r and s body lengths fit in a single varint and the
      --  total signature fits the 72-byte buffer.
      if R_Len > 33 or S_Len > 33 then
         return;
      end if;

      Total := 2 + R_Len + 2 + S_Len;
      if 2 + Total > 72 then
         return;
      end if;

      Idx := DER_Out'First;
      DER_Out (Idx) := 16#30#;        Idx := Idx + 1;          --  SEQUENCE
      DER_Out (Idx) := Hadawallet.U8 (Total); Idx := Idx + 1;  --  total len

      DER_Out (Idx) := 16#02#;        Idx := Idx + 1;          --  INTEGER
      DER_Out (Idx) := Hadawallet.U8 (R_Len); Idx := Idx + 1;  --  r length
      if R_Pad then
         DER_Out (Idx) := 0; Idx := Idx + 1;
      end if;
      for J in R_Start .. R'Last loop
         DER_Out (Idx) := R (J);
         Idx := Idx + 1;
      end loop;

      DER_Out (Idx) := 16#02#;        Idx := Idx + 1;
      DER_Out (Idx) := Hadawallet.U8 (S_Len); Idx := Idx + 1;
      if S_Pad then
         DER_Out (Idx) := 0; Idx := Idx + 1;
      end if;
      for J in S_Start .. S'Last loop
         DER_Out (Idx) := S (J);
         Idx := Idx + 1;
      end loop;

      Length := Idx - DER_Out'First;
   end Encode_Signature;

end Secp256k1.Der;
