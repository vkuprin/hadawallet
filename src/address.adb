--  Address body — BIP173 bech32 encoding for P2WPKH segwit v0.
--
--  SPARK_Mode => Off: pure-Ada implementation. Spec retains Global => null
--  / Depends contracts so callers can prove flow against this module.
--  Test vectors (BIP173) live in tests/test_bech32.adb (Phase 8).

pragma Style_Checks ("-s");

with Interfaces; use Interfaces;
with Hashing;

package body Address
  with SPARK_Mode => Off
is

   Charset : constant String := "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

   GEN : constant array (0 .. 4) of Unsigned_32 :=
     [16#3b6a57b2#, 16#26508e6d#, 16#1ea119fa#, 16#3d4233dd#, 16#2a1462b3#];

   function Polymod (Values : Hadawallet.Byte_Array) return Unsigned_32 is
      Chk : Unsigned_32 := 1;
      B   : Unsigned_32;
   begin
      for V of Values loop
         B := Shift_Right (Chk, 25);
         Chk := Shift_Left (Chk and 16#1FFFFFF#, 5) xor Unsigned_32 (V);
         for I in 0 .. 4 loop
            if (Shift_Right (B, I) and 1) /= 0 then
               Chk := Chk xor GEN (I);
            end if;
         end loop;
      end loop;
      return Chk;
   end Polymod;

   function HRP_For (Net : Hadawallet.Network) return String
   is (case Net is
         when Hadawallet.Bitcoin_Mainnet => "bc",
         when Hadawallet.Bitcoin_Testnet => "tb",
         when Hadawallet.Bitcoin_Regtest => "bcrt");

   procedure Pubkey_To_Address
     (Pubkey : in Hadawallet.Pubkey_Bytes;
      Net    : in Hadawallet.Network;
      Output : out String;
      Length : out Hadawallet.Address_Length;
      Ok     : out Boolean)
   is
      Hrp  : constant String := HRP_For (Net);
      Hash : Hadawallet.Hash160_Bytes;

      --  P2WPKH data payload: [witness_version=0] || 32 base32 groups
      --  derived from the 160-bit hash. 20 bytes * 8 = 160 = 32 * 5,
      --  so no padding bits.
      Data : Hadawallet.Byte_Array (1 .. 33);
      Acc  : Unsigned_32 := 0;
      Bits : Natural := 0;
      Idx  : Positive := 2;

      --  Polymod input: HRP-high || 0 || HRP-low || Data || 6 zeros.
      --  Max layout (regtest): 4 + 1 + 4 + 33 + 6 = 48 bytes.
      Pm_Buf : Hadawallet.Byte_Array (1 .. 2 * Hrp'Length + 1 + 39);
      Pm_Idx : Positive := 1;
      Pm     : Unsigned_32;

      Checksum : Hadawallet.Byte_Array (1 .. 6);

      --  Final string layout: HRP || "1" || 33 data chars || 6 checksum chars.
      Out_Len : constant Natural := Hrp'Length + 1 + 33 + 6;
   begin
      Output := [Output'Range => ' '];
      Length := 0;
      Ok := False;

      if Output'Length < Out_Len then
         return;
      end if;

      --  1. Hash160 of compressed pubkey.
      Hashing.Hash160 (Hadawallet.Byte_Array (Pubkey), Hash);

      --  2. Witness version byte.
      Data (1) := 0;

      --  3. Convert hash (8-bit) → 5-bit groups, MSB-first.
      for B of Hash loop
         Acc := Shift_Left (Acc, 8) or Unsigned_32 (B);
         Bits := Bits + 8;
         while Bits >= 5 loop
            Bits := Bits - 5;
            Data (Idx) := Hadawallet.U8 (Shift_Right (Acc, Bits) and 16#1F#);
            Idx := Idx + 1;
         end loop;
      end loop;

      --  4. Build polymod input: HRP high half, separator zero, HRP low half,
      --     data, 6 trailing zeros.
      for I in Hrp'Range loop
         Pm_Buf (Pm_Idx) :=
           Hadawallet.U8
             (Shift_Right (Unsigned_32 (Character'Pos (Hrp (I))), 5));
         Pm_Idx := Pm_Idx + 1;
      end loop;
      Pm_Buf (Pm_Idx) := 0;
      Pm_Idx := Pm_Idx + 1;
      for I in Hrp'Range loop
         Pm_Buf (Pm_Idx) :=
           Hadawallet.U8 (Unsigned_32 (Character'Pos (Hrp (I))) and 16#1F#);
         Pm_Idx := Pm_Idx + 1;
      end loop;
      for D of Data loop
         Pm_Buf (Pm_Idx) := D;
         Pm_Idx := Pm_Idx + 1;
      end loop;
      for I in 1 .. 6 loop
         Pm_Buf (Pm_Idx) := 0;
         Pm_Idx := Pm_Idx + 1;
      end loop;

      --  5. Compute checksum = polymod xor 1, split into 6 5-bit chunks.
      Pm := Polymod (Pm_Buf) xor 1;
      for I in 0 .. 5 loop
         Checksum (Positive (I + 1)) :=
           Hadawallet.U8 (Shift_Right (Pm, 5 * (5 - I)) and 16#1F#);
      end loop;

      --  6. Assemble final string: HRP || "1" || charset[Data] || charset[CS].
      declare
         O : Positive := Output'First;
      begin
         for C of Hrp loop
            Output (O) := C;
            O := O + 1;
         end loop;
         Output (O) := '1';
         O := O + 1;
         for D of Data loop
            Output (O) := Charset (Natural (D) + Charset'First);
            O := O + 1;
         end loop;
         for D of Checksum loop
            Output (O) := Charset (Natural (D) + Charset'First);
            O := O + 1;
         end loop;
      end;

      Length := Out_Len;
      Ok := True;
   end Pubkey_To_Address;

end Address;
