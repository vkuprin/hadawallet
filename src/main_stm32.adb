--  Main_Stm32 — STM32F411 Nucleo entry point.
--
--  Phase C "skeleton" deliverable: bring up USART2, print a banner,
--  run a SHA-256 self-test against the FIPS 180-4 vector, and halt.
--  No PSBT signing on hardware until Phase D ships pure-SPARK
--  secp256k1 (BACKEND=ada Signing currently returns Sig_Len=0; see
--  src/backend_ada/signing.adb).
--
--  Output (115200 8N1 on PA2 → ST-Link virtual COM):
--
--    hadawallet stm32f411 boot
--    sha256("abc") = ba7816bf...f20015ad
--    status: PASS
--    [signing backend: BACKEND=ada (stub) — see plan Phase D]

pragma Style_Checks ("-s");

with Hadawallet;
with Hashing;
with Uart;
with Startup_Stm32f411;
pragma Unreferenced (Startup_Stm32f411);
--  Forces the startup_stm32f411 unit (and its vector table) into the
--  link even though no symbol from it is referenced by name.

procedure Main_Stm32 is

   use type Hadawallet.U8;
   use type Hadawallet.Byte_Array;

   function Hex_Char (Nibble : Hadawallet.U8) return Character;
   function Hex_Char (Nibble : Hadawallet.U8) return Character is
      Tab : constant String := "0123456789abcdef";
   begin
      return Tab (Integer (Nibble) + 1);
   end Hex_Char;

   procedure Tx_Hex (Buf : Hadawallet.Byte_Array);
   procedure Tx_Hex (Buf : Hadawallet.Byte_Array) is
   begin
      for I in Buf'Range loop
         Uart.Tx_Byte (Hadawallet.U8 (Character'Pos
                         (Hex_Char (Buf (I) / 16))));
         Uart.Tx_Byte (Hadawallet.U8 (Character'Pos
                         (Hex_Char (Buf (I) mod 16))));
      end loop;
   end Tx_Hex;

   --  Expected SHA-256("abc") per FIPS 180-4.
   Expected : constant Hadawallet.Digest_Bytes :=
     [16#ba#, 16#78#, 16#16#, 16#bf#, 16#8f#, 16#01#, 16#cf#, 16#ea#,
      16#41#, 16#41#, 16#40#, 16#de#, 16#5d#, 16#ae#, 16#22#, 16#23#,
      16#b0#, 16#03#, 16#61#, 16#a3#, 16#96#, 16#17#, 16#7a#, 16#9c#,
      16#b4#, 16#10#, 16#ff#, 16#61#, 16#f2#, 16#00#, 16#15#, 16#ad#];

   Abc    : constant Hadawallet.Byte_Array := [16#61#, 16#62#, 16#63#];
   Digest : Hadawallet.Digest_Bytes;
begin
   Uart.Init;
   Uart.Tx_String ("hadawallet stm32f411 boot" & ASCII.CR & ASCII.LF);

   Hashing.SHA256 (Abc, Digest);
   Uart.Tx_String ("sha256(""abc"") = ");
   Tx_Hex (Hadawallet.Byte_Array (Digest));
   Uart.Tx_String ("" & ASCII.CR & ASCII.LF);

   if Digest = Expected then
      Uart.Tx_String ("status: PASS" & ASCII.CR & ASCII.LF);
   else
      Uart.Tx_String ("status: FAIL" & ASCII.CR & ASCII.LF);
   end if;

   Uart.Tx_String
     ("[signing backend: BACKEND=ada (stub) — see plan Phase D]"
      & ASCII.CR & ASCII.LF);

   loop
      null;
   end loop;
end Main_Stm32;
