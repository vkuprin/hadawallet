--  Uart body — STM32F411 USART2 polling driver.
--
--  MMIO is wired via the Ada-standard `Address => ...` aspect with
--  `Volatile` so the compiler doesn't elide reads/writes. No
--  Unchecked_Conversion, no access types — works under any GNAT
--  optimization level.

pragma Style_Checks ("-s");

with System;
with System.Storage_Elements;
with Interfaces;

package body Uart
  with SPARK_Mode => Off
is

   use System.Storage_Elements;
   use type Interfaces.Unsigned_32;

   subtype U32 is Interfaces.Unsigned_32;

   --  RM0383 register addresses (STM32F411xE).
   RCC_AHB1ENR : U32 with
     Volatile, Atomic, Async_Readers, Async_Writers,
     Address => To_Address (16#4002_3830#);
   RCC_APB1ENR : U32 with
     Volatile, Atomic, Async_Readers, Async_Writers,
     Address => To_Address (16#4002_3840#);
   GPIOA_MODER : U32 with
     Volatile, Atomic, Async_Readers, Async_Writers,
     Address => To_Address (16#4002_0000#);
   GPIOA_AFRL  : U32 with
     Volatile, Atomic, Async_Readers, Async_Writers,
     Address => To_Address (16#4002_0020#);
   USART2_BRR  : U32 with
     Volatile, Atomic, Async_Readers, Async_Writers,
     Address => To_Address (16#4000_4408#);
   USART2_CR1  : U32 with
     Volatile, Atomic, Async_Readers, Async_Writers,
     Address => To_Address (16#4000_440C#);
   USART2_SR   : U32 with
     Volatile, Atomic, Async_Readers, Async_Writers,
     Address => To_Address (16#4000_4400#);
   USART2_DR   : U32 with
     Volatile, Atomic, Async_Readers, Async_Writers,
     Address => To_Address (16#4000_4404#);

   procedure Init is
   begin
      --  Enable clocks: GPIOA (AHB1ENR bit 0), USART2 (APB1ENR bit 17).
      RCC_AHB1ENR := RCC_AHB1ENR or 16#0000_0001#;
      RCC_APB1ENR := RCC_APB1ENR or 16#0002_0000#;

      --  PA2 / PA3 to alternate-function mode (MODER = 0b10 per pin).
      GPIOA_MODER := (GPIOA_MODER and not 16#0000_00F0#) or 16#0000_00A0#;

      --  AFRL: AF7 = USART2 for PA2/PA3 (4 bits each, slots 2 and 3).
      GPIOA_AFRL := (GPIOA_AFRL and not 16#0000_FF00#) or 16#0000_7700#;

      --  Baud: BRR = fck / baud at OVER8=0. fck = HSI = 16 MHz default.
      --  16_000_000 / 115_200 ≈ 138.89 → 0x8B (139). Mantissa 8, frac 11.
      USART2_BRR := 16#008B#;

      --  CR1: UE | TE (USART enable, transmitter enable).
      USART2_CR1 := 16#0000_2008#;
   end Init;

   procedure Tx_Byte (B : Hadawallet.U8) is
   begin
      --  Spin until TXE (SR bit 7) goes high.
      loop
         exit when (USART2_SR and 16#0000_0080#) /= 0;
      end loop;
      USART2_DR := U32 (B);
   end Tx_Byte;

   procedure Tx_String (S : String) is
   begin
      for I in S'Range loop
         Tx_Byte (Hadawallet.U8 (Character'Pos (S (I))));
      end loop;
   end Tx_String;

end Uart;
