--  UART — minimal blocking USART2 driver for the STM32F411 Nucleo.
--
--  USART2 is wired to the onboard ST-Link USB virtual COM port via
--  PA2 (TX) and PA3 (RX). At default reset clock (HSI = 16 MHz, no
--  PLL) USART_BRR = 16_000_000 / 115_200 ≈ 138.89; we round to 139
--  (0x8B) which gives an actual baud of about 115_108 — well within
--  the ±2% tolerance for USB serial.
--
--  This is a polling-only driver (no DMA, no interrupts). It exists
--  to demonstrate the cross-compile toolchain works end-to-end and
--  to give Phase C's compile-only firmware something to print.

with Hadawallet;

package Uart
  with SPARK_Mode => On
is

   --  Configure GPIO PA2/PA3 for USART2 alternate function 7 (USART2)
   --  and program USART2 for 115_200 8N1. Must be called once before
   --  Tx_Byte / Tx_String.
   procedure Init
     with Global => null;

   procedure Tx_Byte (B : Hadawallet.U8)
     with Global => null;

   procedure Tx_String (S : String)
     with Global => null;

end Uart;
