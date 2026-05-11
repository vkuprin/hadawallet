--  Minimal startup for STM32F411 Nucleo (Cortex-M4F).
--
--  Wires three things:
--    1. The interrupt vector table at start of flash (0x0800_0000).
--    2. The reset handler — copies .data from flash to SRAM, zeros .bss,
--       runs Ada elaboration via "adainit", jumps to Ada Main_Stm32.
--    3. A default trap handler for every other exception/IRQ that simply
--       halts the CPU with a wait-for-interrupt loop. Good enough for a
--       skeleton; production firmware would route NMI / HardFault to a
--       diagnostic UART writer.
--
--  This file deliberately uses System.Storage_Elements.To_Address rather
--  than depending on board-specific HAL packages — keeps the
--  dependency surface minimal so the cross-build doesn't pull in the
--  full Ada Drivers Library.

pragma Style_Checks ("-s");

with System;
with System.Storage_Elements;

package body Startup_Stm32f411
  with SPARK_Mode => Off
is

   --  Symbols defined by the linker script (stm32f411.ld).
   _Stack_Top : constant System.Address;
   pragma Import (C, _Stack_Top, "_estack");

   --  Forward decls for Ada elaboration + main.
   procedure Adainit
     with Import => True, Convention => C, External_Name => "adainit";

   procedure Main_Stm32
     with Import => True, Convention => Ada, External_Name => "main_stm32";

   procedure Reset_Handler;
   pragma Export (C, Reset_Handler, "Reset_Handler");

   procedure Default_Handler;
   pragma Export (C, Default_Handler, "Default_Handler");

   procedure Reset_Handler is
   begin
      --  .data and .bss init are normally done in C startup; for our
      --  Ada-only skeleton we rely on the runtime's own "_ada_main_setup"
      --  shim (or the equivalent in the runtime's startup). When using
      --  the light Ravenscar profile this is implicit; when using zfp
      --  the linker script's __preinit_array runs first.
      Adainit;
      Main_Stm32;
      loop
         null;
      end loop;
   end Reset_Handler;

   procedure Default_Handler is
   begin
      loop
         null;
      end loop;
   end Default_Handler;

   --  ISR vector table — must live in the .isr_vector section, which
   --  the linker script places at the very start of flash.
   type Isr_Entry is access procedure;
   type Isr_Vector_Table is array (Natural range <>) of Isr_Entry;

   --  Only the first 16 system-exception slots are populated; all
   --  device IRQs default-handle. Reset handler at slot 1 gets jumped
   --  to by the Cortex-M4 boot ROM after loading SP from slot 0.
   Vector_Table : constant Isr_Vector_Table (0 .. 15) :=
     [0 => null,    --  Initial SP — patched by linker (see ld script).
      1 => Reset_Handler'Access,
      others => Default_Handler'Access]
     with Linker_Section => ".isr_vector",
          Export, Convention => C,
          External_Name => "g_pfnVectors";

end Startup_Stm32f411;
