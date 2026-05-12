pragma Warnings (Off);
pragma Ada_95;
pragma Source_File_Name (ada_main, Spec_File_Name => "b__main_stm32.ads");
pragma Source_File_Name (ada_main, Body_File_Name => "b__main_stm32.adb");
pragma Suppress (Overflow_Check);

package body ada_main is

   E05 : Short_Integer; pragma Import (Ada, E05, "hashing_E");
   E08 : Short_Integer; pragma Import (Ada, E08, "startup_stm32f411_E");
   E10 : Short_Integer; pragma Import (Ada, E10, "uart_E");


   procedure adainit is
   begin
      null;

      E05 := E05 + 1;
      Startup_Stm32f411'Elab_Body;
      E08 := E08 + 1;
      E10 := E10 + 1;
   end adainit;

   procedure Ada_Main_Program;
   pragma Import (Ada, Ada_Main_Program, "_ada_main_stm32");

   procedure main is
      Ensure_Reference : aliased System.Address := Ada_Main_Program_Name'Address;
      pragma Volatile (Ensure_Reference);

   begin
      adainit;
      Ada_Main_Program;
   end;

--  BEGIN Object file/option list
   --   /work/obj-stm32/hadawallet.o
   --   /work/obj-stm32/hashing.o
   --   /work/obj-stm32/startup_stm32f411.o
   --   /work/obj-stm32/uart.o
   --   /work/obj-stm32/main_stm32.o
   --   -L/work/obj-stm32/
   --   -L/work/obj-stm32/
   --   -L/root/.local/share/alire/toolchains/gnat_arm_elf_15.2.1_a5e9cfb1/arm-eabi/lib/gnat/light-cortex-m4f/adalib/
   --   -static
   --   -lgnat
--  END Object file/option list   

end ada_main;
