--  Comm body — v0.1 stub.

with Ada.Text_IO;

package body Comm
  with SPARK_Mode => Off
is

   procedure Run is
   begin
      Ada.Text_IO.Put_Line ("hadawallet comm loop: stub (v0.1).");
      Ada.Text_IO.Put_Line ("PSBT-via-stdin handler lands week 3.");
   end Run;

end Comm;
