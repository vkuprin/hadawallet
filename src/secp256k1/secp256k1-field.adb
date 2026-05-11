--  Secp256k1.Field body — Phase D skeleton.

pragma Style_Checks ("-s");

package body Secp256k1.Field
  with SPARK_Mode => Off
is

   procedure From_Be32
     (Bytes : in     Hadawallet.Byte_Array;
      F     :    out Field_Element;
      Ok    :    out Boolean)
   is
      pragma Unreferenced (Bytes);
   begin
      F := Zero;
      Ok := False;   --  TODO Phase D
   end From_Be32;

   procedure To_Be32
     (F     : in     Field_Element;
      Bytes :    out Hadawallet.Byte_Array)
   is
      pragma Unreferenced (F);
   begin
      Bytes := [Bytes'Range => 0];   --  TODO Phase D
   end To_Be32;

   procedure Add (A, B : in Field_Element; R : out Field_Element) is
      pragma Unreferenced (A, B);
   begin
      R := Zero;   --  TODO Phase D
   end Add;

   procedure Sub (A, B : in Field_Element; R : out Field_Element) is
      pragma Unreferenced (A, B);
   begin
      R := Zero;   --  TODO Phase D
   end Sub;

   procedure Mul (A, B : in Field_Element; R : out Field_Element) is
      pragma Unreferenced (A, B);
   begin
      R := Zero;   --  TODO Phase D
   end Mul;

   procedure Sqr (A : in Field_Element; R : out Field_Element) is
      pragma Unreferenced (A);
   begin
      R := Zero;   --  TODO Phase D
   end Sqr;

   procedure Inv
     (A : in Field_Element; R : out Field_Element; Ok : out Boolean)
   is
      pragma Unreferenced (A);
   begin
      R := Zero;
      Ok := False;   --  TODO Phase D
   end Inv;

end Secp256k1.Field;
