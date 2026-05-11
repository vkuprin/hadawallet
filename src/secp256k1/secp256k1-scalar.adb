--  Secp256k1.Scalar body — Phase D skeleton.

pragma Style_Checks ("-s");

package body Secp256k1.Scalar
  with SPARK_Mode => Off
is

   procedure From_Be32
     (Bytes : in     Hadawallet.Byte_Array;
      S     :    out Scalar_Element;
      Ok    :    out Boolean)
   is
      pragma Unreferenced (Bytes);
   begin
      S := Zero;
      Ok := False;   --  TODO Phase D
   end From_Be32;

   procedure To_Be32
     (S     : in     Scalar_Element;
      Bytes :    out Hadawallet.Byte_Array)
   is
      pragma Unreferenced (S);
   begin
      Bytes := [Bytes'Range => 0];   --  TODO Phase D
   end To_Be32;

   procedure Add (A, B : in Scalar_Element; R : out Scalar_Element) is
      pragma Unreferenced (A, B);
   begin
      R := Zero;   --  TODO Phase D
   end Add;

   procedure Mul (A, B : in Scalar_Element; R : out Scalar_Element) is
      pragma Unreferenced (A, B);
   begin
      R := Zero;   --  TODO Phase D
   end Mul;

   procedure Inv
     (A : in Scalar_Element; R : out Scalar_Element; Ok : out Boolean)
   is
      pragma Unreferenced (A);
   begin
      R := Zero;
      Ok := False;   --  TODO Phase D
   end Inv;

   function In_Range_1_To_N_Minus_1 (A : Scalar_Element) return Boolean is
      pragma Unreferenced (A);
   begin
      return False;   --  TODO Phase D
   end In_Range_1_To_N_Minus_1;

end Secp256k1.Scalar;
