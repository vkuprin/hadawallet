--  Secp256k1.Group body — Phase D skeleton.

pragma Style_Checks ("-s");

package body Secp256k1.Group
  with SPARK_Mode => Off
is

   function Generator return Affine_Point is
   begin
      --  TODO Phase D: encode G_x, G_y as Field_Element and return
      --  with Infinity => False.
      return (X => Secp256k1.Field.Zero,
              Y => Secp256k1.Field.Zero,
              Infinity => True);
   end Generator;

   procedure From_Compressed
     (Bytes : in     Hadawallet.Byte_Array;
      P     :    out Affine_Point;
      Ok    :    out Boolean)
   is
      pragma Unreferenced (Bytes);
   begin
      P := (X => Secp256k1.Field.Zero,
            Y => Secp256k1.Field.Zero,
            Infinity => True);
      Ok := False;   --  TODO Phase D
   end From_Compressed;

   procedure To_Compressed
     (P     : in     Affine_Point;
      Bytes :    out Hadawallet.Byte_Array;
      Ok    :    out Boolean)
   is
      pragma Unreferenced (P);
   begin
      Bytes := [Bytes'Range => 0];
      Ok := False;   --  TODO Phase D
   end To_Compressed;

   procedure Scalar_Mul
     (K  : in     Hadawallet.Byte_Array;
      R  :    out Affine_Point;
      Ok :    out Boolean)
   is
      pragma Unreferenced (K);
   begin
      R := (X => Secp256k1.Field.Zero,
            Y => Secp256k1.Field.Zero,
            Infinity => True);
      Ok := False;   --  TODO Phase D
   end Scalar_Mul;

end Secp256k1.Group;
