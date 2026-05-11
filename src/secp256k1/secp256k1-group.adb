--  Secp256k1.Group body — affine arithmetic with double-and-add scalar mul.
--
--  STATUS: Phase D in progress.
--    Generator       : implemented (SEC 2 §2.4.1 constants).
--    To_Compressed   : implemented.
--    Scalar_Mul      : implemented (affine double-and-add).
--    From_Compressed : still TODO (needs sqrt mod p via Field.Pow).
--
--  Affine coords are simple but slow — every Add / Double costs one
--  Field.Inv (≈256 Sqr + 125 Mul). A future D3 pass should switch to
--  Jacobian during the scalar-mul loop with a single Inv at the end.
--  For v0.3 reference correctness, affine is the right call.

pragma Style_Checks ("-s");

package body Secp256k1.Group
  with SPARK_Mode => Off
is

   use type Hadawallet.U8;
   use type Hadawallet.U32;

   ---------------------------------------------------------------------
   --  Generator constant (per SEC 2 §2.4.1).
   --   Gx = 0x79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
   --   Gy = 0x483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
   ---------------------------------------------------------------------

   function Generator return Affine_Point is
      G : Affine_Point;
   begin
      G.X := (Limbs => [16#16F81798#, 16#59F2815B#, 16#2DCE28D9#,
                        16#029BFCDB#, 16#CE870B07#, 16#55A06295#,
                        16#F9DCBBAC#, 16#79BE667E#]);
      G.Y := (Limbs => [16#FB10D4B8#, 16#9C47D08F#, 16#A6855419#,
                        16#FD17B448#, 16#0E1108A8#, 16#5DA4FBFC#,
                        16#26A3C465#, 16#483ADA77#]);
      G.Infinity := False;
      return G;
   end Generator;

   ---------------------------------------------------------------------
   --  Helpers
   ---------------------------------------------------------------------

   --  P negation.
   procedure Negate_Point (P : Affine_Point; R : out Affine_Point);
   procedure Negate_Point (P : Affine_Point; R : out Affine_Point) is
   begin
      R.X := P.X;
      R.Infinity := P.Infinity;
      Secp256k1.Field.Sub (Secp256k1.Field.Zero, P.Y, R.Y);
   end Negate_Point;

   --  Point doubling: R := 2 * P.
   procedure Double_Point (P : Affine_Point; R : out Affine_Point);
   procedure Double_Point (P : Affine_Point; R : out Affine_Point) is
      Three  : constant Secp256k1.Field.Field_Element :=
        (Limbs => [3, 0, 0, 0, 0, 0, 0, 0]);
      Two    : constant Secp256k1.Field.Field_Element :=
        (Limbs => [2, 0, 0, 0, 0, 0, 0, 0]);
      X_Sqr  : Secp256k1.Field.Field_Element;
      Numer  : Secp256k1.Field.Field_Element;
      Denom  : Secp256k1.Field.Field_Element;
      Inv_D  : Secp256k1.Field.Field_Element;
      S      : Secp256k1.Field.Field_Element;
      S_Sqr  : Secp256k1.Field.Field_Element;
      Two_X  : Secp256k1.Field.Field_Element;
      Tmp    : Secp256k1.Field.Field_Element;
      Ok     : Boolean;
   begin
      if P.Infinity then
         R := P;   --  2 * O = O
         return;
      end if;

      --  P.Y = 0 implies the tangent is vertical → 2*P = O.
      if Secp256k1.Field.Compare (P.Y, Secp256k1.Field.Zero) = 0 then
         R := (X => Secp256k1.Field.Zero,
               Y => Secp256k1.Field.Zero,
               Infinity => True);
         return;
      end if;

      --  Slope s = (3 * x²) / (2 * y).
      Secp256k1.Field.Sqr (P.X, X_Sqr);
      Secp256k1.Field.Mul (Three, X_Sqr, Numer);
      Secp256k1.Field.Mul (Two, P.Y, Denom);
      Secp256k1.Field.Inv (Denom, Inv_D, Ok);
      Secp256k1.Field.Mul (Numer, Inv_D, S);

      --  R.X = s² - 2*x
      Secp256k1.Field.Sqr (S, S_Sqr);
      Secp256k1.Field.Mul (Two, P.X, Two_X);
      Secp256k1.Field.Sub (S_Sqr, Two_X, R.X);

      --  R.Y = s * (P.X - R.X) - P.Y
      declare
         Tmp2 : Secp256k1.Field.Field_Element;
      begin
         Secp256k1.Field.Sub (P.X, R.X, Tmp);
         Secp256k1.Field.Mul (S, Tmp, Tmp2);
         Secp256k1.Field.Sub (Tmp2, P.Y, R.Y);
      end;

      R.Infinity := False;
   end Double_Point;

   --  Point addition: R := P + Q.
   procedure Add_Points (P, Q : Affine_Point; R : out Affine_Point);
   procedure Add_Points (P, Q : Affine_Point; R : out Affine_Point) is
      Numer : Secp256k1.Field.Field_Element;
      Denom : Secp256k1.Field.Field_Element;
      Inv_D : Secp256k1.Field.Field_Element;
      S     : Secp256k1.Field.Field_Element;
      S_Sqr : Secp256k1.Field.Field_Element;
      Tmp   : Secp256k1.Field.Field_Element;
      Neg_Q : Affine_Point;
      Ok    : Boolean;
   begin
      if P.Infinity then R := Q; return; end if;
      if Q.Infinity then R := P; return; end if;

      if Secp256k1.Field.Compare (P.X, Q.X) = 0 then
         if Secp256k1.Field.Compare (P.Y, Q.Y) = 0 then
            Double_Point (P, R);
            return;
         end if;
         --  P.X == Q.X but P.Y != Q.Y → Q == -P → R = O
         Negate_Point (P, Neg_Q);
         if Secp256k1.Field.Compare (Neg_Q.Y, Q.Y) = 0 then
            R := (X => Secp256k1.Field.Zero,
                  Y => Secp256k1.Field.Zero,
                  Infinity => True);
            return;
         end if;
         --  Otherwise input is malformed; treat as infinity for safety.
         R := (X => Secp256k1.Field.Zero,
               Y => Secp256k1.Field.Zero,
               Infinity => True);
         return;
      end if;

      --  Slope s = (Q.y - P.y) / (Q.x - P.x).
      Secp256k1.Field.Sub (Q.Y, P.Y, Numer);
      Secp256k1.Field.Sub (Q.X, P.X, Denom);
      Secp256k1.Field.Inv (Denom, Inv_D, Ok);
      Secp256k1.Field.Mul (Numer, Inv_D, S);

      --  R.X = s² - P.x - Q.x
      Secp256k1.Field.Sqr (S, S_Sqr);
      Secp256k1.Field.Sub (S_Sqr, P.X, Tmp);
      Secp256k1.Field.Sub (Tmp, Q.X, R.X);

      --  R.Y = s * (P.x - R.x) - P.y
      declare
         Tmp2 : Secp256k1.Field.Field_Element;
      begin
         Secp256k1.Field.Sub (P.X, R.X, Tmp);
         Secp256k1.Field.Mul (S, Tmp, Tmp2);
         Secp256k1.Field.Sub (Tmp2, P.Y, R.Y);
      end;

      R.Infinity := False;
   end Add_Points;

   ---------------------------------------------------------------------
   --  To_Compressed
   ---------------------------------------------------------------------

   procedure To_Compressed
     (P     : in     Affine_Point;
      Bytes :    out Hadawallet.Byte_Array;
      Ok    :    out Boolean)
   is
      First : constant Positive := Bytes'First;
   begin
      Bytes := [Bytes'Range => 0];
      if P.Infinity then
         Ok := False;
         return;
      end if;
      --  Sign byte: 0x02 if Y is even, 0x03 if odd.
      if (P.Y.Limbs (0) and 1) = 0 then
         Bytes (First) := 16#02#;
      else
         Bytes (First) := 16#03#;
      end if;
      Secp256k1.Field.To_Be32 (P.X, Bytes (First + 1 .. First + 32));
      Ok := True;
   end To_Compressed;

   ---------------------------------------------------------------------
   --  From_Compressed — deferred (needs sqrt mod p).
   ---------------------------------------------------------------------

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
      Ok := False;   --  TODO Phase D — sqrt mod p
   end From_Compressed;

   ---------------------------------------------------------------------
   --  Scalar_Mul: R := K * G via double-and-add.
   ---------------------------------------------------------------------

   procedure Scalar_Mul
     (K  : in     Hadawallet.Byte_Array;
      R  :    out Affine_Point;
      Ok :    out Boolean)
   is
      First : constant Positive := K'First;
      G     : constant Affine_Point := Generator;
      Acc   : Affine_Point :=
        (X => Secp256k1.Field.Zero,
         Y => Secp256k1.Field.Zero,
         Infinity => True);
      Tmp   : Affine_Point;
      Bit   : Hadawallet.U8;
      Byte  : Hadawallet.U8;
   begin
      --  Process bits from MSB to LSB. K is 32 bytes big-endian.
      for I in 0 .. 31 loop
         Byte := K (First + I);
         for B in 0 .. 7 loop
            Double_Point (Acc, Tmp);
            Acc := Tmp;
            Bit := (Byte / Hadawallet.U8 (2 ** (7 - B))) and 1;
            if Bit = 1 then
               Add_Points (Acc, G, Tmp);
               Acc := Tmp;
            end if;
         end loop;
      end loop;

      R := Acc;
      Ok := not Acc.Infinity;
   end Scalar_Mul;

end Secp256k1.Group;
