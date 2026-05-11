--  Secp256k1.Scalar body.

pragma Style_Checks ("-s");

package body Secp256k1.Scalar
  with SPARK_Mode => Off
is

   use type Hadawallet.U32;
   use type Hadawallet.U64;

   --  Curve order n in 8 × U32 little-endian limbs.
   --  n = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
   N : constant Limbs_8 :=
     [16#D0364141#, 16#BFD25E8C#, 16#AF48A03B#, 16#BAAEDCE6#,
      16#FFFFFFFE#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#];

   procedure From_Be32
     (Bytes : in     Hadawallet.Byte_Array;
      S     :    out Scalar_Element;
      Ok    :    out Boolean)
   is
      First : constant Positive := Bytes'First;
   begin
      for I in 0 .. 7 loop
         declare
            B0 : constant Hadawallet.U32 :=
              Hadawallet.U32 (Bytes (First + 4 * (7 - I)));
            B1 : constant Hadawallet.U32 :=
              Hadawallet.U32 (Bytes (First + 4 * (7 - I) + 1));
            B2 : constant Hadawallet.U32 :=
              Hadawallet.U32 (Bytes (First + 4 * (7 - I) + 2));
            B3 : constant Hadawallet.U32 :=
              Hadawallet.U32 (Bytes (First + 4 * (7 - I) + 3));
         begin
            S.Limbs (I) :=
              B0 * 2**24 + B1 * 2**16 + B2 * 2**8 + B3;
         end;
      end loop;
      Ok := Compare (S, (Limbs => N)) < 0;
   end From_Be32;

   procedure To_Be32
     (S     : in     Scalar_Element;
      Bytes :    out Hadawallet.Byte_Array)
   is
      First : constant Positive := Bytes'First;
   begin
      for I in 0 .. 7 loop
         declare
            Limb : constant Hadawallet.U32 := S.Limbs (I);
         begin
            Bytes (First + 4 * (7 - I))     :=
              Hadawallet.U8 ((Limb / 2**24) and 16#FF#);
            Bytes (First + 4 * (7 - I) + 1) :=
              Hadawallet.U8 ((Limb / 2**16) and 16#FF#);
            Bytes (First + 4 * (7 - I) + 2) :=
              Hadawallet.U8 ((Limb / 2**8)  and 16#FF#);
            Bytes (First + 4 * (7 - I) + 3) :=
              Hadawallet.U8 (Limb and 16#FF#);
         end;
      end loop;
   end To_Be32;

   function Compare (A, B : Scalar_Element) return Integer is
   begin
      for I in reverse 0 .. 7 loop
         if A.Limbs (I) < B.Limbs (I) then
            return -1;
         elsif A.Limbs (I) > B.Limbs (I) then
            return 1;
         end if;
      end loop;
      return 0;
   end Compare;

   function In_Range_1_To_N_Minus_1 (A : Scalar_Element) return Boolean is
   begin
      return Compare (A, Zero) > 0
             and then Compare (A, (Limbs => N)) < 0;
   end In_Range_1_To_N_Minus_1;

   procedure Raw_Add
     (A, B  : in     Limbs_8;
      R     :    out Limbs_8;
      Carry :    out Hadawallet.U64);
   procedure Raw_Add
     (A, B  : in     Limbs_8;
      R     :    out Limbs_8;
      Carry :    out Hadawallet.U64)
   is
      C : Hadawallet.U64 := 0;
   begin
      for I in 0 .. 7 loop
         C := Hadawallet.U64 (A (I)) + Hadawallet.U64 (B (I)) + C;
         R (I) := Hadawallet.U32 (C and 16#FFFFFFFF#);
         C := C / 2**32;
      end loop;
      Carry := C;
   end Raw_Add;

   procedure Raw_Sub
     (A, B   : in     Limbs_8;
      R      :    out Limbs_8;
      Borrow :    out Hadawallet.U64);
   procedure Raw_Sub
     (A, B   : in     Limbs_8;
      R      :    out Limbs_8;
      Borrow :    out Hadawallet.U64)
   is
      Diff : Hadawallet.U64;
      Bor  : Hadawallet.U64 := 0;
   begin
      for I in 0 .. 7 loop
         Diff :=
           (Hadawallet.U64 (A (I)) + 2**32)
           - Hadawallet.U64 (B (I))
           - Bor;
         R (I) := Hadawallet.U32 (Diff and 16#FFFFFFFF#);
         Bor := (if Diff < 2**32 then 1 else 0);
      end loop;
      Borrow := Bor;
   end Raw_Sub;

   procedure Add (A, B : in Scalar_Element; R : out Scalar_Element) is
      Sum   : Limbs_8;
      Carry : Hadawallet.U64;
      Tmp   : Limbs_8;
      Bor   : Hadawallet.U64;
   begin
      Raw_Add (A.Limbs, B.Limbs, Sum, Carry);
      if Carry /= 0
        or else Compare ((Limbs => Sum), (Limbs => N)) >= 0
      then
         Raw_Sub (Sum, N, Tmp, Bor);
         R.Limbs := Tmp;
      else
         R.Limbs := Sum;
      end if;
   end Add;

   procedure Sub (A, B : in Scalar_Element; R : out Scalar_Element) is
      Diff : Limbs_8;
      Bor  : Hadawallet.U64;
      Sum  : Limbs_8;
      C    : Hadawallet.U64;
   begin
      Raw_Sub (A.Limbs, B.Limbs, Diff, Bor);
      if Bor /= 0 then
         Raw_Add (Diff, N, Sum, C);
         R.Limbs := Sum;
      else
         R.Limbs := Diff;
      end if;
   end Sub;

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

end Secp256k1.Scalar;
