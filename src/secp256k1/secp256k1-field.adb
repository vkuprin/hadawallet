--  Secp256k1.Field body.

pragma Style_Checks ("-s");

package body Secp256k1.Field
  with SPARK_Mode => Off
is

   use type Hadawallet.U32;
   use type Hadawallet.U64;

   --  p = 2^256 - 2^32 - 977 in 8 × U32 little-endian limbs.
   P : constant Limbs_8 :=
     [16#FFFFFC2F#, 16#FFFFFFFE#, 16#FFFFFFFF#, 16#FFFFFFFF#,
      16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#];

   ---------------------------------------------------------------------
   --  Byte conversion
   ---------------------------------------------------------------------

   procedure From_Be32
     (Bytes : in     Hadawallet.Byte_Array;
      F     :    out Field_Element;
      Ok    :    out Boolean)
   is
      First : constant Positive := Bytes'First;
   begin
      --  Most-significant byte is at Bytes(First); pack into limb 7 down.
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
            F.Limbs (I) :=
              B0 * 2**24 + B1 * 2**16 + B2 * 2**8 + B3;
         end;
      end loop;

      --  Validate F < p.
      Ok := Compare (F, (Limbs => P)) < 0;
   end From_Be32;

   procedure To_Be32
     (F     : in     Field_Element;
      Bytes :    out Hadawallet.Byte_Array)
   is
      First : constant Positive := Bytes'First;
   begin
      for I in 0 .. 7 loop
         declare
            Limb : constant Hadawallet.U32 := F.Limbs (I);
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

   ---------------------------------------------------------------------
   --  Compare + raw add/sub (without modular reduction)
   ---------------------------------------------------------------------

   function Compare (A, B : Field_Element) return Integer is
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

   --  Raw 256-bit add: R := A + B, Carry := overflow bit.
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

   --  Raw 256-bit sub: R := A - B, Borrow := 1 if A < B.
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

   ---------------------------------------------------------------------
   --  Modular add / sub
   ---------------------------------------------------------------------

   procedure Add (A, B : in Field_Element; R : out Field_Element) is
      Sum   : Limbs_8;
      Carry : Hadawallet.U64;
      Tmp   : Limbs_8;
      Bor   : Hadawallet.U64;
   begin
      Raw_Add (A.Limbs, B.Limbs, Sum, Carry);
      --  If Sum overflowed 256 bits OR Sum >= p, subtract p.
      if Carry /= 0
        or else Compare ((Limbs => Sum), (Limbs => P)) >= 0
      then
         Raw_Sub (Sum, P, Tmp, Bor);
         R.Limbs := Tmp;
      else
         R.Limbs := Sum;
      end if;
   end Add;

   procedure Sub (A, B : in Field_Element; R : out Field_Element) is
      Diff : Limbs_8;
      Bor  : Hadawallet.U64;
      Sum  : Limbs_8;
      C    : Hadawallet.U64;
   begin
      Raw_Sub (A.Limbs, B.Limbs, Diff, Bor);
      if Bor /= 0 then
         Raw_Add (Diff, P, Sum, C);
         R.Limbs := Sum;
      else
         R.Limbs := Diff;
      end if;
   end Sub;

   ---------------------------------------------------------------------
   --  TODO Phase D — Mul / Sqr / Inv stubs.
   ---------------------------------------------------------------------

   procedure Mul (A, B : in Field_Element; R : out Field_Element) is
      pragma Unreferenced (A, B);
   begin
      R := Zero;
   end Mul;

   procedure Sqr (A : in Field_Element; R : out Field_Element) is
      pragma Unreferenced (A);
   begin
      R := Zero;
   end Sqr;

   procedure Inv
     (A : in Field_Element; R : out Field_Element; Ok : out Boolean)
   is
      pragma Unreferenced (A);
   begin
      R := Zero;
      Ok := False;
   end Inv;

end Secp256k1.Field;
