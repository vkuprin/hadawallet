--  Secp256k1.Field body.

pragma Style_Checks ("-s");

with Interfaces;

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
   --  Mul: schoolbook 256×256 → 512, then reduce via 2^256 ≡ 2^32 + 977.
   ---------------------------------------------------------------------

   --  Multiply 8-limb High by C = 2^32 + 977 and add to 8-limb Low.
   --  Output is 10-limb (up to 2^258) with final carry returned.
   procedure Mul_Hi_By_C_Add_Lo
     (High  : in     Limbs_8;
      Low   : in     Limbs_8;
      Out_R :    out Limbs_8;
      Carry :    out Hadawallet.U64);
   procedure Mul_Hi_By_C_Add_Lo
     (High  : in     Limbs_8;
      Low   : in     Limbs_8;
      Out_R :    out Limbs_8;
      Carry :    out Hadawallet.U64)
   is
      Acc      : Hadawallet.U64;
      Mul977   : array (0 .. 8) of Hadawallet.U32 := [others => 0];
      Combined : array (0 .. 9) of Hadawallet.U32 := [others => 0];
   begin
      --  Step 1: Mul977 := High * 977.
      Acc := 0;
      for I in 0 .. 7 loop
         Acc := Acc + Hadawallet.U64 (High (I)) * 977;
         Mul977 (I) := Hadawallet.U32 (Acc and 16#FFFFFFFF#);
         Acc := Acc / 2**32;
      end loop;
      Mul977 (8) := Hadawallet.U32 (Acc);

      --  Step 2: Combined := (High << 32) + Mul977. This equals
      --  High * (2^32 + 977).
      Combined (0) := Mul977 (0);
      Acc := 0;
      for I in 0 .. 7 loop
         Acc := Hadawallet.U64 (Mul977 (I + 1))
              + Hadawallet.U64 (High (I))
              + Acc;
         Combined (I + 1) := Hadawallet.U32 (Acc and 16#FFFFFFFF#);
         Acc := Acc / 2**32;
      end loop;
      Combined (9) := Hadawallet.U32 (Acc);

      --  Step 3: Out_R := Low + Combined[0..7]; Carry holds Combined[8..9]
      --  plus any overflow from the 256-bit add.
      Acc := 0;
      for I in 0 .. 7 loop
         Acc := Hadawallet.U64 (Low (I))
              + Hadawallet.U64 (Combined (I))
              + Acc;
         Out_R (I) := Hadawallet.U32 (Acc and 16#FFFFFFFF#);
         Acc := Acc / 2**32;
      end loop;
      --  Combined (8) and (9) sit above the 256-bit boundary; bring
      --  them into the carry word (max 33 bits).
      Carry := Acc + Hadawallet.U64 (Combined (8))
             + Hadawallet.U64 (Combined (9)) * 2**32;
   end Mul_Hi_By_C_Add_Lo;

   procedure Mul (A, B : in Field_Element; R : out Field_Element) is
      use type Interfaces.Unsigned_128;

      Wide  : array (0 .. 15) of Hadawallet.U32 := [others => 0];
      Acc   : Interfaces.Unsigned_128 := 0;

      Low_Half  : Limbs_8;
      High_Half : Limbs_8;
      Tmp       : Limbs_8;
      Carry     : Hadawallet.U64;
      Sum       : Limbs_8;
      C2        : Hadawallet.U64;
   begin
      --  256×256 → 512 schoolbook.
      for K in 0 .. 14 loop
         declare
            I_Min : constant Integer := Integer'Max (0, K - 7);
            I_Max : constant Integer := Integer'Min (7, K);
         begin
            for I in I_Min .. I_Max loop
               Acc := Acc + Interfaces.Unsigned_128 (A.Limbs (I))
                          * Interfaces.Unsigned_128 (B.Limbs (K - I));
            end loop;
         end;
         Wide (K) := Hadawallet.U32 (Acc and 16#FFFFFFFF#);
         Acc := Acc / 2**32;
      end loop;
      Wide (15) := Hadawallet.U32 (Acc and 16#FFFFFFFF#);

      --  Split into low/high halves.
      for I in 0 .. 7 loop
         Low_Half  (I) := Wide (I);
         High_Half (I) := Wide (I + 8);
      end loop;

      --  First reduction: Tmp := Low + High * (2^32 + 977).
      Mul_Hi_By_C_Add_Lo (High_Half, Low_Half, Tmp, Carry);

      --  Second reduction: the carry word is up to 33 bits, place it in
      --  a fresh High_Half (only limbs 0 and 1 may be non-zero) and run
      --  the same Mul-Hi-By-C+Lo helper.
      High_Half := [others => 0];
      High_Half (0) := Hadawallet.U32 (Carry and 16#FFFFFFFF#);
      High_Half (1) := Hadawallet.U32 (Carry / 2**32);

      Mul_Hi_By_C_Add_Lo (High_Half, Tmp, R.Limbs, Carry);

      --  Final correction: if Carry > 0 OR R >= p, subtract p
      --  (worst case, this happens up to a few times — a single
      --  subtraction is sufficient because Carry can be at most 1).
      if Carry /= 0
        or else Compare ((Limbs => R.Limbs), (Limbs => P)) >= 0
      then
         Raw_Sub (R.Limbs, P, Sum, C2);
         R.Limbs := Sum;
      end if;
   end Mul;

   procedure Sqr (A : in Field_Element; R : out Field_Element) is
   begin
      Mul (A, A, R);
   end Sqr;

   --  Inv via Fermat's little theorem: for A ≠ 0, A^(p-2) ≡ A^-1 mod p.
   --  Square-and-multiply through every bit of (p-2) — ~256 squarings
   --  plus one Mul per set bit. Not constant-time (early exit at A=0
   --  and the conditional Mul leak the privkey-bit pattern); a future
   --  Phase D3 pass should switch to a constant-time addition chain
   --  per Bernstein/Yang.
   procedure Inv
     (A : in Field_Element; R : out Field_Element; Ok : out Boolean)
   is
      --  p - 2 in 8 × U32 little-endian limbs.
      P_Minus_2 : constant Limbs_8 :=
        [16#FFFFFC2D#, 16#FFFFFFFE#, 16#FFFFFFFF#, 16#FFFFFFFF#,
         16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#];
      T   : Field_Element := One;
      Acc : Field_Element := A;
      Tmp : Field_Element;
   begin
      if Compare (A, Zero) = 0 then
         R := Zero;
         Ok := False;
         return;
      end if;

      for I in 0 .. 7 loop
         for B in 0 .. 31 loop
            if (P_Minus_2 (I) and Hadawallet.U32 (2**B)) /= 0 then
               Mul (T, Acc, Tmp);
               T := Tmp;
            end if;
            Mul (Acc, Acc, Tmp);
            Acc := Tmp;
         end loop;
      end loop;

      R := T;
      Ok := True;
   end Inv;

end Secp256k1.Field;
