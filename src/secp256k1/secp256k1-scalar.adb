--  Secp256k1.Scalar body.

pragma Style_Checks ("-s");

with Interfaces;

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

   ---------------------------------------------------------------------
   --  Mul: schoolbook 256×256 → 512, then bit-by-bit reduction mod n.
   --
   --  n doesn't have the nice special-form reduction that p does, so
   --  we use the simplest correct approach: long division. ~512
   --  iterations of (shift Acc left by 1, conditionally subtract n).
   --  Acc is 9 limbs (288 bits) since after a shift it can briefly
   --  exceed 2^256 by one bit. Slow but correct; D3 will switch to
   --  Barrett or Montgomery reduction.
   ---------------------------------------------------------------------

   type Limbs_9 is array (0 .. 8) of Hadawallet.U32;

   --  n extended to 9 limbs (high limb = 0).
   N_Ext : constant Limbs_9 :=
     [N (0), N (1), N (2), N (3), N (4), N (5), N (6), N (7), 0];

   --  Compare two 9-limb numbers. Returns -1/0/+1.
   function Compare_9 (A, B : Limbs_9) return Integer;
   function Compare_9 (A, B : Limbs_9) return Integer is
   begin
      for I in reverse 0 .. 8 loop
         if A (I) < B (I) then
            return -1;
         elsif A (I) > B (I) then
            return 1;
         end if;
      end loop;
      return 0;
   end Compare_9;

   --  Subtract: R := A - B (assumes A >= B). Borrow ignored.
   procedure Subtract_9 (A, B : Limbs_9; R : out Limbs_9);
   procedure Subtract_9 (A, B : Limbs_9; R : out Limbs_9) is
      Diff : Hadawallet.U64;
      Bor  : Hadawallet.U64 := 0;
   begin
      for I in 0 .. 8 loop
         Diff :=
           (Hadawallet.U64 (A (I)) + 2**32)
           - Hadawallet.U64 (B (I)) - Bor;
         R (I) := Hadawallet.U32 (Diff and 16#FFFFFFFF#);
         Bor := (if Diff < 2**32 then 1 else 0);
      end loop;
   end Subtract_9;

   procedure Mul (A, B : in Scalar_Element; R : out Scalar_Element) is
      use type Interfaces.Unsigned_128;

      Wide : array (0 .. 15) of Hadawallet.U32 := [others => 0];
      Acc_W : Interfaces.Unsigned_128 := 0;

      Acc   : Limbs_9 := [others => 0];
      Tmp   : Limbs_9;
      Carry : Hadawallet.U64;
      Bit   : Hadawallet.U32;
      Big   : Hadawallet.U64;
   begin
      --  Schoolbook 8×8 → 16.
      for K in 0 .. 14 loop
         declare
            I_Min : constant Integer := Integer'Max (0, K - 7);
            I_Max : constant Integer := Integer'Min (7, K);
         begin
            for I in I_Min .. I_Max loop
               Acc_W := Acc_W
                      + Interfaces.Unsigned_128 (A.Limbs (I))
                      * Interfaces.Unsigned_128 (B.Limbs (K - I));
            end loop;
         end;
         Wide (K) := Hadawallet.U32 (Acc_W and 16#FFFFFFFF#);
         Acc_W := Acc_W / 2**32;
      end loop;
      Wide (15) := Hadawallet.U32 (Acc_W and 16#FFFFFFFF#);

      --  Long-division bit-by-bit.
      for I in reverse 0 .. 15 loop
         for B_Idx in reverse 0 .. 31 loop
            Bit := (Wide (I) / Hadawallet.U32 (2**B_Idx)) and 1;
            --  Shift Acc left by 1 bit, bringing in Bit at position 0.
            Carry := Hadawallet.U64 (Bit);
            for J in 0 .. 8 loop
               Big := Hadawallet.U64 (Acc (J)) * 2 + Carry;
               Acc (J) := Hadawallet.U32 (Big and 16#FFFFFFFF#);
               Carry := Big / 2**32;
            end loop;
            --  Maybe subtract n. Loop because shift can push us up to ~2*n.
            while Compare_9 (Acc, N_Ext) >= 0 loop
               Subtract_9 (Acc, N_Ext, Tmp);
               Acc := Tmp;
            end loop;
         end loop;
      end loop;

      for I in 0 .. 7 loop
         R.Limbs (I) := Acc (I);
      end loop;
   end Mul;

   ---------------------------------------------------------------------
   --  Inv via Fermat: a^(n-2) mod n, square-and-multiply. NOT
   --  constant-time (D3 work).
   ---------------------------------------------------------------------

   procedure Inv
     (A : in Scalar_Element; R : out Scalar_Element; Ok : out Boolean)
   is
      --  n - 2 in 8 × U32 little-endian limbs.
      N_Minus_2 : constant Limbs_8 :=
        [16#D036413F#, 16#BFD25E8C#, 16#AF48A03B#, 16#BAAEDCE6#,
         16#FFFFFFFE#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#];
      T   : Scalar_Element := One;
      Acc : Scalar_Element := A;
      Tmp : Scalar_Element;
   begin
      if Compare (A, Zero) = 0 then
         R := Zero;
         Ok := False;
         return;
      end if;

      for I in 0 .. 7 loop
         for B in 0 .. 31 loop
            if (N_Minus_2 (I) and Hadawallet.U32 (2**B)) /= 0 then
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

end Secp256k1.Scalar;
