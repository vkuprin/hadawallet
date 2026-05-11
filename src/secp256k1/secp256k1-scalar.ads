--  Secp256k1.Scalar — arithmetic modulo the curve order
--    n = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
--
--  Representation: 8 × U32 little-endian limbs, same shape as
--  Secp256k1.Field. Distinct type so accidental cross-modulus
--  arithmetic is caught at compile time.
--
--  STATUS: Phase D in progress. From_Be32 / To_Be32 / Compare /
--  In_Range / Add / Sub work and pass vectors. Mul / Inv still stubs.

with Hadawallet;

package Secp256k1.Scalar
  with SPARK_Mode => On
is

   type Limbs_8 is array (0 .. 7) of Hadawallet.U32;
   type Scalar_Element is record
      Limbs : Limbs_8 := [others => 0];
   end record;

   Zero : constant Scalar_Element := (Limbs => [0, 0, 0, 0, 0, 0, 0, 0]);
   One  : constant Scalar_Element := (Limbs => [1, 0, 0, 0, 0, 0, 0, 0]);

   procedure From_Be32
     (Bytes : in     Hadawallet.Byte_Array;
      S     :    out Scalar_Element;
      Ok    :    out Boolean)
   with Pre     => Bytes'Length = 32,
        Global  => null,
        Depends => ((S, Ok) => Bytes);

   procedure To_Be32
     (S     : in     Scalar_Element;
      Bytes :    out Hadawallet.Byte_Array)
   with Pre     => Bytes'Length = 32,
        Global  => null,
        Depends => (Bytes => S);

   --  Three-way: -1 / 0 / +1.
   function Compare (A, B : Scalar_Element) return Integer
   with Global => null;

   --  Returns True iff 1 ≤ A < n. Used to validate privkeys, k nonces,
   --  and CKDpriv tweak inputs.
   function In_Range_1_To_N_Minus_1 (A : Scalar_Element) return Boolean
   with Global => null;

   --  (A + B) mod n
   procedure Add (A, B : in Scalar_Element; R : out Scalar_Element)
   with Global => null, Depends => (R => (A, B));

   --  (A - B) mod n
   procedure Sub (A, B : in Scalar_Element; R : out Scalar_Element)
   with Global => null, Depends => (R => (A, B));

   --  TODO Phase D: Mul, Inv.
   procedure Mul (A, B : in Scalar_Element; R : out Scalar_Element)
   with Global => null, Depends => (R => (A, B));

   procedure Inv
     (A : in Scalar_Element; R : out Scalar_Element; Ok : out Boolean)
   with Global => null, Depends => ((R, Ok) => A);

end Secp256k1.Scalar;
