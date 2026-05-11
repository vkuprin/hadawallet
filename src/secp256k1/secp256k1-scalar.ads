--  Secp256k1.Scalar — arithmetic modulo the curve order
--    n = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFE_BAAE_DCE6_AF48_A03B_BFD2_5E8C_D036_4141
--
--  STATUS: Phase D skeleton. Same shape as Field but reduces mod n.

with Hadawallet;

package Secp256k1.Scalar
  with SPARK_Mode => On
is

   type Limbs_4 is array (0 .. 3) of Hadawallet.U64;
   type Scalar_Element is record
      Limbs : Limbs_4 := [others => 0];
   end record;

   Zero : constant Scalar_Element := (Limbs => [0, 0, 0, 0]);
   One  : constant Scalar_Element := (Limbs => [1, 0, 0, 0]);

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

   procedure Add (A, B : in Scalar_Element; R : out Scalar_Element)
   with Global => null, Depends => (R => (A, B));

   procedure Mul (A, B : in Scalar_Element; R : out Scalar_Element)
   with Global => null, Depends => (R => (A, B));

   procedure Inv
     (A : in Scalar_Element; R : out Scalar_Element; Ok : out Boolean)
   with Global => null, Depends => ((R, Ok) => A);

   --  In_Range_1_To_N_Minus_1: returns True iff 1 ≤ A < n. Used to
   --  validate privkeys, k nonces, and CKDpriv tweak inputs.
   function In_Range_1_To_N_Minus_1 (A : Scalar_Element) return Boolean
   with Global => null;

end Secp256k1.Scalar;
