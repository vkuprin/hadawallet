--  Secp256k1.Field — 256-bit arithmetic modulo
--    p = 2^256 − 2^32 − 977
--
--  STATUS: Phase D skeleton. Body returns zero outputs and Ok=False.
--  Real implementation: 4×64-bit (or 10×26-bit on M-class targets)
--  limb representation, constant-time add/sub/mul/sqr/inverse, with
--  bounded loop invariants for SPARK Silver. ~4–8 weeks D1 effort.

with Hadawallet;

package Secp256k1.Field
  with SPARK_Mode => On
is

   --  4 × 64-bit limb representation of a field element. Limbs are
   --  little-endian: Limbs(0) holds bits 0..63, Limbs(3) holds bits
   --  192..255. Values are NOT necessarily reduced mod p — see
   --  Normalize.
   type Limbs_4 is array (0 .. 3) of Hadawallet.U64;
   type Field_Element is record
      Limbs : Limbs_4 := [others => 0];
   end record;

   Zero : constant Field_Element := (Limbs => [0, 0, 0, 0]);
   One  : constant Field_Element := (Limbs => [1, 0, 0, 0]);

   --  32-byte big-endian conversion (field representation per SEC1 §2.3.5).
   procedure From_Be32
     (Bytes : in     Hadawallet.Byte_Array;
      F     :    out Field_Element;
      Ok    :    out Boolean)
   with Pre     => Bytes'Length = 32,
        Global  => null,
        Depends => ((F, Ok) => Bytes);

   procedure To_Be32
     (F     : in     Field_Element;
      Bytes :    out Hadawallet.Byte_Array)
   with Pre     => Bytes'Length = 32,
        Global  => null,
        Depends => (Bytes => F);

   --  Modular arithmetic. All operate on canonical (normalized) inputs
   --  and produce canonical outputs.
   procedure Add (A, B : in Field_Element; R : out Field_Element)
   with Global => null, Depends => (R => (A, B));

   procedure Sub (A, B : in Field_Element; R : out Field_Element)
   with Global => null, Depends => (R => (A, B));

   procedure Mul (A, B : in Field_Element; R : out Field_Element)
   with Global => null, Depends => (R => (A, B));

   procedure Sqr (A : in Field_Element; R : out Field_Element)
   with Global => null, Depends => (R => A);

   procedure Inv (A : in Field_Element; R : out Field_Element; Ok : out Boolean)
   with Global => null, Depends => ((R, Ok) => A);

end Secp256k1.Field;
