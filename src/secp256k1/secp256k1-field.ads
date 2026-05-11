--  Secp256k1.Field — 256-bit arithmetic modulo
--    p = 2^256 − 2^32 − 977
--      = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F
--
--  Representation: 8 × U32 limbs, little-endian (Limbs(0) = bits 0..31,
--  Limbs(7) = bits 224..255). Chosen over 4 × U64 to keep multiplication
--  intermediates inside U64 — no 128-bit arithmetic needed.
--
--  STATUS: Phase D in progress. From_Be32 / To_Be32 / Compare /
--  Sub_If_Carry / Add / Sub work and pass vectors. Mul / Sqr / Inv
--  are still stubs (the harder D1 work).

with Hadawallet;

package Secp256k1.Field
  with SPARK_Mode => On
is

   type Limbs_8 is array (0 .. 7) of Hadawallet.U32;
   type Field_Element is record
      Limbs : Limbs_8 := [others => 0];
   end record;

   Zero : constant Field_Element := (Limbs => [0, 0, 0, 0, 0, 0, 0, 0]);
   One  : constant Field_Element := (Limbs => [1, 0, 0, 0, 0, 0, 0, 0]);

   --  Parse a 32-byte big-endian buffer. Ok = False if the value is
   --  greater than or equal to p (caller may need to retry with a
   --  different random source).
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

   --  Three-way comparison: returns -1, 0, +1 if A <, =, > B.
   function Compare (A, B : Field_Element) return Integer
   with Global => null;

   --  (A + B) mod p
   procedure Add (A, B : in Field_Element; R : out Field_Element)
   with Global => null, Depends => (R => (A, B));

   --  (A - B) mod p
   procedure Sub (A, B : in Field_Element; R : out Field_Element)
   with Global => null, Depends => (R => (A, B));

   --  TODO Phase D: Mul, Sqr, Inv. Multiplication needs 8×8 partial
   --  products with mod-p reduction; inversion via Fermat
   --  (a^(p-2) mod p) is composable once Mul lands. Estimate: ~2 weeks
   --  D1.a effort.
   procedure Mul (A, B : in Field_Element; R : out Field_Element)
   with Global => null, Depends => (R => (A, B));

   procedure Sqr (A : in Field_Element; R : out Field_Element)
   with Global => null, Depends => (R => A);

   procedure Inv (A : in Field_Element; R : out Field_Element; Ok : out Boolean)
   with Global => null, Depends => ((R, Ok) => A);

end Secp256k1.Field;
