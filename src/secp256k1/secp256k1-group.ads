--  Secp256k1.Group — affine + Jacobian points on the secp256k1 curve.
--
--  STATUS: Phase D skeleton. The constant-time scalar multiplication
--  is the keystone for both ECDSA signing and BIP32 non-hardened
--  derivation; ~1–2 weeks of D1 effort once Field/Scalar are correct.

with Hadawallet;
with Secp256k1.Field;

package Secp256k1.Group
  with SPARK_Mode => On
is

   type Affine_Point is record
      X        : Secp256k1.Field.Field_Element := Secp256k1.Field.Zero;
      Y        : Secp256k1.Field.Field_Element := Secp256k1.Field.Zero;
      Infinity : Boolean := True;
   end record;

   --  Generator G of secp256k1 (per SEC 2 §2.4.1).
   function Generator return Affine_Point
   with Global => null;

   --  Decode a 33-byte SEC1 compressed pubkey. Ok = False on
   --  malformed input or off-curve point.
   procedure From_Compressed
     (Bytes : in     Hadawallet.Byte_Array;
      P     :    out Affine_Point;
      Ok    :    out Boolean)
   with Pre     => Bytes'Length = 33,
        Global  => null,
        Depends => ((P, Ok) => Bytes);

   --  Encode P as a 33-byte SEC1 compressed pubkey.
   procedure To_Compressed
     (P     : in     Affine_Point;
      Bytes :    out Hadawallet.Byte_Array;
      Ok    :    out Boolean)
   with Pre     => Bytes'Length = 33,
        Global  => null,
        Depends => ((Bytes, Ok) => P);

   --  Constant-time scalar multiplication. Used by ECDSA and CKDpriv.
   procedure Scalar_Mul
     (K  : in     Hadawallet.Byte_Array;
      R  :    out Affine_Point;
      Ok :    out Boolean)
   with Pre     => K'Length = 32,
        Global  => null,
        Depends => ((R, Ok) => K);

end Secp256k1.Group;
