--  Secp256k1.Ecdsa body — RFC 6979 deterministic ECDSA on top of
--  pure-Ada Scalar / Group / Der.
--
--  Nonce derivation uses HMAC-SHA512 (we already have it; SHA-256
--  variant of HMAC isn't in Hashing yet). This means our deterministic
--  signatures are NOT byte-identical to libsecp256k1's RFC 6979
--  nonces (which use HMAC-SHA256), but they ARE valid ECDSA
--  signatures that any standard verifier will accept. Adding
--  HMAC-SHA256 to Hashing would close the byte-equality gap.

pragma Style_Checks ("-s");

with Hashing;
with Secp256k1.Field;
with Secp256k1.Scalar;
with Secp256k1.Group;
with Secp256k1.Der;

package body Secp256k1.Ecdsa
  with SPARK_Mode => Off
is


   ---------------------------------------------------------------------
   --  Helpers
   ---------------------------------------------------------------------

   --  Returns True iff Bytes encode a scalar in [1, n-1].
   function Privkey_In_Range (Bytes : Hadawallet.Byte_Array) return Boolean;
   function Privkey_In_Range (Bytes : Hadawallet.Byte_Array) return Boolean is
      S  : Secp256k1.Scalar.Scalar_Element;
      Ok : Boolean;
   begin
      Secp256k1.Scalar.From_Be32 (Bytes, S, Ok);
      if not Ok then
         return False;
      end if;
      return Secp256k1.Scalar.In_Range_1_To_N_Minus_1 (S);
   end Privkey_In_Range;

   --  Reduce a 32-byte big-endian value mod n. The input may be
   --  >= n (e.g., a SHA-256 digest); since n > 2^255 the value is
   --  at most 2*n so one conditional subtract suffices.
   procedure Reduce_Bytes_Mod_N
     (Bytes : in     Hadawallet.Byte_Array;
      S     :    out Secp256k1.Scalar.Scalar_Element);
   procedure Reduce_Bytes_Mod_N
     (Bytes : in     Hadawallet.Byte_Array;
      S     :    out Secp256k1.Scalar.Scalar_Element)
   is
      Ok          : Boolean;
      Tmp         : Secp256k1.Scalar.Scalar_Element;
      N_As_Scalar : Secp256k1.Scalar.Scalar_Element;
      N_Bytes : constant Hadawallet.Byte_Array (1 .. 32) :=
        [16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FE#,
         16#BA#, 16#AE#, 16#DC#, 16#E6#, 16#AF#, 16#48#, 16#A0#, 16#3B#,
         16#BF#, 16#D2#, 16#5E#, 16#8C#, 16#D0#, 16#36#, 16#41#, 16#41#];
   begin
      Secp256k1.Scalar.From_Be32 (Bytes, S, Ok);
      if Ok then
         return;
      end if;
      --  Bytes >= n. Build a "Scalar" whose Limbs are the bits of
      --  Bytes (From_Be32 already populated S.Limbs even on Ok=False
      --  — the Ok flag only signals the range check), then do
      --  Tmp := S; subtract n_as_scalar (which has the bits of n)
      --  using Scalar.Sub. Since Scalar.Sub does mod-n arithmetic
      --  and (Bytes - n) is a valid Scalar in [0, n-1] when Bytes <
      --  2n (always true here since Bytes < 2^256 < 2n), the result
      --  is correct.
      Tmp := S;
      Secp256k1.Scalar.From_Be32 (N_Bytes, N_As_Scalar, Ok);
      --  Ok is False here (n is not in [0, n-1]) but N_As_Scalar.Limbs
      --  encode n's bit pattern, which is what we want.
      Secp256k1.Scalar.Sub (Tmp, N_As_Scalar, S);
   end Reduce_Bytes_Mod_N;

   --  RFC 6979 §3.2 deterministic K generation, using HMAC-SHA512
   --  (NOT the canonical SHA-256 — see header note).
   procedure Generate_K
     (Privkey : in     Hadawallet.Privkey_Bytes;
      Z       : in     Hadawallet.Byte_Array;
      K_Out   :    out Hadawallet.Privkey_Bytes;
      Ok      :    out Boolean);
   procedure Generate_K
     (Privkey : in     Hadawallet.Privkey_Bytes;
      Z       : in     Hadawallet.Byte_Array;
      K_Out   :    out Hadawallet.Privkey_Bytes;
      Ok      :    out Boolean)
   is
      V : Hadawallet.Mac_Bytes_512 := [others => 16#01#];
      K : Hadawallet.Mac_Bytes_512 := [others => 16#00#];
      --  Step d: K = HMAC(K, V || 0x00 || int2octets(x) || bits2octets(h))
      --  with int2octets(x) = privkey (32 bytes), bits2octets(h) = z (32 bytes).
      --  Concatenated message: 64 + 1 + 32 + 32 = 129 bytes.
      Msg : Hadawallet.Byte_Array (1 .. 129);
      T   : Hadawallet.Privkey_Bytes;
      Tmp : Hadawallet.Mac_Bytes_512;
   begin
      --  Step d: K := HMAC(K, V || 0x00 || privkey || z)
      Msg (1 .. 64)   := Hadawallet.Byte_Array (V);
      Msg (65)        := 16#00#;
      Msg (66 .. 97)  := Hadawallet.Byte_Array (Privkey);
      Msg (98 .. 129) := Z;
      Hashing.HMAC_SHA512 (Hadawallet.Byte_Array (K), Msg, Tmp);
      K := Tmp;

      --  Step e: V := HMAC(K, V)
      Hashing.HMAC_SHA512 (Hadawallet.Byte_Array (K),
                            Hadawallet.Byte_Array (V), V);

      --  Step f: K := HMAC(K, V || 0x01 || privkey || z)
      Msg (1 .. 64)   := Hadawallet.Byte_Array (V);
      Msg (65)        := 16#01#;
      Msg (66 .. 97)  := Hadawallet.Byte_Array (Privkey);
      Msg (98 .. 129) := Z;
      Hashing.HMAC_SHA512 (Hadawallet.Byte_Array (K), Msg, Tmp);
      K := Tmp;

      --  Step g: V := HMAC(K, V)
      Hashing.HMAC_SHA512 (Hadawallet.Byte_Array (K),
                            Hadawallet.Byte_Array (V), V);

      --  Step h: loop until T is in [1, n-1]. Each iteration:
      --    V := HMAC(K, V); T := first 32 bytes of V.
      for Attempt in 1 .. 16 loop
         Hashing.HMAC_SHA512 (Hadawallet.Byte_Array (K),
                               Hadawallet.Byte_Array (V), V);
         for I in 1 .. 32 loop
            T (I) := V (I);
         end loop;
         if Privkey_In_Range (Hadawallet.Byte_Array (T)) then
            K_Out := T;
            Ok := True;
            return;
         end if;
         --  K := HMAC(K, V || 0x00); V := HMAC(K, V)
         declare
            Msg2 : Hadawallet.Byte_Array (1 .. 65);
         begin
            Msg2 (1 .. 64) := Hadawallet.Byte_Array (V);
            Msg2 (65)      := 16#00#;
            Hashing.HMAC_SHA512 (Hadawallet.Byte_Array (K), Msg2, Tmp);
            K := Tmp;
         end;
         Hashing.HMAC_SHA512 (Hadawallet.Byte_Array (K),
                               Hadawallet.Byte_Array (V), V);
      end loop;

      K_Out := [others => 0];
      Ok := False;
   end Generate_K;

   --  n/2 (floor) in 8 × U32 little-endian. Used for BIP62 low-s.
   N_Half : constant Secp256k1.Scalar.Scalar_Element :=
     (Limbs => [16#681B20A0#, 16#DFE92F46#, 16#57A4501D#, 16#5D576E73#,
                16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#7FFFFFFF#]);

   ---------------------------------------------------------------------
   --  Public API
   ---------------------------------------------------------------------

   procedure Sign
     (Privkey : in     Hadawallet.Privkey_Bytes;
      Digest  : in     Hadawallet.Digest_Bytes;
      Sig     :    out Hadawallet.Signature_Bytes;
      Length  :    out Hadawallet.Signature_Length)
   is
      Z_Scalar  : Secp256k1.Scalar.Scalar_Element;
      D_Scalar  : Secp256k1.Scalar.Scalar_Element;
      K_Bytes   : Hadawallet.Privkey_Bytes;
      K_Scalar  : Secp256k1.Scalar.Scalar_Element;
      K_Inv     : Secp256k1.Scalar.Scalar_Element;
      R_Point   : Secp256k1.Group.Affine_Point;
      R_X_Bytes : Hadawallet.Byte_Array (1 .. 32);
      R_Scalar  : Secp256k1.Scalar.Scalar_Element;
      RD        : Secp256k1.Scalar.Scalar_Element;
      RD_Plus_Z : Secp256k1.Scalar.Scalar_Element;
      S_Scalar  : Secp256k1.Scalar.Scalar_Element;
      Negated_S : Secp256k1.Scalar.Scalar_Element;
      Ok        : Boolean;
      R_Bytes   : Hadawallet.Byte_Array (1 .. 32);
      S_Bytes   : Hadawallet.Byte_Array (1 .. 32);
   begin
      Sig := [others => 0];
      Length := 0;

      if not Privkey_In_Range (Hadawallet.Byte_Array (Privkey)) then
         return;
      end if;

      Reduce_Bytes_Mod_N (Hadawallet.Byte_Array (Digest), Z_Scalar);
      Secp256k1.Scalar.From_Be32 (Hadawallet.Byte_Array (Privkey),
                                   D_Scalar, Ok);
      if not Ok then
         return;
      end if;

      --  RFC 6979 deterministic nonce.
      Generate_K (Privkey, Hadawallet.Byte_Array (Digest), K_Bytes, Ok);
      if not Ok then
         return;
      end if;
      Secp256k1.Scalar.From_Be32 (Hadawallet.Byte_Array (K_Bytes),
                                   K_Scalar, Ok);
      if not Ok then
         return;
      end if;

      --  R = k * G; r = R.x mod n.
      Secp256k1.Group.Scalar_Mul (Hadawallet.Byte_Array (K_Bytes),
                                   R_Point, Ok);
      if not Ok then
         return;
      end if;
      Secp256k1.Field.To_Be32 (R_Point.X, R_X_Bytes);
      Reduce_Bytes_Mod_N (R_X_Bytes, R_Scalar);
      if Secp256k1.Scalar.Compare (R_Scalar, Secp256k1.Scalar.Zero) = 0 then
         return;   --  Should retry with new k; for v0.3 we just fail.
      end if;

      --  s = k^-1 * (z + r * d) mod n.
      Secp256k1.Scalar.Inv (K_Scalar, K_Inv, Ok);
      if not Ok then
         return;
      end if;
      Secp256k1.Scalar.Mul (R_Scalar, D_Scalar, RD);
      Secp256k1.Scalar.Add (RD, Z_Scalar, RD_Plus_Z);
      Secp256k1.Scalar.Mul (K_Inv, RD_Plus_Z, S_Scalar);
      if Secp256k1.Scalar.Compare (S_Scalar, Secp256k1.Scalar.Zero) = 0 then
         return;
      end if;

      --  BIP62 low-s: if s > n/2, s := n - s.
      if Secp256k1.Scalar.Compare (S_Scalar, N_Half) > 0 then
         Secp256k1.Scalar.Sub (Secp256k1.Scalar.Zero, S_Scalar, Negated_S);
         S_Scalar := Negated_S;
      end if;

      Secp256k1.Scalar.To_Be32 (R_Scalar, R_Bytes);
      Secp256k1.Scalar.To_Be32 (S_Scalar, S_Bytes);
      Secp256k1.Der.Encode_Signature (R_Bytes, S_Bytes, Sig, Length);
   end Sign;

   procedure Pubkey_From_Privkey
     (Privkey : in     Hadawallet.Privkey_Bytes;
      Pubkey  :    out Hadawallet.Pubkey_Bytes;
      Ok      :    out Boolean)
   is
      P    : Secp256k1.Group.Affine_Point;
      OkM  : Boolean;
      OkC  : Boolean;
   begin
      Pubkey := [others => 0];
      if not Privkey_In_Range (Hadawallet.Byte_Array (Privkey)) then
         Ok := False;
         return;
      end if;

      Secp256k1.Group.Scalar_Mul
        (Hadawallet.Byte_Array (Privkey), P, OkM);
      if not OkM then
         Ok := False;
         return;
      end if;

      Secp256k1.Group.To_Compressed
        (P, Hadawallet.Byte_Array (Pubkey), OkC);
      Ok := OkC;
   end Pubkey_From_Privkey;

   procedure Tweak_Add_Scalar
     (Key   : in out Hadawallet.Privkey_Bytes;
      Tweak : in     Hadawallet.Privkey_Bytes;
      Ok    :    out Boolean)
   is
      S_Key, S_Tweak, S_Sum : Secp256k1.Scalar.Scalar_Element;
      Key_Ok, Tweak_Ok      : Boolean;
   begin
      Secp256k1.Scalar.From_Be32 (Hadawallet.Byte_Array (Key), S_Key,
                                   Key_Ok);
      Secp256k1.Scalar.From_Be32 (Hadawallet.Byte_Array (Tweak), S_Tweak,
                                   Tweak_Ok);
      if not Key_Ok or not Tweak_Ok then
         Key := [others => 0];
         Ok := False;
         return;
      end if;

      Secp256k1.Scalar.Add (S_Key, S_Tweak, S_Sum);

      if not Secp256k1.Scalar.In_Range_1_To_N_Minus_1 (S_Sum) then
         Key := [others => 0];
         Ok := False;
         return;
      end if;

      Secp256k1.Scalar.To_Be32 (S_Sum, Hadawallet.Byte_Array (Key));
      Ok := True;
   end Tweak_Add_Scalar;

end Secp256k1.Ecdsa;
