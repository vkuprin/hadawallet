--  Key_Derivation body — BIP39 mnemonic-to-seed and BIP32 CKDpriv.
--
--  Architecture: Key_Derivation is the only module besides Signing that
--  handles raw private-key bytes. It derives a child key from a master
--  privkey + chain code along a BIP32 path, then hands the child to
--  Signing.Load_Privkey. Bytes are wiped between iterations.
--
--  v0.2 limitation: UTF-8 NFKD normalization of the mnemonic and
--  passphrase is NOT applied. Bytes are accepted as given. This is
--  sufficient for ASCII wordlists (English BIP39) and ASCII passphrases
--  — which covers ~99% of real-world use. Non-ASCII mnemonics (Japanese,
--  Korean, etc.) require NFKD and are deferred to v0.3.

pragma Style_Checks ("-s");

with Hashing;
with Signing;

package body Key_Derivation
  with SPARK_Mode => Off
is

   use type Hadawallet.U8;
   use type Hadawallet.U32;
   use type Hadawallet.Path_Element;

   -----------------------------------------------------------------------
   --  Helpers
   -----------------------------------------------------------------------

   --  Pack a U32 into 4 big-endian bytes at Buf(Pos..Pos+3).
   procedure Put_BE32
     (Buf : in out Hadawallet.Byte_Array;
      Pos : in Positive;
      V   : in Hadawallet.U32);
   procedure Put_BE32
     (Buf : in out Hadawallet.Byte_Array;
      Pos : in Positive;
      V   : in Hadawallet.U32) is
   begin
      Buf (Pos) := Hadawallet.U8 ((V / 2 ** 24) and 16#FF#);
      Buf (Pos + 1) := Hadawallet.U8 ((V / 2 ** 16) and 16#FF#);
      Buf (Pos + 2) := Hadawallet.U8 ((V / 2 ** 8) and 16#FF#);
      Buf (Pos + 3) := Hadawallet.U8 (V and 16#FF#);
   end Put_BE32;

   --  PBKDF2-HMAC-SHA512 with c=2048 iterations, dkLen=hLen=64.
   --  Single-block specialization (BIP39 exactly fits one block).
   procedure PBKDF2_2048
     (Password : in Hadawallet.Byte_Array;
      Salt     : in Hadawallet.Byte_Array;
      Out_Buf  : out Hadawallet.Mac_Bytes_512);
   procedure PBKDF2_2048
     (Password : in Hadawallet.Byte_Array;
      Salt     : in Hadawallet.Byte_Array;
      Out_Buf  : out Hadawallet.Mac_Bytes_512)
   is
      S1     : Hadawallet.Byte_Array (1 .. Salt'Length + 4);
      U_Prev : Hadawallet.Mac_Bytes_512;
      U_Cur  : Hadawallet.Mac_Bytes_512;
      T      : Hadawallet.Mac_Bytes_512 := [others => 0];
   begin
      if Salt'Length > 0 then
         S1 (1 .. Salt'Length) := Salt;
      end if;
      Put_BE32 (S1, Salt'Length + 1, 1);

      Hashing.HMAC_SHA512 (Password, S1, U_Cur);
      T := U_Cur;

      for J in 2 .. 2048 loop
         U_Prev := U_Cur;
         Hashing.HMAC_SHA512 (Password, U_Prev, U_Cur);
         for I in T'Range loop
            T (I) := T (I) xor U_Cur (I);
         end loop;
      end loop;

      Out_Buf := T;

      pragma Warnings (Off, "possibly useless assignment");
      U_Prev := [others => 0];
      U_Cur := [others => 0];
      T := [others => 0];
      S1 := [others => 0];
      pragma Warnings (On, "possibly useless assignment");
   end PBKDF2_2048;

   -----------------------------------------------------------------------
   --  BIP39: mnemonic + passphrase -> 64-byte seed.
   -----------------------------------------------------------------------

   procedure Mnemonic_To_Seed
     (Mnemonic   : in String;
      Passphrase : in String;
      Seed       : out Hadawallet.Mac_Bytes_512)
   is
      M_Bytes     : Hadawallet.Byte_Array (1 .. Mnemonic'Length);
      S_Bytes     : Hadawallet.Byte_Array (1 .. 8 + Passphrase'Length);
      --  "mnemonic" literal as bytes (per BIP39).
      Salt_Prefix : constant Hadawallet.Byte_Array (1 .. 8) :=
        [16#6D#, 16#6E#, 16#65#, 16#6D#, 16#6F#, 16#6E#, 16#69#, 16#63#];
   begin
      for I in 1 .. Mnemonic'Length loop
         M_Bytes (I) :=
           Hadawallet.U8 (Character'Pos (Mnemonic (Mnemonic'First + I - 1)));
      end loop;

      S_Bytes (1 .. 8) := Salt_Prefix;
      for I in 1 .. Passphrase'Length loop
         S_Bytes (8 + I) :=
           Hadawallet.U8
             (Character'Pos (Passphrase (Passphrase'First + I - 1)));
      end loop;

      PBKDF2_2048 (M_Bytes, S_Bytes, Seed);

      pragma Warnings (Off, "possibly useless assignment");
      M_Bytes := [others => 0];
      S_Bytes := [others => 0];
      pragma Warnings (On, "possibly useless assignment");
   end Mnemonic_To_Seed;

   -----------------------------------------------------------------------
   --  BIP32: master key derivation.
   -----------------------------------------------------------------------

   procedure Master_Key_From_Seed
     (Seed       : in Hadawallet.Mac_Bytes_512;
      Privkey    : out Hadawallet.Privkey_Bytes;
      Chain_Code : out Hadawallet.Chain_Code)
   is
      --  "Bitcoin seed" as bytes (per BIP32 master derivation).
      Key   : constant Hadawallet.Byte_Array (1 .. 12) :=
        [16#42#,
         16#69#,
         16#74#,
         16#63#,
         16#6F#,
         16#69#,
         16#6E#,
         16#20#,
         16#73#,
         16#65#,
         16#65#,
         16#64#];
      I_Buf : Hadawallet.Mac_Bytes_512;
   begin
      Hashing.HMAC_SHA512 (Key, Seed, I_Buf);
      for J in 1 .. 32 loop
         Privkey (J) := I_Buf (J);
         Chain_Code (J) := I_Buf (32 + J);
      end loop;
      pragma Warnings (Off, "possibly useless assignment");
      I_Buf := [others => 0];
      pragma Warnings (On, "possibly useless assignment");
   end Master_Key_From_Seed;

   -----------------------------------------------------------------------
   --  BIP32: CKDpriv along a path.
   --
   --  For each path element e:
   --    hardened (bit 31 set):
   --       I = HMAC-SHA512(c_par, 0x00 || k_par || ser32(e))
   --    normal:
   --       I = HMAC-SHA512(c_par, serP(K_par) || ser32(e))
   --    child_priv  = (parse256(IL) + k_par) mod n
   --                  [via Signing.Tweak_Add_Scalar]
   --    child_chain = IR
   --
   --  Returns all-zero outputs on FFI failure (e.g., IL >= n or sum is
   --  zero, probability ~2^-127 — caller may retry with sibling index).
   -----------------------------------------------------------------------

   procedure Derive_Path
     (Master_Privkey    : in Hadawallet.Privkey_Bytes;
      Master_Chain_Code : in Hadawallet.Chain_Code;
      Path              : in Hadawallet.Derivation_Path;
      Child_Privkey     : out Hadawallet.Privkey_Bytes;
      Child_Chain_Code  : out Hadawallet.Chain_Code)
   is
      Hardened_Bit : constant Hadawallet.Path_Element := 16#8000_0000#;

      Cur_Priv  : Hadawallet.Privkey_Bytes := Master_Privkey;
      Cur_Chain : Hadawallet.Chain_Code := Master_Chain_Code;

      In_Buf  : Hadawallet.Byte_Array (1 .. 37) := [others => 0];
      I_Bytes : Hadawallet.Mac_Bytes_512;
      Pub     : Hadawallet.Pubkey_Bytes;
      IL      : Hadawallet.Privkey_Bytes;
      Ok      : Boolean;
      Idx_U32 : Hadawallet.U32;
   begin
      Child_Privkey := [others => 0];
      Child_Chain_Code := [others => 0];

      if Path'Length = 0 then
         Child_Privkey := Cur_Priv;
         Child_Chain_Code := Cur_Chain;
         Cur_Priv := [others => 0];
         Cur_Chain := [others => 0];
         return;
      end if;

      for E_Idx in Path'Range loop
         Idx_U32 := Hadawallet.U32 (Path (E_Idx));

         if (Path (E_Idx) and Hardened_Bit) /= 0 then
            In_Buf (1) := 0;
            for J in 1 .. 32 loop
               In_Buf (1 + J) := Cur_Priv (J);
            end loop;
            Put_BE32 (In_Buf, 34, Idx_U32);
         else
            Signing.Pubkey_From_Privkey (Cur_Priv, Pub, Ok);
            if not Ok then
               Cur_Priv := [others => 0];
               Cur_Chain := [others => 0];
               return;
            end if;
            for J in 1 .. 33 loop
               In_Buf (J) := Pub (J);
            end loop;
            Put_BE32 (In_Buf, 34, Idx_U32);
         end if;

         Hashing.HMAC_SHA512 (Cur_Chain, In_Buf, I_Bytes);

         for J in 1 .. 32 loop
            IL (J) := I_Bytes (J);
            Cur_Chain (J) := I_Bytes (32 + J);
         end loop;

         Signing.Tweak_Add_Scalar (Cur_Priv, IL, Ok);

         IL := [others => 0];
         I_Bytes := [others => 0];
         Pub := [others => 0];
         In_Buf := [others => 0];

         if not Ok then
            Cur_Priv := [others => 0];
            Cur_Chain := [others => 0];
            return;
         end if;
      end loop;

      Child_Privkey := Cur_Priv;
      Child_Chain_Code := Cur_Chain;

      pragma Warnings (Off, "possibly useless assignment");
      Cur_Priv := [others => 0];
      Cur_Chain := [others => 0];
      pragma Warnings (On, "possibly useless assignment");
   end Derive_Path;

end Key_Derivation;
