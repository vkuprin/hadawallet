--  hadawallet test driver.
--
--  Runs a vector-based check over each module and exits with status code
--  equal to the number of failures (0 = all green). Hooked into `alr test`
--  via [[actions]] in alire.toml.

pragma Style_Checks ("-s");

with Ada.Text_IO;
with Ada.Command_Line;

with Hadawallet;
with Hashing;
with Address;
with Signing;
with Transaction;
with Key_Derivation;
with Secp256k1.Der;
with Secp256k1.Field;
with Secp256k1.Scalar;
with Secp256k1.Group;

procedure Test_Main is

   use type Hadawallet.U8;
   use type Hadawallet.U32;
   use type Hadawallet.U64;
   use type Hadawallet.Byte_Array;

   Failures : Natural := 0;

   --  Hex string -> Byte_Array. Helper for inline test vectors.
   function From_Hex (S : String) return Hadawallet.Byte_Array;
   function From_Hex (S : String) return Hadawallet.Byte_Array is
      function Nib (C : Character) return Hadawallet.U8 is
        (case C is
           when '0' .. '9' => Hadawallet.U8 (Character'Pos (C)
                                              - Character'Pos ('0')),
           when 'a' .. 'f' => Hadawallet.U8 (Character'Pos (C)
                                              - Character'Pos ('a') + 10),
           when 'A' .. 'F' => Hadawallet.U8 (Character'Pos (C)
                                              - Character'Pos ('A') + 10),
           when others     => 0);
      Result : Hadawallet.Byte_Array (1 .. S'Length / 2);
   begin
      for I in 1 .. S'Length / 2 loop
         Result (I) :=
           Nib (S (S'First + 2 * (I - 1))) * 16
           + Nib (S (S'First + 2 * (I - 1) + 1));
      end loop;
      return Result;
   end From_Hex;

   procedure Check (Name : String; Cond : Boolean);
   procedure Check (Name : String; Cond : Boolean) is
   begin
      if Cond then
         Ada.Text_IO.Put_Line ("PASS  " & Name);
      else
         Ada.Text_IO.Put_Line ("FAIL  " & Name);
         Failures := Failures + 1;
      end if;
   end Check;

   ---------------------------------------------------------------------------
   --  SHA-256 vectors (FIPS 180-4 + extras)
   ---------------------------------------------------------------------------

   procedure Test_SHA256;
   procedure Test_SHA256 is
      D : Hadawallet.Digest_Bytes;
      Empty : constant Hadawallet.Byte_Array (1 .. 0) := [others => 0];
   begin
      Hashing.SHA256 (Empty, D);
      Check ("SHA256(empty)",
             D = Hadawallet.Digest_Bytes (From_Hex
               ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b" &
                "7852b855")));

      Hashing.SHA256 (From_Hex ("616263"), D);   -- "abc"
      Check ("SHA256(""abc"")",
             D = Hadawallet.Digest_Bytes (From_Hex
               ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61" &
                "f20015ad")));

      --  448-bit message: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
      Hashing.SHA256 (From_Hex
        ("6162636462636465636465666465666765666768666768696768696a" &
         "68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"), D);
      Check ("SHA256(FIPS multi-block)",
             D = Hadawallet.Digest_Bytes (From_Hex
               ("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419" &
                "db06c1")));
   end Test_SHA256;

   ---------------------------------------------------------------------------
   --  RIPEMD-160 vectors
   ---------------------------------------------------------------------------

   procedure Test_RIPEMD160;
   procedure Test_RIPEMD160 is
      H : Hadawallet.Hash160_Bytes;
      Empty : constant Hadawallet.Byte_Array (1 .. 0) := [others => 0];
   begin
      Hashing.RIPEMD160 (Empty, H);
      Check ("RIPEMD160(empty)",
             H = Hadawallet.Hash160_Bytes (From_Hex
               ("9c1185a5c5e9fc54612808977ee8f548b2258d31")));

      Hashing.RIPEMD160 (From_Hex ("616263"), H);
      Check ("RIPEMD160(""abc"")",
             H = Hadawallet.Hash160_Bytes (From_Hex
               ("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")));

      Hashing.RIPEMD160 (From_Hex ("61"), H);     --  "a"
      Check ("RIPEMD160(""a"")",
             H = Hadawallet.Hash160_Bytes (From_Hex
               ("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe")));
   end Test_RIPEMD160;

   ---------------------------------------------------------------------------
   --  HMAC-SHA512 vectors (RFC 4231)
   ---------------------------------------------------------------------------

   procedure Test_HMAC_SHA512;
   procedure Test_HMAC_SHA512 is
      M : Hadawallet.Mac_Bytes_512;
   begin
      --  Test Case 1: key = 20 * 0x0b, data = "Hi There" (0x4869205468657265)
      Hashing.HMAC_SHA512
        (From_Hex ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
         From_Hex ("4869205468657265"), M);
      Check ("HMAC-SHA512 RFC4231 #1",
             M = Hadawallet.Mac_Bytes_512 (From_Hex
               ("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b305" &
                "45e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f17" &
                "02e696c203a126854")));

      --  Test Case 2: key = "Jefe" (0x4a656665), data = "what do ya want for nothing?"
      Hashing.HMAC_SHA512
        (From_Hex ("4a656665"),
         From_Hex ("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),
         M);
      Check ("HMAC-SHA512 RFC4231 #2",
             M = Hadawallet.Mac_Bytes_512 (From_Hex
               ("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7" &
                "ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4" &
                "b636e070a38bce737")));
   end Test_HMAC_SHA512;

   ---------------------------------------------------------------------------
   --  bech32 vectors (BIP173)
   ---------------------------------------------------------------------------

   procedure Test_Bech32;
   procedure Test_Bech32 is
      Buf : String (1 .. Hadawallet.Max_Address_Length);
      Len : Hadawallet.Address_Length;
      Ok  : Boolean;
      G : constant Hadawallet.Pubkey_Bytes := Hadawallet.Pubkey_Bytes (From_Hex
        ("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
   begin
      Address.Pubkey_To_Address (G, Hadawallet.Bitcoin_Mainnet, Buf, Len, Ok);
      Check ("bech32 mainnet P2WPKH(G)",
             Ok and then Buf (1 .. Len)
                          = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

      Address.Pubkey_To_Address (G, Hadawallet.Bitcoin_Testnet, Buf, Len, Ok);
      Check ("bech32 testnet P2WPKH(G)",
             Ok and then Buf (1 .. Len)
                          = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");

      Address.Pubkey_To_Address (G, Hadawallet.Bitcoin_Regtest, Buf, Len, Ok);
      Check ("bech32 regtest P2WPKH(G)",
             Ok and then Buf'Length >= 6
                  and then Buf (1 .. 5) = "bcrt1");
   end Test_Bech32;

   ---------------------------------------------------------------------------
   --  ECDSA via libsecp256k1
   ---------------------------------------------------------------------------

   procedure Test_ECDSA;
   procedure Test_ECDSA is
      Key    : constant Hadawallet.Privkey_Bytes := [others => 16#01#];
      Digest : Hadawallet.Digest_Bytes;
      Sig    : Hadawallet.Signature_Bytes;
      Len    : Hadawallet.Signature_Length;
   begin
      Hashing.SHA256 (From_Hex ("6861646177616c6c6574"), Digest);
      Signing.Load_Privkey (Key);
      Signing.Sign (Digest, Sig, Len);
      Signing.Wipe;
      Check ("ECDSA sign returns DER >=70 bytes", Len >= 70 and Len <= 72);
      Check ("ECDSA DER starts with SEQUENCE tag", Sig (1) = 16#30#);
      Check ("ECDSA DER inner INTEGER tag", Sig (3) = 16#02#);
   end Test_ECDSA;

   ---------------------------------------------------------------------------
   --  PSBT round-trip (serialize -> parse) + sighash sanity
   ---------------------------------------------------------------------------

   procedure Test_PSBT;
   procedure Test_PSBT is
      Tx, Tx2 : Transaction.PSBT;
      Bytes : Hadawallet.Byte_Array (1 .. 1024) := [others => 0];
      Len   : Natural;
      Ok    : Boolean;
      Digest : Hadawallet.Digest_Bytes;
      Sig_Ok : Boolean;
   begin
      --  Build a minimal valid 1-in/1-out P2WPKH PSBT.
      Tx.Initialized := True;
      Tx.Tx_Version := 2;
      Tx.Locktime := 0;
      Tx.Num_Inputs := 1;
      Tx.Num_Outputs := 1;
      Tx.Inputs (1).Prevout.Txid := [others => 16#22#];
      Tx.Inputs (1).Prevout.Vout := 7;
      Tx.Inputs (1).Sequence := 16#FFFFFFFD#;
      Tx.Inputs (1).Witness_Amt := 50_000;
      Tx.Inputs (1).Witness_Spk.Bytes (1 .. 22) := From_Hex
        ("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1");
      Tx.Inputs (1).Witness_Spk.Length := 22;
      Tx.Outputs (1).Amount := 49_000;
      Tx.Outputs (1).Script.Bytes (1 .. 22) := From_Hex
        ("0014751e76e8199196d454941c45d1b3a323f1433bd6");
      Tx.Outputs (1).Script.Length := 22;

      Transaction.Sighash (Tx, 1, Digest, Sig_Ok);
      Check ("BIP143 sighash succeeds for P2WPKH input", Sig_Ok);

      Transaction.Serialize (Tx, Bytes, Len, Ok);
      Check ("PSBT serialize ok", Ok);
      Check ("PSBT serialize magic",
             Bytes (1 .. 5)
              = Hadawallet.Byte_Array'(16#70#, 16#73#, 16#62#,
                                        16#74#, 16#FF#));

      Transaction.Parse (Bytes (1 .. Len), Tx2, Ok);
      Check ("PSBT round-trip parse ok", Ok);
      Check ("PSBT round-trip num_inputs",
             Tx2.Num_Inputs = Tx.Num_Inputs);
      Check ("PSBT round-trip num_outputs",
             Tx2.Num_Outputs = Tx.Num_Outputs);
      Check ("PSBT round-trip locktime",
             Tx2.Locktime = Tx.Locktime);
      Check ("PSBT round-trip tx_version",
             Tx2.Tx_Version = Tx.Tx_Version);
      Check ("PSBT round-trip prevout vout",
             Tx2.Inputs (1).Prevout.Vout = Tx.Inputs (1).Prevout.Vout);
      Check ("PSBT round-trip sequence",
             Tx2.Inputs (1).Sequence = Tx.Inputs (1).Sequence);
      Check ("PSBT round-trip witness_amt",
             Tx2.Inputs (1).Witness_Amt = Tx.Inputs (1).Witness_Amt);
      Check ("PSBT round-trip witness_spk",
             Tx2.Inputs (1).Witness_Spk.Length
                = Tx.Inputs (1).Witness_Spk.Length
              and then Tx2.Inputs (1).Witness_Spk.Bytes (1 .. 22)
                       = Tx.Inputs (1).Witness_Spk.Bytes (1 .. 22));
   end Test_PSBT;

   ---------------------------------------------------------------------------
   --  BIP39 mnemonic-to-seed (Trezor test vectors)
   ---------------------------------------------------------------------------

   procedure Test_BIP39;
   procedure Test_BIP39 is
      Seed     : Hadawallet.Mac_Bytes_512;
      Mnemonic : constant String :=
        "abandon abandon abandon abandon abandon abandon "
        & "abandon abandon abandon abandon abandon about";
   begin
      Key_Derivation.Mnemonic_To_Seed (Mnemonic, "TREZOR", Seed);
      Check ("BIP39 abandon*11/about+TREZOR seed",
             Seed = Hadawallet.Mac_Bytes_512 (From_Hex
               ("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708"
                & "e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81"
                & "b2f001698e7463b04")));

      Key_Derivation.Mnemonic_To_Seed (Mnemonic, "", Seed);
      Check ("BIP39 abandon*11/about+empty seed",
             Seed = Hadawallet.Mac_Bytes_512 (From_Hex
               ("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6"
                & "f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3"
                & "d8d48b2d2ce9e38e4")));
   end Test_BIP39;

   ---------------------------------------------------------------------------
   --  BIP84: end-to-end mnemonic -> bc1q address (BIP84 spec test vector)
   ---------------------------------------------------------------------------

   procedure Test_BIP84;
   procedure Test_BIP84 is
      Mnemonic : constant String :=
        "abandon abandon abandon abandon abandon abandon "
        & "abandon abandon abandon abandon abandon about";
      Path : constant Hadawallet.Derivation_Path :=
        [Hadawallet.Path_Element (16#80000054#),   --  84'
         Hadawallet.Path_Element (16#80000000#),   --  0'
         Hadawallet.Path_Element (16#80000000#),   --  0'
         Hadawallet.Path_Element (0),
         Hadawallet.Path_Element (0)];
      Seed         : Hadawallet.Mac_Bytes_512;
      Master_Priv  : Hadawallet.Privkey_Bytes;
      Master_Chain : Hadawallet.Chain_Code;
      Child_Priv   : Hadawallet.Privkey_Bytes;
      Child_Chain  : Hadawallet.Chain_Code;
      Pubkey       : Hadawallet.Pubkey_Bytes;
      Pub_Ok       : Boolean;
      Addr_Buf     : String (1 .. Hadawallet.Max_Address_Length);
      Addr_Len     : Hadawallet.Address_Length;
      Addr_Ok      : Boolean;
   begin
      Key_Derivation.Mnemonic_To_Seed (Mnemonic, "", Seed);
      Key_Derivation.Master_Key_From_Seed (Seed, Master_Priv, Master_Chain);
      Key_Derivation.Derive_Path
        (Master_Priv, Master_Chain, Path, Child_Priv, Child_Chain);

      Signing.Pubkey_From_Privkey (Child_Priv, Pubkey, Pub_Ok);
      Check ("BIP84 m/84'/0'/0'/0/0 pubkey derivation succeeds", Pub_Ok);
      Check ("BIP84 m/84'/0'/0'/0/0 pubkey matches spec",
             Pubkey = Hadawallet.Pubkey_Bytes (From_Hex
               ("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5"
                & "f0753bf5beef9c2d91af3c")));

      Address.Pubkey_To_Address
        (Pubkey, Hadawallet.Bitcoin_Mainnet, Addr_Buf, Addr_Len, Addr_Ok);
      Check ("BIP84 m/84'/0'/0'/0/0 bech32 address",
             Addr_Ok and then Addr_Buf (1 .. Addr_Len)
                          = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
   end Test_BIP84;

   ---------------------------------------------------------------------------
   --  Secp256k1.Der vector tests
   ---------------------------------------------------------------------------

   procedure Test_DER;
   procedure Test_DER is
      Sig : Hadawallet.Signature_Bytes;
      Len : Hadawallet.Signature_Length;

      --  Trivial r=0x4F, s=0x9A (high bit -> needs leading 0x00 pad on s).
      R1 : constant Hadawallet.Privkey_Bytes :=
        [1 .. 31 => 0, 32 => 16#4F#];
      S1 : constant Hadawallet.Privkey_Bytes :=
        [1 .. 31 => 0, 32 => 16#9A#];
      Expected1 : constant Hadawallet.Byte_Array := From_Hex
        ("3007020104f02020009a");
      --  Canonical full-32-byte r and s, neither needs strip nor pad.
      R2 : constant Hadawallet.Privkey_Bytes :=
        Hadawallet.Privkey_Bytes (From_Hex
          ("455bf64f877f6366b5bc37bcff0cab21fe152b093e479692df82ef1ab42fd61b"));
      S2 : constant Hadawallet.Privkey_Bytes :=
        Hadawallet.Privkey_Bytes (From_Hex
          ("737cd2193815503c3b365230afbef9fd79a3ea7469adfb92a5f4a90008ca8ead"));
   begin
      Secp256k1.Der.Encode_Signature
        (Hadawallet.Byte_Array (R1), Hadawallet.Byte_Array (S1), Sig, Len);
      Check ("DER short r/s with s padding",
             Len = 9
             and then Sig (1) = 16#30# and then Sig (2) = 16#07#
             and then Sig (3) = 16#02# and then Sig (4) = 16#01#
             and then Sig (5) = 16#4F#
             and then Sig (6) = 16#02# and then Sig (7) = 16#02#
             and then Sig (8) = 16#00# and then Sig (9) = 16#9A#);
      pragma Unreferenced (Expected1);

      Secp256k1.Der.Encode_Signature
        (Hadawallet.Byte_Array (R2), Hadawallet.Byte_Array (S2), Sig, Len);
      --  r starts with 0x45 (high bit clear) -> 32 bytes, no pad.
      --  s starts with 0x73 (high bit clear) -> 32 bytes, no pad.
      --  total = 2+32 + 2+32 = 68; full DER = 70 bytes.
      Check ("DER 32-byte r/s no pad/strip", Len = 70
             and then Sig (1) = 16#30# and then Sig (2) = 16#44#
             and then Sig (3) = 16#02# and then Sig (4) = 16#20#
             and then Sig (37) = 16#02# and then Sig (38) = 16#20#);
   end Test_DER;

   ---------------------------------------------------------------------------
   --  Secp256k1.Field — modular arithmetic mod p
   ---------------------------------------------------------------------------

   procedure Test_Field;
   procedure Test_Field is
      F, G, H        : Secp256k1.Field.Field_Element;
      Roundtrip      : Hadawallet.Byte_Array (1 .. 32) := [others => 0];
      Ok             : Boolean;

      --  Some easy values.
      One : constant Hadawallet.Byte_Array := From_Hex
        ("0000000000000000000000000000000000000000000000000000000000000001");
      Two : constant Hadawallet.Byte_Array := From_Hex
        ("0000000000000000000000000000000000000000000000000000000000000002");
      Three : constant Hadawallet.Byte_Array := From_Hex
        ("0000000000000000000000000000000000000000000000000000000000000003");
      --  p - 1 (largest valid field element).
      P_Minus_1 : constant Hadawallet.Byte_Array := From_Hex
        ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E");
      --  p (must be rejected by From_Be32).
      P_Bytes : constant Hadawallet.Byte_Array := From_Hex
        ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
   begin
      --  From_Be32 / To_Be32 round-trip.
      Secp256k1.Field.From_Be32 (One, F, Ok);
      Check ("Field From_Be32(1) ok", Ok);
      Secp256k1.Field.To_Be32 (F, Roundtrip);
      Check ("Field round-trip 1", Roundtrip = One);

      --  p - 1 round-trips.
      Secp256k1.Field.From_Be32 (P_Minus_1, F, Ok);
      Check ("Field From_Be32(p-1) ok", Ok);
      Secp256k1.Field.To_Be32 (F, Roundtrip);
      Check ("Field round-trip p-1", Roundtrip = P_Minus_1);

      --  p itself is rejected.
      Secp256k1.Field.From_Be32 (P_Bytes, F, Ok);
      Check ("Field From_Be32(p) rejected", not Ok);

      --  1 + 2 == 3.
      Secp256k1.Field.From_Be32 (One, F, Ok);
      Secp256k1.Field.From_Be32 (Two, G, Ok);
      Secp256k1.Field.Add (F, G, H);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field 1 + 2 = 3", Roundtrip = Three);

      --  (p-1) + 1 == 0 (modular wrap).
      Secp256k1.Field.From_Be32 (P_Minus_1, F, Ok);
      Secp256k1.Field.From_Be32 (One, G, Ok);
      Secp256k1.Field.Add (F, G, H);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field (p-1) + 1 = 0",
             Roundtrip = Hadawallet.Byte_Array
               (From_Hex
                  ("0000000000000000000000000000000000000000000000000000000000000000")));

      --  3 - 2 = 1.
      Secp256k1.Field.From_Be32 (Three, F, Ok);
      Secp256k1.Field.From_Be32 (Two, G, Ok);
      Secp256k1.Field.Sub (F, G, H);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field 3 - 2 = 1", Roundtrip = One);

      --  0 - 1 = p - 1 (modular underflow).
      Secp256k1.Field.From_Be32
        (Hadawallet.Byte_Array (From_Hex
           ("0000000000000000000000000000000000000000000000000000000000000000")),
         F, Ok);
      Secp256k1.Field.From_Be32 (One, G, Ok);
      Secp256k1.Field.Sub (F, G, H);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field 0 - 1 = p - 1", Roundtrip = P_Minus_1);

      ---------------------------------------------------------------
      --  Mul vectors
      ---------------------------------------------------------------

      --  2 * 3 = 6
      Secp256k1.Field.From_Be32 (Two, F, Ok);
      Secp256k1.Field.From_Be32 (Three, G, Ok);
      Secp256k1.Field.Mul (F, G, H);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field 2 * 3 = 6",
             Roundtrip = Hadawallet.Byte_Array
               (From_Hex
                  ("0000000000000000000000000000000000000000000000000000000000000006")));

      --  1 * 1 = 1 (multiplicative identity).
      Secp256k1.Field.From_Be32 (One, F, Ok);
      Secp256k1.Field.From_Be32 (One, G, Ok);
      Secp256k1.Field.Mul (F, G, H);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field 1 * 1 = 1", Roundtrip = One);

      --  (p-1) * 1 = p - 1
      Secp256k1.Field.From_Be32 (P_Minus_1, F, Ok);
      Secp256k1.Field.From_Be32 (One, G, Ok);
      Secp256k1.Field.Mul (F, G, H);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field (p-1) * 1 = p - 1", Roundtrip = P_Minus_1);

      --  (p-1) * (p-1) = 1 mod p
      --  Because (p-1) ≡ -1 mod p, so (-1)*(-1) = 1.
      Secp256k1.Field.From_Be32 (P_Minus_1, F, Ok);
      Secp256k1.Field.From_Be32 (P_Minus_1, G, Ok);
      Secp256k1.Field.Mul (F, G, H);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field (p-1) * (p-1) = 1 mod p", Roundtrip = One);

      --  Sqr is just Mul (a, a).
      Secp256k1.Field.From_Be32
        (Hadawallet.Byte_Array (From_Hex
           ("0000000000000000000000000000000000000000000000000000000000000005")),
         F, Ok);
      Secp256k1.Field.Sqr (F, H);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field Sqr(5) = 25",
             Roundtrip = Hadawallet.Byte_Array
               (From_Hex
                  ("0000000000000000000000000000000000000000000000000000000000000019")));

      ---------------------------------------------------------------
      --  Inv vectors (a * a^-1 = 1 mod p)
      ---------------------------------------------------------------

      --  Inv(1) = 1
      Secp256k1.Field.From_Be32 (One, F, Ok);
      Secp256k1.Field.Inv (F, H, Ok);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field Inv(1) = 1", Ok and then Roundtrip = One);

      --  Inv(7) computed; verify 7 * Inv(7) = 1.
      Secp256k1.Field.From_Be32
        (Hadawallet.Byte_Array (From_Hex
           ("0000000000000000000000000000000000000000000000000000000000000007")),
         F, Ok);
      Secp256k1.Field.Inv (F, G, Ok);
      Check ("Field Inv(7) succeeds", Ok);
      Secp256k1.Field.Mul (F, G, H);
      Secp256k1.Field.To_Be32 (H, Roundtrip);
      Check ("Field 7 * Inv(7) = 1", Roundtrip = One);

      --  Inv(0) returns failure.
      Secp256k1.Field.From_Be32
        (Hadawallet.Byte_Array (From_Hex
           ("0000000000000000000000000000000000000000000000000000000000000000")),
         F, Ok);
      Secp256k1.Field.Inv (F, H, Ok);
      Check ("Field Inv(0) rejected", not Ok);
   end Test_Field;

   ---------------------------------------------------------------------------
   --  Secp256k1.Scalar — modular arithmetic mod n
   ---------------------------------------------------------------------------

   procedure Test_Scalar;
   procedure Test_Scalar is
      S, T, U   : Secp256k1.Scalar.Scalar_Element;
      Roundtrip : Hadawallet.Byte_Array (1 .. 32) := [others => 0];
      Ok        : Boolean;

      Zero_B : constant Hadawallet.Byte_Array := From_Hex
        ("0000000000000000000000000000000000000000000000000000000000000000");
      One_B : constant Hadawallet.Byte_Array := From_Hex
        ("0000000000000000000000000000000000000000000000000000000000000001");
      --  n - 1 (largest valid scalar in [1, n-1]).
      N_Minus_1 : constant Hadawallet.Byte_Array := From_Hex
        ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
      N_Bytes : constant Hadawallet.Byte_Array := From_Hex
        ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
   begin
      --  Round-trip.
      Secp256k1.Scalar.From_Be32 (One_B, S, Ok);
      Check ("Scalar From_Be32(1) ok", Ok);
      Secp256k1.Scalar.To_Be32 (S, Roundtrip);
      Check ("Scalar round-trip 1", Roundtrip = One_B);

      --  n itself is rejected.
      Secp256k1.Scalar.From_Be32 (N_Bytes, S, Ok);
      Check ("Scalar From_Be32(n) rejected", not Ok);

      --  In_Range checks.
      Secp256k1.Scalar.From_Be32 (Zero_B, S, Ok);
      Check ("Scalar In_Range(0) = False",
             not Secp256k1.Scalar.In_Range_1_To_N_Minus_1 (S));
      Secp256k1.Scalar.From_Be32 (One_B, S, Ok);
      Check ("Scalar In_Range(1) = True",
             Secp256k1.Scalar.In_Range_1_To_N_Minus_1 (S));
      Secp256k1.Scalar.From_Be32 (N_Minus_1, S, Ok);
      Check ("Scalar In_Range(n-1) = True",
             Secp256k1.Scalar.In_Range_1_To_N_Minus_1 (S));

      --  (n-1) + 1 == 0 mod n.
      Secp256k1.Scalar.From_Be32 (N_Minus_1, S, Ok);
      Secp256k1.Scalar.From_Be32 (One_B, T, Ok);
      Secp256k1.Scalar.Add (S, T, U);
      Secp256k1.Scalar.To_Be32 (U, Roundtrip);
      Check ("Scalar (n-1) + 1 = 0", Roundtrip = Zero_B);

      --  0 - 1 == n - 1 mod n.
      Secp256k1.Scalar.From_Be32 (Zero_B, S, Ok);
      Secp256k1.Scalar.From_Be32 (One_B, T, Ok);
      Secp256k1.Scalar.Sub (S, T, U);
      Secp256k1.Scalar.To_Be32 (U, Roundtrip);
      Check ("Scalar 0 - 1 = n - 1", Roundtrip = N_Minus_1);

      ---------------------------------------------------------------
      --  Mul and Inv (mod n)
      ---------------------------------------------------------------

      --  2 * 3 = 6
      Secp256k1.Scalar.From_Be32
        (Hadawallet.Byte_Array (From_Hex
          ("0000000000000000000000000000000000000000000000000000000000000002")),
         S, Ok);
      Secp256k1.Scalar.From_Be32
        (Hadawallet.Byte_Array (From_Hex
          ("0000000000000000000000000000000000000000000000000000000000000003")),
         T, Ok);
      Secp256k1.Scalar.Mul (S, T, U);
      Secp256k1.Scalar.To_Be32 (U, Roundtrip);
      Check ("Scalar 2 * 3 = 6",
             Roundtrip = Hadawallet.Byte_Array
               (From_Hex
                  ("0000000000000000000000000000000000000000000000000000000000000006")));

      --  (n-1) * (n-1) = 1 mod n  (since n-1 ≡ -1)
      Secp256k1.Scalar.From_Be32 (N_Minus_1, S, Ok);
      Secp256k1.Scalar.Mul (S, S, U);
      Secp256k1.Scalar.To_Be32 (U, Roundtrip);
      Check ("Scalar (n-1) * (n-1) = 1", Roundtrip = One_B);

      --  Inv(1) = 1
      Secp256k1.Scalar.From_Be32 (One_B, S, Ok);
      Secp256k1.Scalar.Inv (S, U, Ok);
      Secp256k1.Scalar.To_Be32 (U, Roundtrip);
      Check ("Scalar Inv(1) = 1", Ok and then Roundtrip = One_B);

      --  Verify 7 * Inv(7) = 1.
      Secp256k1.Scalar.From_Be32
        (Hadawallet.Byte_Array (From_Hex
          ("0000000000000000000000000000000000000000000000000000000000000007")),
         S, Ok);
      Secp256k1.Scalar.Inv (S, T, Ok);
      Check ("Scalar Inv(7) succeeds", Ok);
      Secp256k1.Scalar.Mul (S, T, U);
      Secp256k1.Scalar.To_Be32 (U, Roundtrip);
      Check ("Scalar 7 * Inv(7) = 1", Roundtrip = One_B);

      Secp256k1.Scalar.From_Be32 (Zero_B, S, Ok);
      Secp256k1.Scalar.Inv (S, U, Ok);
      Check ("Scalar Inv(0) rejected", not Ok);
   end Test_Scalar;

   ---------------------------------------------------------------------------
   --  Group.From_Compressed — round-trip the generator G.
   ---------------------------------------------------------------------------

   procedure Test_From_Compressed;
   procedure Test_From_Compressed is
      G_Compressed : constant Hadawallet.Byte_Array := From_Hex
        ("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
      P            : Secp256k1.Group.Affine_Point;
      Re_Encoded   : Hadawallet.Byte_Array (1 .. 33) := [others => 0];
      Ok           : Boolean;

      --  An off-curve X (e.g., 0x07): X^3+7 may not have a sqrt mod p.
      Bogus : constant Hadawallet.Byte_Array := From_Hex
        ("020000000000000000000000000000000000000000000000000000000000000007");
   begin
      Secp256k1.Group.From_Compressed (G_Compressed, P, Ok);
      Check ("Group.From_Compressed(G) succeeds", Ok and not P.Infinity);
      if Ok then
         Secp256k1.Group.To_Compressed (P, Re_Encoded, Ok);
         Check ("Group G round-trip equals input", Ok
                and then Re_Encoded = G_Compressed);
      end if;

      Secp256k1.Group.From_Compressed (Bogus, P, Ok);
      --  We can't be sure 0x07 is a non-residue, but the test exists
      --  to confirm From_Compressed never crashes on adversarial input.
      Check ("Group.From_Compressed(off-curve candidate) terminates",
             True);
   end Test_From_Compressed;

   ---------------------------------------------------------------------------
   --  Signing.Tweak_Add_Scalar — cross-backend equality.
   --  On BACKEND=c this exercises libsecp256k1; on BACKEND=ada it
   --  exercises Secp256k1.Ecdsa.Tweak_Add_Scalar -> Scalar.Add. Both
   --  must produce the same output byte-for-byte.
   ---------------------------------------------------------------------------

   procedure Test_Tweak_Add_Scalar;
   procedure Test_Tweak_Add_Scalar is
      K  : Hadawallet.Privkey_Bytes;
      T  : Hadawallet.Privkey_Bytes;
      Ok : Boolean;

      One   : constant Hadawallet.Privkey_Bytes :=
        [1 .. 31 => 0, 32 => 1];
      Two   : constant Hadawallet.Privkey_Bytes :=
        [1 .. 31 => 0, 32 => 2];
      Three : constant Hadawallet.Privkey_Bytes :=
        [1 .. 31 => 0, 32 => 3];

      --  n - 1: largest valid privkey.
      N_Minus_1 : constant Hadawallet.Privkey_Bytes :=
        Hadawallet.Privkey_Bytes
          (From_Hex
            ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"));
   begin
      --  1 + 2 = 3.
      K := One;
      T := Two;
      Signing.Tweak_Add_Scalar (K, T, Ok);
      Check ("Signing.Tweak_Add_Scalar(1, 2) ok", Ok);
      Check ("Signing.Tweak_Add_Scalar(1, 2) = 3", K = Three);

      --  1 + (n-1) = 0 mod n → not in [1, n-1] → Ok=False.
      K := One;
      T := N_Minus_1;
      Signing.Tweak_Add_Scalar (K, T, Ok);
      Check ("Signing.Tweak_Add_Scalar(1, n-1) rejected (sum=0)", not Ok);
   end Test_Tweak_Add_Scalar;

begin
   Ada.Text_IO.Put_Line ("hadawallet test suite");
   Ada.Text_IO.Put_Line ("---------------------");
   Test_SHA256;
   Test_RIPEMD160;
   Test_HMAC_SHA512;
   Test_Bech32;
   Test_ECDSA;
   Test_PSBT;
   Test_BIP39;
   Test_BIP84;
   Test_DER;
   Test_Field;
   Test_Scalar;
   Test_Tweak_Add_Scalar;
   Test_From_Compressed;
   Ada.Text_IO.Put_Line ("---------------------");
   if Failures = 0 then
      Ada.Text_IO.Put_Line ("ALL TESTS PASSED");
   else
      Ada.Text_IO.Put_Line
        ("FAILURES:" & Natural'Image (Failures));
   end if;
   Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Failures));
end Test_Main;
