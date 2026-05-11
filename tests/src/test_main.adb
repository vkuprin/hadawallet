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
   Ada.Text_IO.Put_Line ("---------------------");
   if Failures = 0 then
      Ada.Text_IO.Put_Line ("ALL TESTS PASSED");
   else
      Ada.Text_IO.Put_Line
        ("FAILURES:" & Natural'Image (Failures));
   end if;
   Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Failures));
end Test_Main;
