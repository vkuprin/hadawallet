--  hadawallet entry point.
--
--  Modes:
--    (no args)               : sign-mode. Reads a PSBT on stdin, signs
--                              each input (P2WPKH only), writes a signed
--                              PSBT on stdout. Privkey is resolved via
--                              Comm.Load_Active_Privkey (mnemonic first,
--                              then raw-bytes file fallback).
--    --smoke                 : runs all module smoke tests against known
--                              vectors.
--    --fixture               : emits a minimal unsigned-but-
--                              witness-utxo-populated PSBT to stdout for
--                              the offline demo. The corresponding
--                              privkey is the canonical secp256k1
--                              generator-point privkey (0x01..0x01).
--    --address [<network>]   : derives the active privkey's BIP173
--                              bech32 P2WPKH address and prints it.
--                              <network> in {mainnet, testnet, regtest};
--                              default mainnet.

with Ada.Text_IO;
with Ada.Command_Line;
with Interfaces.C_Streams;

with Hadawallet;
with Signing;
with Hashing;
with Address;
with Transaction;
with Comm;

procedure Main is

   use type Hadawallet.U8;

   --  Convert a byte to two hex digits, lowercase.
   function Hex (B : Hadawallet.U8) return String;
   function Hex (B : Hadawallet.U8) return String is
      H : constant String := "0123456789abcdef";
   begin
      return [H (Integer (B / 16) + 1), H (Integer (B mod 16) + 1)];
   end Hex;

   --  Canonical G-pubkey demo material (BIP173 example).
   G_Pubkey : constant Hadawallet.Pubkey_Bytes :=
     [16#02#,
      16#79#,
      16#be#,
      16#66#,
      16#7e#,
      16#f9#,
      16#dc#,
      16#bb#,
      16#ac#,
      16#55#,
      16#a0#,
      16#62#,
      16#95#,
      16#ce#,
      16#87#,
      16#0b#,
      16#07#,
      16#02#,
      16#9b#,
      16#fc#,
      16#db#,
      16#2d#,
      16#ce#,
      16#28#,
      16#d9#,
      16#59#,
      16#f2#,
      16#81#,
      16#5b#,
      16#16#,
      16#f8#,
      16#17#,
      16#98#];

   procedure Run_Smoke;
   procedure Emit_Fixture;
   procedure Emit_Address (Net : Hadawallet.Network);

   ---------------------------------------------------------------------------
   --  --smoke
   ---------------------------------------------------------------------------

   procedure Run_Smoke is
      Test_Key : constant Hadawallet.Privkey_Bytes := [others => 16#42#];

      Abc         : constant Hadawallet.Byte_Array := [16#61#, 16#62#, 16#63#];
      Abc_Hash    : Hadawallet.Digest_Bytes;
      Abc_Hex     : String (1 .. 64);
      Abc_Rip     : Hadawallet.Hash160_Bytes;
      Abc_Rip_Hex : String (1 .. 40);

      Hmac_Key : constant Hadawallet.Byte_Array (1 .. 20) :=
        [others => 16#0b#];
      Hmac_Msg : constant Hadawallet.Byte_Array :=
        [16#48#, 16#69#, 16#20#, 16#54#, 16#68#, 16#65#, 16#72#, 16#65#];
      Hmac_Out : Hadawallet.Mac_Bytes_512;
      Hmac_Hex : String (1 .. 128);

      Addr_Buf : String (1 .. Hadawallet.Max_Address_Length);
      Addr_Len : Hadawallet.Address_Length;
      Addr_Ok  : Boolean;

      Sig_Key    : constant Hadawallet.Privkey_Bytes := [others => 16#01#];
      Sig_Msg    : constant Hadawallet.Byte_Array :=
        [16#68#,
         16#61#,
         16#64#,
         16#61#,
         16#77#,
         16#61#,
         16#6c#,
         16#6c#,
         16#65#,
         16#74#];
      Sig_Digest : Hadawallet.Digest_Bytes;
      Sig_Bytes  : Hadawallet.Signature_Bytes;
      Sig_Len    : Hadawallet.Signature_Length;
      Sig_Hex    : String (1 .. 144);
   begin
      Ada.Text_IO.Put_Line ("hadawallet v0.1-dev (smoke)");
      Ada.Text_IO.Put_Line
        ("formally verified Bitcoin hardware wallet firmware");
      Ada.Text_IO.New_Line;

      Ada.Text_IO.Put_Line
        ("[smoke] Has_Key before = " & Boolean'Image (Signing.Has_Key));
      Signing.Load_Privkey (Test_Key);
      Ada.Text_IO.Put_Line
        ("[smoke] Has_Key load   = " & Boolean'Image (Signing.Has_Key));
      Signing.Wipe;
      Ada.Text_IO.Put_Line
        ("[smoke] Has_Key wipe   = " & Boolean'Image (Signing.Has_Key));

      Hashing.SHA256 (Abc, Abc_Hash);
      for I in Abc_Hash'Range loop
         Abc_Hex
           (2 * (I - Abc_Hash'First) + 1 .. 2 * (I - Abc_Hash'First) + 2) :=
           Hex (Abc_Hash (I));
      end loop;
      Ada.Text_IO.Put_Line ("[smoke] SHA256(""abc"")    = " & Abc_Hex);

      Hashing.RIPEMD160 (Abc, Abc_Rip);
      for I in Abc_Rip'Range loop
         Abc_Rip_Hex
           (2 * (I - Abc_Rip'First) + 1 .. 2 * (I - Abc_Rip'First) + 2) :=
           Hex (Abc_Rip (I));
      end loop;
      Ada.Text_IO.Put_Line ("[smoke] RIPEMD160(""abc"") = " & Abc_Rip_Hex);

      Hashing.HMAC_SHA512 (Hmac_Key, Hmac_Msg, Hmac_Out);
      for I in Hmac_Out'Range loop
         Hmac_Hex
           (2 * (I - Hmac_Out'First) + 1 .. 2 * (I - Hmac_Out'First) + 2) :=
           Hex (Hmac_Out (I));
      end loop;
      Ada.Text_IO.Put_Line ("[smoke] HMAC-SHA512 RFC4231 #1 =");
      Ada.Text_IO.Put_Line ("    " & Hmac_Hex (1 .. 64));
      Ada.Text_IO.Put_Line ("    " & Hmac_Hex (65 .. 128));

      Address.Pubkey_To_Address
        (G_Pubkey, Hadawallet.Bitcoin_Mainnet, Addr_Buf, Addr_Len, Addr_Ok);
      Ada.Text_IO.Put_Line
        ("[smoke] bech32 P2WPKH(G) = "
         & Addr_Buf (1 .. Addr_Len)
         & " (ok="
         & Boolean'Image (Addr_Ok)
         & ")");

      Signing.Load_Privkey (Sig_Key);
      Hashing.SHA256 (Sig_Msg, Sig_Digest);
      Signing.Sign (Sig_Digest, Sig_Bytes, Sig_Len);
      Signing.Wipe;
      if Sig_Len > 0 then
         for I in 1 .. Natural (Sig_Len) loop
            Sig_Hex (2 * (I - 1) + 1 .. 2 * (I - 1) + 2) :=
              Hex (Sig_Bytes (I));
         end loop;
         Ada.Text_IO.Put_Line
           ("[smoke] ECDSA sign len = "
            & Hadawallet.Signature_Length'Image (Sig_Len)
            & " bytes DER");
         Ada.Text_IO.Put_Line ("    " & Sig_Hex (1 .. 2 * Natural (Sig_Len)));
      else
         Ada.Text_IO.Put_Line ("[smoke] ECDSA sign FAILED");
      end if;
   end Run_Smoke;

   ---------------------------------------------------------------------------
   --  --fixture
   ---------------------------------------------------------------------------

   procedure Emit_Fixture is
      use Interfaces.C_Streams;
      Psbt    : Transaction.PSBT;
      Out_Buf : Hadawallet.Byte_Array (1 .. 1024) := [others => 0];
      Out_Len : Natural;
      Out_Ok  : Boolean;
      G_Hash  : Hadawallet.Hash160_Bytes;
      Ignored : size_t;
   begin
      Psbt.Initialized := True;
      Psbt.Tx_Version := 2;
      Psbt.Locktime := 0;
      Psbt.Num_Inputs := 1;
      Psbt.Num_Outputs := 1;
      Psbt.Inputs (1).Prevout.Txid := [others => 16#11#];
      Psbt.Inputs (1).Prevout.Vout := 0;
      Psbt.Inputs (1).Sequence := 16#FFFFFFFE#;
      Psbt.Inputs (1).Witness_Amt := 100_000;
      Hashing.Hash160 (Hadawallet.Byte_Array (G_Pubkey), G_Hash);
      Psbt.Inputs (1).Witness_Spk.Bytes (1) := 16#00#;
      Psbt.Inputs (1).Witness_Spk.Bytes (2) := 16#14#;
      for I in 1 .. 20 loop
         Psbt.Inputs (1).Witness_Spk.Bytes (2 + I) := G_Hash (I);
      end loop;
      Psbt.Inputs (1).Witness_Spk.Length := 22;
      Psbt.Outputs (1).Amount := 90_000;
      Psbt.Outputs (1).Script.Length := 22;
      Psbt.Outputs (1).Script.Bytes (1 .. 22) :=
        Psbt.Inputs (1).Witness_Spk.Bytes (1 .. 22);

      Transaction.Serialize (Psbt, Out_Buf, Out_Len, Out_Ok);
      if Out_Ok then
         Ignored := fwrite (Out_Buf'Address, 1, size_t (Out_Len), stdout);
      else
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "hadawallet: --fixture serialize failed");
      end if;
   end Emit_Fixture;

   ---------------------------------------------------------------------------
   --  --address
   ---------------------------------------------------------------------------

   procedure Emit_Address (Net : Hadawallet.Network) is
      Privkey  : Hadawallet.Privkey_Bytes;
      Pubkey   : Hadawallet.Pubkey_Bytes;
      Key_Ok   : Boolean;
      Pub_Ok   : Boolean;
      Addr_Buf : String (1 .. Hadawallet.Max_Address_Length);
      Addr_Len : Hadawallet.Address_Length;
      Addr_Ok  : Boolean;
   begin
      Comm.Load_Active_Privkey (Privkey, Key_Ok);
      if not Key_Ok then
         Ada.Command_Line.Set_Exit_Status (1);
         return;
      end if;
      Signing.Pubkey_From_Privkey (Privkey, Pubkey, Pub_Ok);
      Privkey := [others => 0];
      if not Pub_Ok then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "hadawallet: --address pubkey derivation failed");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
      end if;
      Address.Pubkey_To_Address (Pubkey, Net, Addr_Buf, Addr_Len, Addr_Ok);
      if not Addr_Ok then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "hadawallet: --address bech32 encode failed");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
      end if;
      Ada.Text_IO.Put_Line (Addr_Buf (1 .. Addr_Len));
   end Emit_Address;

begin
   if Ada.Command_Line.Argument_Count >= 1 then
      declare
         Arg : constant String := Ada.Command_Line.Argument (1);
      begin
         if Arg = "--smoke" then
            Run_Smoke;
            return;
         elsif Arg = "--fixture" then
            Emit_Fixture;
            return;
         elsif Arg = "--address" then
            declare
               Net : Hadawallet.Network := Hadawallet.Bitcoin_Mainnet;
            begin
               if Ada.Command_Line.Argument_Count >= 2 then
                  declare
                     A2 : constant String := Ada.Command_Line.Argument (2);
                  begin
                     if A2 = "mainnet" then
                        Net := Hadawallet.Bitcoin_Mainnet;
                     elsif A2 = "testnet" then
                        Net := Hadawallet.Bitcoin_Testnet;
                     elsif A2 = "regtest" then
                        Net := Hadawallet.Bitcoin_Regtest;
                     else
                        Ada.Text_IO.Put_Line
                          (Ada.Text_IO.Standard_Error,
                           "hadawallet: unknown network """ & A2 & """");
                        Ada.Command_Line.Set_Exit_Status (1);
                        return;
                     end if;
                  end;
               end if;
               Emit_Address (Net);
            end;
            return;
         else
            Ada.Text_IO.Put_Line
              (Ada.Text_IO.Standard_Error,
               "hadawallet: unknown argument """ & Arg & """");
            Ada.Text_IO.Put_Line
              (Ada.Text_IO.Standard_Error,
               "usage: hadawallet"
               & " [--smoke | --fixture | --address [<net>]]");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
         end if;
      end;
   end if;

   --  Default: sign-mode (stdin PSBT -> stdout signed PSBT).
   Comm.Run;
end Main;
