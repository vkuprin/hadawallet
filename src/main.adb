--  hadawallet entry point.
--
--  v0.1: smoke test. Loads a test private key, demonstrates that
--  the Has_Key boolean flips, runs the (stub) Comm loop, exits.

with Ada.Text_IO;

with Hadawallet;
with Signing;
with Hashing;
with Address;
with Comm;

procedure Main is

   Test_Key : constant Hadawallet.Privkey_Bytes := [others => 16#42#];

   --  Convert a byte to two hex digits, lowercase, for diagnostic output.
   function Hex (B : Hadawallet.U8) return String;
   function Hex (B : Hadawallet.U8) return String is
      H : constant String := "0123456789abcdef";
      use type Hadawallet.U8;
   begin
      return [H (Integer (B / 16) + 1), H (Integer (B mod 16) + 1)];
   end Hex;

   --  Hashing smoke vectors. Expected outputs per FIPS 180-4 / RFC 4231 /
   --  RIPEMD-160 spec:
   --    SHA-256("abc") =
   --      ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
   --    SHA-512 via HMAC_SHA512 zero-key smoke: see HMAC test below.
   --    RIPEMD-160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
   --    HMAC-SHA512(key=0x0b*20, msg="Hi There") =
   --      87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde
   --      daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854
   Abc         : constant Hadawallet.Byte_Array := [16#61#, 16#62#, 16#63#];
   Abc_Hash    : Hadawallet.Digest_Bytes;
   Abc_Hex     : String (1 .. 64);
   Abc_Rip     : Hadawallet.Hash160_Bytes;
   Abc_Rip_Hex : String (1 .. 40);
   Hmac_Key    : constant Hadawallet.Byte_Array (1 .. 20) :=
     [others => 16#0b#];
   Hmac_Msg    : constant Hadawallet.Byte_Array :=
     [16#48#, 16#69#, 16#20#, 16#54#, 16#68#, 16#65#, 16#72#, 16#65#];
   Hmac_Out    : Hadawallet.Mac_Bytes_512;
   Hmac_Hex    : String (1 .. 128);

   --  BIP173 P2WPKH test vector. Pubkey is the secp256k1 generator point G.
   --  Expected mainnet address: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
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
   Addr_Buf : String (1 .. Hadawallet.Max_Address_Length);
   Addr_Len : Hadawallet.Address_Length;
   Addr_Ok  : Boolean;

   --  Smoke-test secp256k1 ECDSA sign. Privkey 0x01..0x01 (32 bytes), digest =
   --  SHA-256("hadawallet"). RFC 6979 makes the signature deterministic.
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
   Ada.Text_IO.Put_Line ("hadawallet v0.1-dev (skeleton)");
   Ada.Text_IO.Put_Line ("formally verified Bitcoin hardware wallet firmware");
   Ada.Text_IO.New_Line;

   Ada.Text_IO.Put_Line
     ("[smoke-test] Has_Key before load = " & Boolean'Image (Signing.Has_Key));

   Signing.Load_Privkey (Test_Key);
   Ada.Text_IO.Put_Line
     ("[smoke-test] Has_Key after load  = " & Boolean'Image (Signing.Has_Key));

   Signing.Wipe;
   Ada.Text_IO.Put_Line
     ("[smoke-test] Has_Key after wipe  = " & Boolean'Image (Signing.Has_Key));

   Hashing.SHA256 (Abc, Abc_Hash);
   for I in Abc_Hash'Range loop
      Abc_Hex (2 * (I - Abc_Hash'First) + 1 .. 2 * (I - Abc_Hash'First) + 2) :=
        Hex (Abc_Hash (I));
   end loop;
   Ada.Text_IO.Put_Line ("[smoke-test] SHA256(""abc"")    = " & Abc_Hex);

   Hashing.RIPEMD160 (Abc, Abc_Rip);
   for I in Abc_Rip'Range loop
      Abc_Rip_Hex
        (2 * (I - Abc_Rip'First) + 1 .. 2 * (I - Abc_Rip'First) + 2) :=
        Hex (Abc_Rip (I));
   end loop;
   Ada.Text_IO.Put_Line ("[smoke-test] RIPEMD160(""abc"") = " & Abc_Rip_Hex);

   Hashing.HMAC_SHA512 (Hmac_Key, Hmac_Msg, Hmac_Out);
   for I in Hmac_Out'Range loop
      Hmac_Hex
        (2 * (I - Hmac_Out'First) + 1 .. 2 * (I - Hmac_Out'First) + 2) :=
        Hex (Hmac_Out (I));
   end loop;
   Ada.Text_IO.Put_Line ("[smoke-test] HMAC-SHA512 RFC4231 #1 =");
   Ada.Text_IO.Put_Line ("    " & Hmac_Hex (1 .. 64));
   Ada.Text_IO.Put_Line ("    " & Hmac_Hex (65 .. 128));

   Address.Pubkey_To_Address
     (G_Pubkey, Hadawallet.Bitcoin_Mainnet, Addr_Buf, Addr_Len, Addr_Ok);
   Ada.Text_IO.Put_Line
     ("[smoke-test] bech32 P2WPKH(G)  = "
      & Addr_Buf (1 .. Addr_Len)
      & " (ok="
      & Boolean'Image (Addr_Ok)
      & ")");

   --  Real ECDSA sign via libsecp256k1.
   Signing.Load_Privkey (Sig_Key);
   Hashing.SHA256 (Sig_Msg, Sig_Digest);
   Signing.Sign (Sig_Digest, Sig_Bytes, Sig_Len);
   if Sig_Len > 0 then
      for I in 1 .. Natural (Sig_Len) loop
         Sig_Hex (2 * (I - 1) + 1 .. 2 * (I - 1) + 2) := Hex (Sig_Bytes (I));
      end loop;
      Ada.Text_IO.Put_Line
        ("[smoke-test] ECDSA sign len  = "
         & Hadawallet.Signature_Length'Image (Sig_Len)
         & " bytes (DER)");
      Ada.Text_IO.Put_Line ("    " & Sig_Hex (1 .. 2 * Natural (Sig_Len)));
   else
      Ada.Text_IO.Put_Line ("[smoke-test] ECDSA sign FAILED");
   end if;
   Signing.Wipe;

   Ada.Text_IO.New_Line;
   Comm.Run;
end Main;
