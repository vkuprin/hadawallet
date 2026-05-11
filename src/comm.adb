--  Comm body — stdin/stdout PSBT loop + privkey resolution.
--
--  Protocol:
--    stdin  : raw binary PSBT (BIP174 bytes)
--    stdout : raw binary signed PSBT (with partial_sig per input)
--    stderr : diagnostics (sighash, signature length, status)
--
--  Privkey source resolution order:
--    1. $HADAWALLET_MNEMONIC_FILE (default ~/.hadawallet/mnemonic.txt)
--       → BIP39 mnemonic → BIP32 derive at $HADAWALLET_PATH
--       (default m/84'/0'/0'/0/0 for BIP84 P2WPKH).
--    2. $HADAWALLET_PRIVKEY_FILE (default ~/.hadawallet/key.bin)
--       → 32 raw bytes (v0.1 fallback, non-secure, kept for demos).

pragma Style_Checks ("-s");

with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;
with Ada.Environment_Variables;
with Ada.Directories;
with Interfaces.C_Streams;

with Signing;
with Transaction;
with Key_Derivation;

package body Comm
  with SPARK_Mode => Off
is

   use type Ada.Streams.Stream_Element_Offset;
   use type Hadawallet.Path_Element;
   use Interfaces.C_Streams;

   Max_Psbt : constant := 8192;

   -----------------------------------------------------------------------
   --  Env / path resolution.
   -----------------------------------------------------------------------

   function Privkey_Path return String is
      Env_Key  : constant String := "HADAWALLET_PRIVKEY_FILE";
      Home_Env : constant String := "HOME";
   begin
      if Ada.Environment_Variables.Exists (Env_Key) then
         return Ada.Environment_Variables.Value (Env_Key);
      elsif Ada.Environment_Variables.Exists (Home_Env) then
         return
           Ada.Environment_Variables.Value (Home_Env) & "/.hadawallet/key.bin";
      else
         return "./hadawallet-key.bin";
      end if;
   end Privkey_Path;

   function Mnemonic_Path return String is
      Env_Key  : constant String := "HADAWALLET_MNEMONIC_FILE";
      Home_Env : constant String := "HOME";
   begin
      if Ada.Environment_Variables.Exists (Env_Key) then
         return Ada.Environment_Variables.Value (Env_Key);
      elsif Ada.Environment_Variables.Exists (Home_Env) then
         return
           Ada.Environment_Variables.Value (Home_Env)
           & "/.hadawallet/mnemonic.txt";
      else
         return "./hadawallet-mnemonic.txt";
      end if;
   end Mnemonic_Path;

   function Path_Env return String is
      Env_Key : constant String := "HADAWALLET_PATH";
   begin
      if Ada.Environment_Variables.Exists (Env_Key) then
         return Ada.Environment_Variables.Value (Env_Key);
      else
         return "m/84'/0'/0'/0/0";
      end if;
   end Path_Env;

   -----------------------------------------------------------------------
   --  Parse "m/84'/0'/0'/0/0" -> Derivation_Path.
   -----------------------------------------------------------------------

   procedure Parse_Path
     (S    : in String;
      Path : in out Hadawallet.Derivation_Path;
      Len  : out Natural;
      Ok   : out Boolean)
   is
      Hardened_Bit : constant Hadawallet.Path_Element := 16#8000_0000#;
      I            : Natural := S'First;
      E            : Hadawallet.Path_Element;
      Has_Digit    : Boolean;
   begin
      Len := 0;
      Ok := False;
      if I > S'Last or else S (I) /= 'm' then
         return;
      end if;
      I := I + 1;
      while I <= S'Last loop
         if S (I) /= '/' then
            return;
         end if;
         I := I + 1;
         E := 0;
         Has_Digit := False;
         while I <= S'Last and then S (I) in '0' .. '9' loop
            E :=
              E
              * 10
              + Hadawallet.Path_Element
                  (Character'Pos (S (I)) - Character'Pos ('0'));
            Has_Digit := True;
            I := I + 1;
         end loop;
         if not Has_Digit then
            return;
         end if;
         if I <= S'Last and then S (I) = ''' then
            E := E or Hardened_Bit;
            I := I + 1;
         end if;
         if Len >= Hadawallet.Max_Path_Depth then
            return;
         end if;
         Len := Len + 1;
         Path (Path'First + Len - 1) := E;
      end loop;
      Ok := True;
   end Parse_Path;

   -----------------------------------------------------------------------
   --  Privkey loaders.
   -----------------------------------------------------------------------

   procedure Load_Privkey_From_File
     (Key : out Hadawallet.Privkey_Bytes; Ok : out Boolean)
   is
      Path : constant String := Privkey_Path;
      use Ada.Streams.Stream_IO;
      File : File_Type;
      Buf  : Ada.Streams.Stream_Element_Array (1 .. 32);
      Last : Ada.Streams.Stream_Element_Offset;
   begin
      Key := [others => 0];
      Ok := False;
      if not Ada.Directories.Exists (Path) then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "hadawallet: missing privkey file at " & Path);
         return;
      end if;
      Open (File, In_File, Path);
      Read (File, Buf, Last);
      Close (File);
      if Last /= 32 then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "hadawallet: privkey file must be exactly 32 bytes");
         return;
      end if;
      for I in 1 .. 32 loop
         Key (I) :=
           Hadawallet.U8 (Buf (Ada.Streams.Stream_Element_Offset (I)));
      end loop;
      Ok := True;
   end Load_Privkey_From_File;

   procedure Try_Load_From_Mnemonic
     (Key   : out Hadawallet.Privkey_Bytes;
      Found : out Boolean;
      Ok    : out Boolean)
   is
      Path : constant String := Mnemonic_Path;
      use Ada.Streams.Stream_IO;

      File         : File_Type;
      Stream_Buf   : Ada.Streams.Stream_Element_Array (1 .. 4096);
      Last         : Ada.Streams.Stream_Element_Offset := 0;
      Mnemonic_Len : Natural := 0;
      Mnemonic_Buf : String (1 .. 4096);

      Path_String : constant String := Path_Env;
      Path_Buf    :
        Hadawallet.Derivation_Path (1 .. Hadawallet.Max_Path_Depth);
      Path_Len    : Natural;
      Path_Ok     : Boolean;

      Seed         : Hadawallet.Mac_Bytes_512;
      Master_Priv  : Hadawallet.Privkey_Bytes;
      Master_Chain : Hadawallet.Chain_Code;
      Child_Chain  : Hadawallet.Chain_Code;
   begin
      Key := [others => 0];
      Found := False;
      Ok := False;

      if not Ada.Directories.Exists (Path) then
         return;
      end if;

      Found := True;

      Open (File, In_File, Path);
      Read (File, Stream_Buf, Last);
      Close (File);

      --  Convert + trim trailing whitespace and line terminators.
      for I in 1 .. Natural (Last) loop
         Mnemonic_Buf (I) :=
           Character'Val
             (Integer (Stream_Buf (Ada.Streams.Stream_Element_Offset (I))));
      end loop;
      Mnemonic_Len := Natural (Last);
      while Mnemonic_Len > 0
        and then (Mnemonic_Buf (Mnemonic_Len) = Character'Val (10)
                  or else Mnemonic_Buf (Mnemonic_Len) = Character'Val (13)
                  or else Mnemonic_Buf (Mnemonic_Len) = ' '
                  or else Mnemonic_Buf (Mnemonic_Len) = Character'Val (9))
      loop
         Mnemonic_Len := Mnemonic_Len - 1;
      end loop;

      if Mnemonic_Len = 0 then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "hadawallet: empty mnemonic file at " & Path);
         return;
      end if;

      Parse_Path (Path_String, Path_Buf, Path_Len, Path_Ok);
      if not Path_Ok then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "hadawallet: invalid derivation path: " & Path_String);
         return;
      end if;

      Key_Derivation.Mnemonic_To_Seed
        (Mnemonic_Buf (1 .. Mnemonic_Len), "", Seed);
      Key_Derivation.Master_Key_From_Seed (Seed, Master_Priv, Master_Chain);
      Key_Derivation.Derive_Path
        (Master_Priv,
         Master_Chain,
         Path_Buf (1 .. Path_Len),
         Key,
         Child_Chain);

      Ok := True;

      pragma Warnings (Off, "possibly useless assignment");
      Seed := [others => 0];
      Master_Priv := [others => 0];
      Master_Chain := [others => 0];
      Child_Chain := [others => 0];
      Mnemonic_Buf := [others => Character'Val (0)];
      pragma Warnings (On, "possibly useless assignment");
   end Try_Load_From_Mnemonic;

   procedure Load_Active_Privkey
     (Key : out Hadawallet.Privkey_Bytes; Ok : out Boolean)
   is
      Found : Boolean;
   begin
      Try_Load_From_Mnemonic (Key, Found, Ok);
      if Found then
         return;
      end if;
      Load_Privkey_From_File (Key, Ok);
   end Load_Active_Privkey;

   -----------------------------------------------------------------------
   --  Binary stdin/stdout.
   -----------------------------------------------------------------------

   procedure Read_Stdin (Buf : out Hadawallet.Byte_Array; Len : out Natural) is
      N : size_t;
   begin
      N := fread (Buf'Address, 1, size_t (Buf'Length), stdin);
      Len := Natural (N);
   end Read_Stdin;

   procedure Write_Stdout (Buf : Hadawallet.Byte_Array; Len : Natural) is
      Ignored : size_t;
   begin
      if Len > 0 then
         Ignored := fwrite (Buf'Address, 1, size_t (Len), stdout);
      end if;
   end Write_Stdout;

   -----------------------------------------------------------------------
   --  Sign loop.
   -----------------------------------------------------------------------

   procedure Run is
      In_Buf   : Hadawallet.Byte_Array (1 .. Max_Psbt);
      In_Len   : Natural;
      Out_Buf  : Hadawallet.Byte_Array (1 .. Max_Psbt) := [others => 0];
      Out_Len  : Natural;
      Out_Ok   : Boolean;
      Psbt     : Transaction.PSBT;
      Parse_Ok : Boolean;
      Digest   : Hadawallet.Digest_Bytes;
      Sig      : Hadawallet.Signature_Bytes;
      Sig_Len  : Hadawallet.Signature_Length;
      Sig_Ok   : Boolean;
      Privkey  : Hadawallet.Privkey_Bytes;
      Pubkey   : Hadawallet.Pubkey_Bytes;
      Key_Ok   : Boolean;
      Pub_Ok   : Boolean;
   begin
      Read_Stdin (In_Buf, In_Len);
      if In_Len = 0 then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "hadawallet: empty stdin; expected a PSBT byte stream");
         return;
      end if;

      Transaction.Parse (In_Buf (1 .. In_Len), Psbt, Parse_Ok);
      if not Parse_Ok then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error, "hadawallet: PSBT parse failed");
         return;
      end if;

      Load_Active_Privkey (Privkey, Key_Ok);
      if not Key_Ok then
         return;
      end if;

      --  Derive the compressed pubkey BEFORE handing the privkey to
      --  Signing — BIP174 needs the pubkey as the partial_sig key data,
      --  and we want the key bytes to disappear after Load_Privkey.
      Signing.Pubkey_From_Privkey (Privkey, Pubkey, Pub_Ok);
      if not Pub_Ok then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "hadawallet: pubkey derivation failed");
         pragma Warnings (Off, "possibly useless assignment");
         Privkey := [others => 0];
         pragma Warnings (On, "possibly useless assignment");
         return;
      end if;

      Signing.Load_Privkey (Privkey);
      pragma Warnings (Off, "possibly useless assignment");
      Privkey := [others => 0];
      pragma Warnings (On, "possibly useless assignment");

      for I in 1 .. Psbt.Num_Inputs loop
         Transaction.Sighash (Psbt, I, Digest, Sig_Ok);
         if not Sig_Ok then
            Ada.Text_IO.Put_Line
              (Ada.Text_IO.Standard_Error,
               "hadawallet: sighash failed for input"
               & Integer'Image (I)
               & " (non-P2WPKH script?)");
            Signing.Wipe;
            return;
         end if;
         Signing.Sign (Digest, Sig, Sig_Len);
         if Sig_Len = 0 then
            Ada.Text_IO.Put_Line
              (Ada.Text_IO.Standard_Error,
               "hadawallet: ECDSA sign returned 0 bytes for input"
               & Integer'Image (I));
            Signing.Wipe;
            return;
         end if;
         Psbt.Inputs (I).Partial_Sig := Sig;
         Psbt.Inputs (I).Partial_Len := Sig_Len;
         Psbt.Inputs (I).Partial_Pubkey := Pubkey;
      end loop;

      Signing.Wipe;

      Transaction.Serialize (Psbt, Out_Buf, Out_Len, Out_Ok);
      if not Out_Ok then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error, "hadawallet: PSBT serialize failed");
         return;
      end if;

      Write_Stdout (Out_Buf, Out_Len);
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "hadawallet: signed PSBT written ("
         & Natural'Image (Out_Len)
         & " bytes,"
         & Natural'Image (Psbt.Num_Inputs)
         & " inputs)");
   end Run;

end Comm;
