--  Comm body — real stdin/stdout PSBT loop.
--
--  Protocol:
--    stdin  : raw binary PSBT (BIP174 bytes)
--    stdout : raw binary signed PSBT (with partial_sig per input)
--    stderr : diagnostics (sighash, signature length, status)
--
--  Privkey source (v0.1 only):
--    File at $HADAWALLET_PRIVKEY_FILE, or ~/.hadawallet/key.bin.
--    File contains exactly 32 raw bytes. NON-SECURE — production keys
--    will come from BIP39/BIP32 derivation (Phase 4).

pragma Style_Checks ("-s");

with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Environment_Variables;
with Ada.Text_IO;
with Ada.Directories;
with Interfaces.C_Streams;

with Hadawallet;
with Signing;
with Transaction;

package body Comm
  with SPARK_Mode => Off
is

   use type Ada.Streams.Stream_Element_Offset;
   use Interfaces.C_Streams;

   Max_Psbt : constant := 8192;

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

   procedure Read_Stdin (Buf : out Hadawallet.Byte_Array; Len : out Natural) is
      N : size_t;
   begin
      --  Binary-safe stdin read via libc fread. Ada.Text_IO is line-oriented
      --  and would mangle 0x0A bytes in a PSBT.
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
      Key_Ok   : Boolean;
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

      Load_Privkey_From_File (Privkey, Key_Ok);
      if not Key_Ok then
         return;
      end if;

      Signing.Load_Privkey (Privkey);

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
      end loop;

      Signing.Wipe;
      Privkey := [others => 0];

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
