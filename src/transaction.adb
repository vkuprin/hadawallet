--  Transaction body — BIP174 (PSBT) + BIP143 sighash.
--
--  Scope: P2WPKH segwit v0 only; <= 16 inputs/outputs.
--  Body is SPARK_Mode => Off; spec retains Global/Depends so callers can
--  prove their flow against this module.

pragma Style_Checks ("-s");

with Hashing;

package body Transaction
  with SPARK_Mode => Off
is

   use type Hadawallet.U8;
   use type Hadawallet.U32;
   use type Hadawallet.U64;
   use type Hadawallet.Byte_Array;

   ---------------------------------------------------------------------------
   --  Cursor abstraction over a byte buffer
   ---------------------------------------------------------------------------

   type Cursor is record
      Pos  : Positive;
      Last : Natural;
      Bad  : Boolean := False;
   end record;

   function Remaining (C : Cursor) return Natural
   is (if C.Bad or else C.Pos > C.Last then 0 else C.Last - C.Pos + 1);

   procedure Take_Bytes
     (B       : in Hadawallet.Byte_Array;
      C       : in out Cursor;
      N       : in Natural;
      Out_Buf : out Hadawallet.Byte_Array;
      Out_Len : out Natural) is
   begin
      Out_Len := 0;
      if C.Bad or else Remaining (C) < N or else N > Out_Buf'Length then
         C.Bad := True;
         return;
      end if;
      for I in 0 .. N - 1 loop
         Out_Buf (Out_Buf'First + I) := B (C.Pos + I);
      end loop;
      Out_Len := N;
      C.Pos := C.Pos + N;
   end Take_Bytes;

   procedure Take_U8
     (B : Hadawallet.Byte_Array; C : in out Cursor; V : out Hadawallet.U8) is
   begin
      V := 0;
      if C.Bad or else Remaining (C) < 1 then
         C.Bad := True;
         return;
      end if;
      V := B (C.Pos);
      C.Pos := C.Pos + 1;
   end Take_U8;

   procedure Take_LE32
     (B : Hadawallet.Byte_Array; C : in out Cursor; V : out Hadawallet.U32) is
   begin
      V := 0;
      if C.Bad or else Remaining (C) < 4 then
         C.Bad := True;
         return;
      end if;
      V :=
        Hadawallet.U32 (B (C.Pos))
        or Hadawallet.U32 (B (C.Pos + 1)) * 16#100#
        or Hadawallet.U32 (B (C.Pos + 2)) * 16#10000#
        or Hadawallet.U32 (B (C.Pos + 3)) * 16#1000000#;
      C.Pos := C.Pos + 4;
   end Take_LE32;

   procedure Take_LE64
     (B : Hadawallet.Byte_Array; C : in out Cursor; V : out Hadawallet.U64) is
   begin
      V := 0;
      if C.Bad or else Remaining (C) < 8 then
         C.Bad := True;
         return;
      end if;
      for I in 0 .. 7 loop
         V := V or Hadawallet.U64 (B (C.Pos + I)) * (2**(8 * I));
      end loop;
      C.Pos := C.Pos + 8;
   end Take_LE64;

   procedure Take_Varint
     (B : Hadawallet.Byte_Array; C : in out Cursor; V : out Hadawallet.U64)
   is
      Tag : Hadawallet.U8;
   begin
      V := 0;
      Take_U8 (B, C, Tag);
      if C.Bad then
         return;
      end if;
      case Tag is
         when 0 .. 16#FC# =>
            V := Hadawallet.U64 (Tag);

         when 16#FD#      =>
            if Remaining (C) < 2 then
               C.Bad := True;
               return;
            end if;
            V :=
              Hadawallet.U64 (B (C.Pos))
              or Hadawallet.U64 (B (C.Pos + 1)) * 16#100#;
            C.Pos := C.Pos + 2;

         when 16#FE#      =>
            declare
               V32 : Hadawallet.U32;
            begin
               Take_LE32 (B, C, V32);
               V := Hadawallet.U64 (V32);
            end;

         when 16#FF#      =>
            Take_LE64 (B, C, V);
      end case;
   end Take_Varint;

   ---------------------------------------------------------------------------
   --  Writers
   ---------------------------------------------------------------------------

   procedure Put_Varint
     (Out_Buf : in out Hadawallet.Byte_Array;
      Idx     : in out Positive;
      V       : Hadawallet.U64) is
   begin
      if V < 16#FD# then
         Out_Buf (Idx) := Hadawallet.U8 (V);
         Idx := Idx + 1;
      elsif V <= 16#FFFF# then
         Out_Buf (Idx) := 16#FD#;
         Out_Buf (Idx + 1) := Hadawallet.U8 (V mod 16#100#);
         Out_Buf (Idx + 2) := Hadawallet.U8 ((V / 16#100#) mod 16#100#);
         Idx := Idx + 3;
      elsif V <= 16#FFFFFFFF# then
         Out_Buf (Idx) := 16#FE#;
         for I in 0 .. 3 loop
            Out_Buf (Idx + 1 + I) :=
              Hadawallet.U8 ((V / (2**(8 * I))) mod 16#100#);
         end loop;
         Idx := Idx + 5;
      else
         Out_Buf (Idx) := 16#FF#;
         for I in 0 .. 7 loop
            Out_Buf (Idx + 1 + I) :=
              Hadawallet.U8 ((V / (2**(8 * I))) mod 16#100#);
         end loop;
         Idx := Idx + 9;
      end if;
   end Put_Varint;

   procedure Put_LE32
     (Out_Buf : in out Hadawallet.Byte_Array;
      Idx     : in out Positive;
      V       : Hadawallet.U32) is
   begin
      for I in 0 .. 3 loop
         Out_Buf (Idx + I) := Hadawallet.U8 ((V / (2**(8 * I))) mod 16#100#);
      end loop;
      Idx := Idx + 4;
   end Put_LE32;

   procedure Put_LE64
     (Out_Buf : in out Hadawallet.Byte_Array;
      Idx     : in out Positive;
      V       : Hadawallet.U64) is
   begin
      for I in 0 .. 7 loop
         Out_Buf (Idx + I) := Hadawallet.U8 ((V / (2**(8 * I))) mod 16#100#);
      end loop;
      Idx := Idx + 8;
   end Put_LE64;

   procedure Put_Bytes
     (Out_Buf : in out Hadawallet.Byte_Array;
      Idx     : in out Positive;
      Src     : Hadawallet.Byte_Array) is
   begin
      for I in Src'Range loop
         Out_Buf (Idx + (I - Src'First)) := Src (I);
      end loop;
      Idx := Idx + Src'Length;
   end Put_Bytes;

   ---------------------------------------------------------------------------
   --  Unsigned-tx parser (inside global map key 0x00)
   ---------------------------------------------------------------------------

   procedure Parse_Unsigned_Tx
     (Bytes : Hadawallet.Byte_Array; Tx : in out PSBT; C : in out Cursor)
   is
      Num_In, Num_Out, Script_Len : Hadawallet.U64;
      Skip_Buf                    :
        Hadawallet.Byte_Array (1 .. Max_Script_Bytes);
      Skip_Len                    : Natural;
   begin
      Take_LE32 (Bytes, C, Tx.Tx_Version);
      Take_Varint (Bytes, C, Num_In);
      if C.Bad or else Num_In = 0 or else Num_In > Hadawallet.U64 (Max_Inputs)
      then
         C.Bad := True;
         return;
      end if;
      Tx.Num_Inputs := Natural (Num_In);

      for I in 1 .. Tx.Num_Inputs loop
         declare
            Txid_Buf : Hadawallet.Byte_Array (1 .. 32);
            Txid_Len : Natural;
         begin
            Take_Bytes (Bytes, C, 32, Txid_Buf, Txid_Len);
            if C.Bad then
               return;
            end if;
            Tx.Inputs (I).Prevout.Txid := Hadawallet.Digest_Bytes (Txid_Buf);
         end;
         Take_LE32 (Bytes, C, Tx.Inputs (I).Prevout.Vout);
         Take_Varint (Bytes, C, Script_Len);
         if C.Bad then
            return;
         end if;
         if Script_Len > 0 then
            if Script_Len > Hadawallet.U64 (Max_Script_Bytes) then
               C.Bad := True;
               return;
            end if;
            Take_Bytes (Bytes, C, Natural (Script_Len), Skip_Buf, Skip_Len);
         end if;
         Take_LE32 (Bytes, C, Tx.Inputs (I).Sequence);
      end loop;

      Take_Varint (Bytes, C, Num_Out);
      if C.Bad or else Num_Out > Hadawallet.U64 (Max_Outputs) then
         C.Bad := True;
         return;
      end if;
      Tx.Num_Outputs := Natural (Num_Out);

      for I in 1 .. Tx.Num_Outputs loop
         Take_LE64 (Bytes, C, Tx.Outputs (I).Amount);
         Take_Varint (Bytes, C, Script_Len);
         if C.Bad or else Script_Len > Hadawallet.U64 (Max_Script_Bytes) then
            C.Bad := True;
            return;
         end if;
         Take_Bytes
           (Bytes,
            C,
            Natural (Script_Len),
            Tx.Outputs (I).Script.Bytes,
            Tx.Outputs (I).Script.Length);
      end loop;

      Take_LE32 (Bytes, C, Tx.Locktime);
   end Parse_Unsigned_Tx;

   procedure Skip_Value (Bytes : Hadawallet.Byte_Array; C : in out Cursor) is
      Val_Len  : Hadawallet.U64;
      Skip_Buf : Hadawallet.Byte_Array (1 .. Max_Tx_Bytes);
      Skip_Len : Natural;
   begin
      Take_Varint (Bytes, C, Val_Len);
      if C.Bad then
         return;
      end if;
      if Val_Len > Hadawallet.U64 (Max_Tx_Bytes) then
         C.Bad := True;
         return;
      end if;
      Take_Bytes (Bytes, C, Natural (Val_Len), Skip_Buf, Skip_Len);
   end Skip_Value;

   procedure Parse_Global_Map
     (Bytes : Hadawallet.Byte_Array; Tx : in out PSBT; C : in out Cursor)
   is
      Key_Len, Val_Len : Hadawallet.U64;
      Key_Type         : Hadawallet.U8;
   begin
      loop
         Take_Varint (Bytes, C, Key_Len);
         if C.Bad then
            return;
         end if;
         exit when Key_Len = 0;
         if Key_Len > Hadawallet.U64 (Max_Tx_Bytes) then
            C.Bad := True;
            return;
         end if;
         Take_U8 (Bytes, C, Key_Type);
         if C.Bad then
            return;
         end if;
         if Key_Len > 1 then
            declare
               Skip_Buf : Hadawallet.Byte_Array (1 .. Max_Tx_Bytes);
               Skip_Len : Natural;
            begin
               Take_Bytes
                 (Bytes, C, Natural (Key_Len - 1), Skip_Buf, Skip_Len);
               if C.Bad then
                  return;
               end if;
            end;
         end if;

         if Key_Type = 16#00# then
            Take_Varint (Bytes, C, Val_Len);
            if C.Bad then
               return;
            end if;
            if Val_Len > Hadawallet.U64 (Max_Tx_Bytes) then
               C.Bad := True;
               return;
            end if;
            declare
               Saved_Pos : constant Positive := C.Pos;
            begin
               Parse_Unsigned_Tx (Bytes, Tx, C);
               if C.Bad or else C.Pos /= Saved_Pos + Natural (Val_Len) then
                  C.Bad := True;
                  return;
               end if;
            end;
         else
            Skip_Value (Bytes, C);
            if C.Bad then
               return;
            end if;
         end if;
      end loop;
   end Parse_Global_Map;

   procedure Parse_Input_Map
     (Bytes  : Hadawallet.Byte_Array;
      In_Rec : in out Input_Record;
      C      : in out Cursor)
   is
      Key_Len, Val_Len : Hadawallet.U64;
      Key_Type         : Hadawallet.U8;
   begin
      loop
         Take_Varint (Bytes, C, Key_Len);
         if C.Bad then
            return;
         end if;
         exit when Key_Len = 0;
         if Key_Len > Hadawallet.U64 (Max_Tx_Bytes) then
            C.Bad := True;
            return;
         end if;
         Take_U8 (Bytes, C, Key_Type);
         if C.Bad then
            return;
         end if;
         if Key_Len > 1 then
            declare
               Skip_Buf : Hadawallet.Byte_Array (1 .. Max_Tx_Bytes);
               Skip_Len : Natural;
            begin
               Take_Bytes
                 (Bytes, C, Natural (Key_Len - 1), Skip_Buf, Skip_Len);
               if C.Bad then
                  return;
               end if;
            end;
         end if;

         if Key_Type = 16#01# then
            Take_Varint (Bytes, C, Val_Len);
            if C.Bad then
               return;
            end if;
            Take_LE64 (Bytes, C, In_Rec.Witness_Amt);
            declare
               Script_Len : Hadawallet.U64;
            begin
               Take_Varint (Bytes, C, Script_Len);
               if C.Bad or else Script_Len > Hadawallet.U64 (Max_Script_Bytes)
               then
                  C.Bad := True;
                  return;
               end if;
               Take_Bytes
                 (Bytes,
                  C,
                  Natural (Script_Len),
                  In_Rec.Witness_Spk.Bytes,
                  In_Rec.Witness_Spk.Length);
            end;
         else
            Skip_Value (Bytes, C);
            if C.Bad then
               return;
            end if;
         end if;
      end loop;
   end Parse_Input_Map;

   procedure Parse_Output_Map
     (Bytes : Hadawallet.Byte_Array; C : in out Cursor)
   is
      Key_Len  : Hadawallet.U64;
      Key_Type : Hadawallet.U8;
   begin
      loop
         Take_Varint (Bytes, C, Key_Len);
         if C.Bad then
            return;
         end if;
         exit when Key_Len = 0;
         if Key_Len > Hadawallet.U64 (Max_Tx_Bytes) then
            C.Bad := True;
            return;
         end if;
         Take_U8 (Bytes, C, Key_Type);
         if C.Bad then
            return;
         end if;
         if Key_Len > 1 then
            declare
               Skip_Buf : Hadawallet.Byte_Array (1 .. Max_Tx_Bytes);
               Skip_Len : Natural;
            begin
               Take_Bytes
                 (Bytes, C, Natural (Key_Len - 1), Skip_Buf, Skip_Len);
               if C.Bad then
                  return;
               end if;
            end;
         end if;
         Skip_Value (Bytes, C);
         if C.Bad then
            return;
         end if;
      end loop;
   end Parse_Output_Map;

   ---------------------------------------------------------------------------
   --  Public Parse
   ---------------------------------------------------------------------------

   procedure Parse
     (Bytes : in Hadawallet.Byte_Array; Tx : out PSBT; Ok : out Boolean)
   is
      Magic          : Hadawallet.Byte_Array (1 .. 5);
      Magic_Len      : Natural;
      Expected_Magic : constant Hadawallet.Byte_Array (1 .. 5) :=
        [16#70#, 16#73#, 16#62#, 16#74#, 16#FF#];
      C              : Cursor :=
        (Pos => Bytes'First, Last => Bytes'Last, Bad => False);
   begin
      Tx := (Initialized => False, others => <>);
      Ok := False;
      if Bytes'Length > Max_Psbt_Bytes or else Bytes'Length < 6 then
         return;
      end if;

      Take_Bytes (Bytes, C, 5, Magic, Magic_Len);
      if C.Bad or else Magic /= Expected_Magic then
         return;
      end if;

      Parse_Global_Map (Bytes, Tx, C);
      if C.Bad or else Tx.Num_Inputs = 0 then
         return;
      end if;

      for I in 1 .. Tx.Num_Inputs loop
         Parse_Input_Map (Bytes, Tx.Inputs (I), C);
         if C.Bad then
            return;
         end if;
      end loop;
      for I in 1 .. Tx.Num_Outputs loop
         Parse_Output_Map (Bytes, C);
         if C.Bad then
            return;
         end if;
      end loop;

      Tx.Initialized := True;
      Ok := True;
   end Parse;

   ---------------------------------------------------------------------------
   --  BIP143 sighash
   ---------------------------------------------------------------------------

   procedure Hash_Prevouts (Tx : PSBT; Out_Hash : out Hadawallet.Digest_Bytes)
   is
      Buf : Hadawallet.Byte_Array (1 .. 36 * Max_Inputs);
      Idx : Positive := Buf'First;
      Mid : Hadawallet.Digest_Bytes;
   begin
      for I in 1 .. Tx.Num_Inputs loop
         Put_Bytes
           (Buf, Idx, Hadawallet.Byte_Array (Tx.Inputs (I).Prevout.Txid));
         Put_LE32 (Buf, Idx, Tx.Inputs (I).Prevout.Vout);
      end loop;
      Hashing.SHA256 (Buf (Buf'First .. Idx - 1), Mid);
      Hashing.SHA256 (Hadawallet.Byte_Array (Mid), Out_Hash);
   end Hash_Prevouts;

   procedure Hash_Sequence (Tx : PSBT; Out_Hash : out Hadawallet.Digest_Bytes)
   is
      Buf : Hadawallet.Byte_Array (1 .. 4 * Max_Inputs);
      Idx : Positive := Buf'First;
      Mid : Hadawallet.Digest_Bytes;
   begin
      for I in 1 .. Tx.Num_Inputs loop
         Put_LE32 (Buf, Idx, Tx.Inputs (I).Sequence);
      end loop;
      Hashing.SHA256 (Buf (Buf'First .. Idx - 1), Mid);
      Hashing.SHA256 (Hadawallet.Byte_Array (Mid), Out_Hash);
   end Hash_Sequence;

   procedure Hash_Outputs (Tx : PSBT; Out_Hash : out Hadawallet.Digest_Bytes)
   is
      Buf :
        Hadawallet.Byte_Array (1 .. (8 + 9 + Max_Script_Bytes) * Max_Outputs);
      Idx : Positive := Buf'First;
      Mid : Hadawallet.Digest_Bytes;
   begin
      for I in 1 .. Tx.Num_Outputs loop
         Put_LE64 (Buf, Idx, Tx.Outputs (I).Amount);
         Put_Varint (Buf, Idx, Hadawallet.U64 (Tx.Outputs (I).Script.Length));
         Put_Bytes
           (Buf,
            Idx,
            Tx.Outputs (I).Script.Bytes (1 .. Tx.Outputs (I).Script.Length));
      end loop;
      Hashing.SHA256 (Buf (Buf'First .. Idx - 1), Mid);
      Hashing.SHA256 (Hadawallet.Byte_Array (Mid), Out_Hash);
   end Hash_Outputs;

   procedure Sighash
     (Tx     : in PSBT;
      Idx    : in Input_Index;
      Digest : out Hadawallet.Digest_Bytes;
      Ok     : out Boolean)
   is
      H_Prev, H_Seq, H_Out : Hadawallet.Digest_Bytes;
      Spk                  : Script_Buffer;
      Pkh                  : Hadawallet.Byte_Array (1 .. 20);
      Pre                  :
        Hadawallet.Byte_Array
          (1 .. 4 + 32 + 32 + 36 + 27 + 8 + 4 + 32 + 4 + 4);
      P                    : Positive := Pre'First;
      Mid                  : Hadawallet.Digest_Bytes;
   begin
      Digest := [others => 0];
      Ok := False;
      if not Tx.Initialized or else Idx > Tx.Num_Inputs then
         return;
      end if;

      Spk := Tx.Inputs (Idx).Witness_Spk;
      if Spk.Length /= 22
        or else Spk.Bytes (1) /= 16#00#
        or else Spk.Bytes (2) /= 16#14#
      then
         return;
      end if;
      for I in 1 .. 20 loop
         Pkh (I) := Spk.Bytes (2 + I);
      end loop;

      Hash_Prevouts (Tx, H_Prev);
      Hash_Sequence (Tx, H_Seq);
      Hash_Outputs (Tx, H_Out);

      Put_LE32 (Pre, P, Tx.Tx_Version);
      Put_Bytes (Pre, P, Hadawallet.Byte_Array (H_Prev));
      Put_Bytes (Pre, P, Hadawallet.Byte_Array (H_Seq));
      Put_Bytes (Pre, P, Hadawallet.Byte_Array (Tx.Inputs (Idx).Prevout.Txid));
      Put_LE32 (Pre, P, Tx.Inputs (Idx).Prevout.Vout);
      --  scriptCode = varint(25) || OP_DUP OP_HASH160 push20 <pkh>
      --                          OP_EQUALVERIFY OP_CHECKSIG
      Pre (P) := 16#19#;
      P := P + 1;
      Pre (P) := 16#76#;
      P := P + 1;
      Pre (P) := 16#A9#;
      P := P + 1;
      Pre (P) := 16#14#;
      P := P + 1;
      for I in 1 .. 20 loop
         Pre (P) := Pkh (I);
         P := P + 1;
      end loop;
      Pre (P) := 16#88#;
      P := P + 1;
      Pre (P) := 16#AC#;
      P := P + 1;
      Put_LE64 (Pre, P, Tx.Inputs (Idx).Witness_Amt);
      Put_LE32 (Pre, P, Tx.Inputs (Idx).Sequence);
      Put_Bytes (Pre, P, Hadawallet.Byte_Array (H_Out));
      Put_LE32 (Pre, P, Tx.Locktime);
      Put_LE32 (Pre, P, 1);  --  SIGHASH_ALL

      Hashing.SHA256 (Pre (Pre'First .. P - 1), Mid);
      Hashing.SHA256 (Hadawallet.Byte_Array (Mid), Digest);
      Ok := True;
   end Sighash;

   ---------------------------------------------------------------------------
   --  Serialize — emits PSBT bytes, including Partial_Sig fields populated
   --  since Parse. Drops optional fields we didn't store (bip32_derivation
   --  etc.). The partial_sig key in BIP174 normally embeds the pubkey; v0.1
   --  emits a bare key, which is non-standard but accepted by most tools for
   --  single-sig P2WPKH demo flows. Strict-mode tooling will reject.
   ---------------------------------------------------------------------------

   procedure Emit_Unsigned_Tx
     (Tx : PSBT; Out_Buf : in out Hadawallet.Byte_Array; Idx : in out Positive)
   is
   begin
      Put_LE32 (Out_Buf, Idx, Tx.Tx_Version);
      Put_Varint (Out_Buf, Idx, Hadawallet.U64 (Tx.Num_Inputs));
      for I in 1 .. Tx.Num_Inputs loop
         Put_Bytes
           (Out_Buf, Idx, Hadawallet.Byte_Array (Tx.Inputs (I).Prevout.Txid));
         Put_LE32 (Out_Buf, Idx, Tx.Inputs (I).Prevout.Vout);
         Put_Varint (Out_Buf, Idx, 0);   --  empty scriptSig
         Put_LE32 (Out_Buf, Idx, Tx.Inputs (I).Sequence);
      end loop;
      Put_Varint (Out_Buf, Idx, Hadawallet.U64 (Tx.Num_Outputs));
      for I in 1 .. Tx.Num_Outputs loop
         Put_LE64 (Out_Buf, Idx, Tx.Outputs (I).Amount);
         Put_Varint
           (Out_Buf, Idx, Hadawallet.U64 (Tx.Outputs (I).Script.Length));
         Put_Bytes
           (Out_Buf,
            Idx,
            Tx.Outputs (I).Script.Bytes (1 .. Tx.Outputs (I).Script.Length));
      end loop;
      Put_LE32 (Out_Buf, Idx, Tx.Locktime);
   end Emit_Unsigned_Tx;

   procedure Serialize
     (Tx     : in PSBT;
      Output : out Hadawallet.Byte_Array;
      Length : out Natural;
      Ok     : out Boolean)
   is
      Idx     : Positive := Output'First;
      Tx_Buf  : Hadawallet.Byte_Array (1 .. Max_Tx_Bytes);
      Tx_Idx  : Positive := Tx_Buf'First;
      Tx_Size : Natural;
   begin
      Output := [Output'Range => 0];
      Length := 0;
      Ok := False;
      if not Tx.Initialized or else Output'Length < 8 then
         return;
      end if;

      --  magic
      Output (Idx) := 16#70#;
      Output (Idx + 1) := 16#73#;
      Output (Idx + 2) := 16#62#;
      Output (Idx + 3) := 16#74#;
      Output (Idx + 4) := 16#FF#;
      Idx := Idx + 5;

      --  global map: key 0x00 = unsigned tx
      Emit_Unsigned_Tx (Tx, Tx_Buf, Tx_Idx);
      Tx_Size := Tx_Idx - Tx_Buf'First;
      Put_Varint (Output, Idx, 1);                 --  key_len = 1
      Output (Idx) := 16#00#;                      --  key_type = 0
      Idx := Idx + 1;
      Put_Varint (Output, Idx, Hadawallet.U64 (Tx_Size));
      Put_Bytes (Output, Idx, Tx_Buf (Tx_Buf'First .. Tx_Idx - 1));
      Output (Idx) := 16#00#;                      --  global map terminator
      Idx := Idx + 1;

      --  per-input maps
      for I in 1 .. Tx.Num_Inputs loop
         if Tx.Inputs (I).Witness_Spk.Length > 0 then
            Put_Varint (Output, Idx, 1);
            Output (Idx) := 16#01#;
            Idx := Idx + 1;
            declare
               Script_Len : constant Natural :=
                 Tx.Inputs (I).Witness_Spk.Length;
               Val_Size   : constant Natural :=
                 8 + (if Script_Len < 16#FD# then 1 else 3) + Script_Len;
            begin
               Put_Varint (Output, Idx, Hadawallet.U64 (Val_Size));
               Put_LE64 (Output, Idx, Tx.Inputs (I).Witness_Amt);
               Put_Varint (Output, Idx, Hadawallet.U64 (Script_Len));
               Put_Bytes
                 (Output,
                  Idx,
                  Tx.Inputs (I).Witness_Spk.Bytes (1 .. Script_Len));
            end;
         end if;

         if Tx.Inputs (I).Partial_Len > 0 then
            --  BIP174 partial_sig key: 0x02 || compressed pubkey (34 B).
            Put_Varint (Output, Idx, 34);
            Output (Idx) := 16#02#;
            Idx := Idx + 1;
            Put_Bytes
              (Output,
               Idx,
               Hadawallet.Byte_Array (Tx.Inputs (I).Partial_Pubkey));
            --  Value: DER signature || SIGHASH_ALL byte.
            Put_Varint
              (Output, Idx, Hadawallet.U64 (Tx.Inputs (I).Partial_Len) + 1);
            Put_Bytes
              (Output,
               Idx,
               Tx.Inputs (I).Partial_Sig
                 (1 .. Positive (Tx.Inputs (I).Partial_Len)));
            Output (Idx) := 16#01#;  --  SIGHASH_ALL
            Idx := Idx + 1;
         end if;

         Output (Idx) := 16#00#;
         Idx := Idx + 1;
      end loop;

      --  per-output maps (empty)
      for I in 1 .. Tx.Num_Outputs loop
         Output (Idx) := 16#00#;
         Idx := Idx + 1;
      end loop;

      Length := Idx - Output'First;
      Ok := True;
   end Serialize;

end Transaction;
