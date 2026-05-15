--  Transaction — PSBT (BIP174) parsing + serialization + BIP143 sighash.
--
--  v0.1 scope: strict P2WPKH segwit v0 only, ≤ 16 inputs / 16 outputs,
--  witness_utxo per input. Taproot, multisig, non-witness inputs, BIP32
--  derivation parsing, and PSBT v2 are out of scope.
--
--  Spec is SPARK_Mode => On with explicit flow contracts so the Comm
--  layer can prove its own flow against this module. Body is
--  SPARK_Mode => Off (byte-level parsing is hard to prove; runtime-error
--  freedom is established by bounded indexing).

with Hadawallet;

package Transaction
  with SPARK_Mode => On
is

   Max_Inputs : constant := 16;
   Max_Outputs : constant := 16;
   Max_Script_Bytes : constant := 64;   --  P2WPKH scriptPubKey is 22 bytes.
   Max_Tx_Bytes : constant := 4096; --  bound the raw unsigned tx blob.
   Max_Psbt_Bytes : constant := 8192; --  bound the whole PSBT blob.

   subtype Input_Index is Natural range 1 .. Max_Inputs;
   subtype Output_Index is Natural range 1 .. Max_Outputs;

   type Outpoint is record
      Txid : Hadawallet.Digest_Bytes;
      Vout : Hadawallet.U32;
   end record;

   type Script_Buffer is record
      Bytes  : Hadawallet.Byte_Array (1 .. Max_Script_Bytes) := [others => 0];
      Length : Natural := 0;
   end record;

   type Input_Record is record
      Prevout        : Outpoint;
      Sequence       : Hadawallet.U32 := 16#FFFF_FFFF#;
      Witness_Amt    : Hadawallet.U64 := 0;
      Witness_Spk    : Script_Buffer;
      Partial_Sig    : Hadawallet.Signature_Bytes := [others => 0];
      Partial_Len    : Hadawallet.Signature_Length := 0;
      --  BIP174 requires the partial_sig key to be 0x02 || compressed
      --  pubkey (34 bytes), not just the type byte. Comm fills this in
      --  before calling Serialize; if unset (all zero), Serialize emits
      --  no partial_sig field.
      Partial_Pubkey : Hadawallet.Pubkey_Bytes := [others => 0];
   end record;

   type Output_Record is record
      Amount : Hadawallet.U64 := 0;
      Script : Script_Buffer;
   end record;

   type Input_Array is array (Input_Index) of Input_Record;
   type Output_Array is array (Output_Index) of Output_Record;

   type PSBT is record
      Initialized : Boolean := False;
      Tx_Version  : Hadawallet.U32 := 2;
      Locktime    : Hadawallet.U32 := 0;
      Num_Inputs  : Natural := 0;
      Num_Outputs : Natural := 0;
      Inputs      : Input_Array;
      Outputs     : Output_Array;
   end record;

   --  Parse a serialized PSBT byte stream.
   --  Ok = False on malformed input, oversize, or unsupported features
   --  (multisig, taproot, non-witness UTXO).
   procedure Parse
     (Bytes : in Hadawallet.Byte_Array; Tx : out PSBT; Ok : out Boolean)
   with Global => null, Depends => ((Tx, Ok) => Bytes);

   --  Compute BIP143 sighash for input Idx, assuming the input is P2WPKH.
   --  Sighash type SIGHASH_ALL (0x01) is hard-wired.
   procedure Sighash
     (Tx     : in PSBT;
      Idx    : in Input_Index;
      Digest : out Hadawallet.Digest_Bytes;
      Ok     : out Boolean)
   with Global => null, Depends => ((Digest, Ok) => (Tx, Idx));

   --  Re-serialize a PSBT, including any Partial_Sig fields populated since
   --  Parse.  Length receives the byte count actually written; bytes beyond
   --  are unspecified.
   procedure Serialize
     (Tx     : in PSBT;
      Output : out Hadawallet.Byte_Array;
      Length : out Natural;
      Ok     : out Boolean)
   with Global => null, Depends => ((Output, Length, Ok) => Tx);

end Transaction;
