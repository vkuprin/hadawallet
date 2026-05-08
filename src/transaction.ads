--  Transaction — PSBT (BIP174) parsing and serialization.
--
--  v0.1: opaque type + API. v0.3 (week 3) implementation supports
--  the strict subset: P2WPKH segwit v0, single-sig, no taproot, no multisig.
--
--  BIP143 sighash is used for segwit v0.

with Hadawallet;

package Transaction
  with SPARK_Mode => On
is

   type PSBT is private;

   --  Parse a serialized PSBT byte stream.
   --  Ok = False on malformed input or unsupported features.
   procedure Parse
     (Bytes : in     Hadawallet.Byte_Array;
      Tx    :    out PSBT;
      Ok    :    out Boolean);

   --  Compute BIP143 sighash for a given input index.
   procedure Sighash
     (Tx          : in     PSBT;
      Input_Index : in     Natural;
      Digest      :    out Hadawallet.Digest_Bytes;
      Ok          :    out Boolean);

   --  Re-serialize a PSBT with attached signatures.
   procedure Serialize
     (Tx     : in     PSBT;
      Output :    out Hadawallet.Byte_Array;
      Length :    out Natural;
      Ok     :    out Boolean);

private

   --  Opaque placeholder; full record lands week 3.
   type PSBT is record
      Initialized : Boolean := False;
   end record;

end Transaction;
