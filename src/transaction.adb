--  Transaction body — v0.1 stub.

package body Transaction
  with SPARK_Mode => Off
is

   procedure Parse
     (Bytes : in     Hadawallet.Byte_Array;
      Tx    :    out PSBT;
      Ok    :    out Boolean)
   is
   begin
      Tx := (Initialized => False);
      Ok := False;
      if Bytes'Length = 0 then
         null;
      end if;
   end Parse;

   procedure Sighash
     (Tx          : in     PSBT;
      Input_Index : in     Natural;
      Digest      :    out Hadawallet.Digest_Bytes;
      Ok          :    out Boolean)
   is
   begin
      Digest := [others => 0];
      Ok     := False;
      if Tx.Initialized and then Input_Index = 0 then
         null;
      end if;
   end Sighash;

   procedure Serialize
     (Tx     : in     PSBT;
      Output :    out Hadawallet.Byte_Array;
      Length :    out Natural;
      Ok     :    out Boolean)
   is
   begin
      Output := [others => 0];
      Length := 0;
      Ok     := False;
      if Tx.Initialized then
         null;
      end if;
   end Serialize;

end Transaction;
