--  Address body — v0.1 stub.

package body Address
  with SPARK_Mode => Off
is

   procedure Pubkey_To_Address
     (Pubkey  : in     Hadawallet.Pubkey_Bytes;
      Net     : in     Hadawallet.Network;
      Output  :    out String;
      Length  :    out Hadawallet.Address_Length;
      Ok      :    out Boolean)
   is
   begin
      Output := (Output'Range => ' ');
      Length := 0;
      Ok     := False;
      if Pubkey (Pubkey'First) = 0 and then Net = Hadawallet.Bitcoin_Mainnet then
         null;
      end if;
   end Pubkey_To_Address;

end Address;
