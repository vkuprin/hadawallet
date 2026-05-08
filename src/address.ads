--  Address — bech32 (BIP173) encoding for P2WPKH segwit v0 addresses.
--
--  v0.1: API only. Pure-SPARK implementation lands week 3.
--
--  Encoding rules:
--    Mainnet  bc1q  + 32 base32 chars + 6-char checksum  (42 chars total)
--    Testnet  tb1q  + ...                                (42 chars total)
--    Regtest  bcrt1q + ...                               (44 chars total)

with Hadawallet;

package Address
  with SPARK_Mode => On
is

   --  Encode a compressed pubkey as a bech32 P2WPKH address.
   --
   --  Output buffer must be at least Hadawallet.Max_Address_Length chars.
   --  Length receives the count of valid chars; bytes beyond are unspecified.
   --  Ok = False on internal encoding error (should not occur for valid pubkey).
   procedure Pubkey_To_Address
     (Pubkey  : in     Hadawallet.Pubkey_Bytes;
      Net     : in     Hadawallet.Network;
      Output  :    out String;
      Length  :    out Hadawallet.Address_Length;
      Ok      :    out Boolean);

end Address;
