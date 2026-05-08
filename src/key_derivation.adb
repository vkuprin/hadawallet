--  Key_Derivation body — v0.1 stubs.

package body Key_Derivation
  with SPARK_Mode => Off
is

   use type Hadawallet.U8;

   procedure Mnemonic_To_Seed
     (Mnemonic   : in     String;
      Passphrase : in     String;
      Seed       :    out Hadawallet.Mac_Bytes_512)
   is
   begin
      Seed := [others => 0];
      if Mnemonic'Length + Passphrase'Length = 0 then
         null;
      end if;
   end Mnemonic_To_Seed;

   procedure Master_Key_From_Seed
     (Seed       : in     Hadawallet.Mac_Bytes_512;
      Privkey    :    out Hadawallet.Privkey_Bytes;
      Chain_Code :    out Hadawallet.Chain_Code)
   is
   begin
      Privkey    := [others => 0];
      Chain_Code := [others => 0];
      if Seed (Seed'First) = 0 then
         null;
      end if;
   end Master_Key_From_Seed;

   procedure Derive_Path
     (Master_Privkey    : in     Hadawallet.Privkey_Bytes;
      Master_Chain_Code : in     Hadawallet.Chain_Code;
      Path              : in     Hadawallet.Derivation_Path;
      Child_Privkey     :    out Hadawallet.Privkey_Bytes;
      Child_Chain_Code  :    out Hadawallet.Chain_Code)
   is
   begin
      Child_Privkey    := Master_Privkey;
      Child_Chain_Code := Master_Chain_Code;
      if Path'Length = 0 then
         null;
      end if;
   end Derive_Path;

end Key_Derivation;
