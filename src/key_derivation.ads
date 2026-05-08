--  Key_Derivation — BIP32/BIP39/BIP44 deterministic key derivation.
--
--  v0.1: API only. Implementations land week 2 atop pure-SPARK Hashing.
--
--  Architectural rule: Key_Derivation is the ONLY module besides
--  Signing that handles raw private key bytes. It exposes a single
--  output path: derive a child key for a given BIP32 path. Callers
--  pass the result directly to Signing.Load_Privkey.

with Hadawallet;

package Key_Derivation
  with SPARK_Mode => On
is

   --  BIP39: derive a 64-byte seed from mnemonic + optional passphrase
   --  via PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase, 2048).
   procedure Mnemonic_To_Seed
     (Mnemonic   : in     String;
      Passphrase : in     String;
      Seed       :    out Hadawallet.Mac_Bytes_512);

   --  BIP32: master key = HMAC-SHA512("Bitcoin seed", seed),
   --  split into (privkey || chain_code).
   procedure Master_Key_From_Seed
     (Seed       : in     Hadawallet.Mac_Bytes_512;
      Privkey    :    out Hadawallet.Privkey_Bytes;
      Chain_Code :    out Hadawallet.Chain_Code);

   --  BIP32: derive child key along path. Hardened indices have bit 31 set.
   procedure Derive_Path
     (Master_Privkey    : in     Hadawallet.Privkey_Bytes;
      Master_Chain_Code : in     Hadawallet.Chain_Code;
      Path              : in     Hadawallet.Derivation_Path;
      Child_Privkey     :    out Hadawallet.Privkey_Bytes;
      Child_Chain_Code  :    out Hadawallet.Chain_Code);

end Key_Derivation;
