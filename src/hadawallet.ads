--  Hadawallet — formally verified Bitcoin hardware wallet firmware.
--
--  This root package defines the shared types used by all modules.
--  It is Pure: no state, no exceptions, just type declarations.

package Hadawallet
  with SPARK_Mode => On, Pure
is

   --  Unsigned word types.
   type U8 is mod 2**8 with Size => 8;
   type U32 is mod 2**32 with Size => 32;
   type U64 is mod 2**64 with Size => 64;

   --  Generic byte buffer.
   type Byte_Array is array (Positive range <>) of U8;

   --  Cryptographic primitives.
   subtype Privkey_Bytes is Byte_Array (1 .. 32);   --  secp256k1 scalar
   subtype Pubkey_Bytes is Byte_Array (1 .. 33);   --  compressed
   subtype Chain_Code is Byte_Array (1 .. 32);   --  BIP32
   subtype Digest_Bytes is Byte_Array (1 .. 32);   --  SHA-256
   subtype Hash160_Bytes is Byte_Array (1 .. 20);   --  RIPEMD-160(SHA-256)
   subtype Mac_Bytes_512 is Byte_Array (1 .. 64);   --  HMAC-SHA512
   subtype Signature_Bytes is Byte_Array (1 .. 72);   --  DER-encoded ECDSA max
   subtype Signature_Length is Natural range 0 .. 72;

   --  BIP32 derivation paths. Hardening bit = bit 31 of element.
   Max_Path_Depth : constant := 8;
   type Path_Element is new U32;
   type Derivation_Path is array (Positive range <>) of Path_Element;

   --  bech32 P2WPKH: bc1q (mainnet), tb1q (testnet), bcrt1q (regtest).
   --  Max length across networks is 64 chars.
   Max_Address_Length : constant := 64;
   subtype Address_Length is Natural range 0 .. Max_Address_Length;

   --  Network selector for address encoding and SLIP-44 path coin type.
   type Network is (Bitcoin_Mainnet, Bitcoin_Testnet, Bitcoin_Regtest);

end Hadawallet;
