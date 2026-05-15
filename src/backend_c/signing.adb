--  Signing body — Phase 2 (key-isolation flow proof) + Phase 5 (secp256k1).
--
--  The Signing body is SPARK_Mode => On, so the Global/Depends contracts on
--  Load_Privkey/Sign/Wipe/Has_Key are checked by gnatprove. The libsecp256k1
--  FFI lives behind FFI_Sign, which is SPARK_Mode => Off but carries an
--  explicit Global/Depends contract that the rest of the body trusts.
--
--  Architectural invariant preserved: no module outside Signing has visibility
--  to Stored_Key. The C call receives the key by pointer but the call site is
--  inside Signing's body. SPARK flow analysis treats FFI_Sign as a black box
--  with the declared dependency Sig depends on (Privkey, Digest), which means
--  the public Sign contract still holds.

with Interfaces.C;
with System;

package body Signing
  with
    SPARK_Mode => On,
    Refined_State => (Key_State => (Stored_Key, Key_Is_Loaded))
is

   Stored_Key    : Hadawallet.Privkey_Bytes := [others => 0];
   Key_Is_Loaded : Boolean := False;

   --  FFI surface. Body is SPARK_Mode => Off (calls into C); contract is
   --  trusted by SPARK at the call site below.
   procedure FFI_Sign
     (Privkey : in Hadawallet.Privkey_Bytes;
      Digest  : in Hadawallet.Digest_Bytes;
      Sig     : out Hadawallet.Signature_Bytes;
      Sig_Len : out Hadawallet.Signature_Length)
   with Global => null, Depends => ((Sig, Sig_Len) => (Privkey, Digest));

   procedure FFI_Tweak_Add
     (Scalar : in out Hadawallet.Privkey_Bytes;
      Tweak  : in Hadawallet.Privkey_Bytes;
      Ok     : out Boolean)
   with Global => null, Depends => ((Scalar, Ok) => (Scalar, Tweak));

   procedure FFI_Pubkey_Create
     (Privkey : in Hadawallet.Privkey_Bytes;
      Pubkey  : out Hadawallet.Pubkey_Bytes;
      Ok      : out Boolean)
   with Global => null, Depends => ((Pubkey, Ok) => Privkey);

   procedure Load_Privkey (Key : in Hadawallet.Privkey_Bytes)
   with
     Refined_Global => (Output => (Stored_Key, Key_Is_Loaded)),
     Refined_Depends => (Stored_Key => Key, Key_Is_Loaded => null)
   is
   begin
      Stored_Key := Key;
      Key_Is_Loaded := True;
   end Load_Privkey;

   function Has_Key return Boolean
   is (Key_Is_Loaded)
   with Refined_Global => (Input => Key_Is_Loaded);

   procedure Sign
     (Digest    : in Hadawallet.Digest_Bytes;
      Signature : out Hadawallet.Signature_Bytes;
      Length    : out Hadawallet.Signature_Length)
   with
     Refined_Global => (Input => (Stored_Key, Key_Is_Loaded)),
     Refined_Depends =>
       ((Signature, Length) => (Stored_Key, Key_Is_Loaded, Digest))
   is
   begin
      Signature := [others => 0];
      if Key_Is_Loaded then
         FFI_Sign (Stored_Key, Digest, Signature, Length);
      else
         Length := 0;
      end if;
   end Sign;

   procedure Wipe
   with
     Refined_Global => (Output => (Stored_Key, Key_Is_Loaded)),
     Refined_Depends => ((Stored_Key, Key_Is_Loaded) => null)
   is
   begin
      Stored_Key := [others => 0];
      Key_Is_Loaded := False;
   end Wipe;

   procedure Tweak_Add_Scalar
     (Scalar : in out Hadawallet.Privkey_Bytes;
      Tweak  : in Hadawallet.Privkey_Bytes;
      Ok     : out Boolean) is
   begin
      FFI_Tweak_Add (Scalar, Tweak, Ok);
   end Tweak_Add_Scalar;

   procedure Pubkey_From_Privkey
     (Privkey : in Hadawallet.Privkey_Bytes;
      Pubkey  : out Hadawallet.Pubkey_Bytes;
      Ok      : out Boolean) is
   begin
      FFI_Pubkey_Create (Privkey, Pubkey, Ok);
   end Pubkey_From_Privkey;

   ---------------------------------------------------------------------------
   --  libsecp256k1 FFI. SPARK_Mode => Off; contract is asserted, not proved.
   ---------------------------------------------------------------------------

   procedure FFI_Sign
     (Privkey : in Hadawallet.Privkey_Bytes;
      Digest  : in Hadawallet.Digest_Bytes;
      Sig     : out Hadawallet.Signature_Bytes;
      Sig_Len : out Hadawallet.Signature_Length)
   is
      pragma SPARK_Mode (Off);
      use Interfaces.C;
      use type System.Address;

      SECP256K1_CONTEXT_NONE : constant unsigned := 1;

      function Context_Create (Flags : unsigned) return System.Address
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_context_create";

      procedure Context_Destroy (Ctx : System.Address)
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_context_destroy";

      function Ecdsa_Sign
        (Ctx      : System.Address;
         Sig_Out  : System.Address;
         Msg32    : System.Address;
         Seckey   : System.Address;
         Nonce_Fn : System.Address;
         Ndata    : System.Address) return int
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_ecdsa_sign";

      function Ecdsa_Sig_Serialize_Der
        (Ctx        : System.Address;
         Output     : System.Address;
         Output_Len : access size_t;
         Sig        : System.Address) return int
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_ecdsa_signature_serialize_der";

      Ctx          : System.Address;
      Internal_Sig : array (0 .. 63) of unsigned_char
      with Convention => C;
      Der_Len      : aliased size_t := 72;
      Rc           : int;
   begin
      Sig := [others => 0];
      Sig_Len := 0;

      Ctx := Context_Create (SECP256K1_CONTEXT_NONE);
      if Ctx = System.Null_Address then
         return;
      end if;

      Rc :=
        Ecdsa_Sign
          (Ctx,
           Internal_Sig'Address,
           Digest'Address,
           Privkey'Address,
           System.Null_Address,
           System.Null_Address);
      if Rc /= 1 then
         Context_Destroy (Ctx);
         return;
      end if;

      Rc :=
        Ecdsa_Sig_Serialize_Der
          (Ctx, Sig'Address, Der_Len'Access, Internal_Sig'Address);
      if Rc = 1 then
         Sig_Len := Hadawallet.Signature_Length (Der_Len);
      end if;

      Context_Destroy (Ctx);
   end FFI_Sign;

   procedure FFI_Tweak_Add
     (Scalar : in out Hadawallet.Privkey_Bytes;
      Tweak  : in Hadawallet.Privkey_Bytes;
      Ok     : out Boolean)
   is
      pragma SPARK_Mode (Off);
      use Interfaces.C;
      use type System.Address;

      SECP256K1_CONTEXT_NONE : constant unsigned := 1;

      function Context_Create (Flags : unsigned) return System.Address
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_context_create";

      procedure Context_Destroy (Ctx : System.Address)
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_context_destroy";

      function Ec_Seckey_Tweak_Add
        (Ctx : System.Address; Seckey : System.Address; Tweak : System.Address)
         return int
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_ec_seckey_tweak_add";

      Ctx : System.Address;
      Rc  : int;
   begin
      Ok := False;
      Ctx := Context_Create (SECP256K1_CONTEXT_NONE);
      if Ctx = System.Null_Address then
         return;
      end if;
      Rc := Ec_Seckey_Tweak_Add (Ctx, Scalar'Address, Tweak'Address);
      Ok := Rc = 1;
      Context_Destroy (Ctx);
   end FFI_Tweak_Add;

   procedure FFI_Pubkey_Create
     (Privkey : in Hadawallet.Privkey_Bytes;
      Pubkey  : out Hadawallet.Pubkey_Bytes;
      Ok      : out Boolean)
   is
      pragma SPARK_Mode (Off);
      use Interfaces.C;
      use type System.Address;

      SECP256K1_CONTEXT_NONE  : constant unsigned := 1;
      --  SECP256K1_EC_COMPRESSED = (1 << 1) | (1 << 8) = 0x102 = 258
      SECP256K1_EC_COMPRESSED : constant unsigned := 258;

      function Context_Create (Flags : unsigned) return System.Address
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_context_create";

      procedure Context_Destroy (Ctx : System.Address)
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_context_destroy";

      function Ec_Pubkey_Create
        (Ctx    : System.Address;
         Pubkey : System.Address;
         Seckey : System.Address) return int
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_ec_pubkey_create";

      function Ec_Pubkey_Serialize
        (Ctx        : System.Address;
         Output     : System.Address;
         Output_Len : access size_t;
         Pubkey     : System.Address;
         Flags      : unsigned) return int
      with
        Import => True,
        Convention => C,
        External_Name => "secp256k1_ec_pubkey_serialize";

      Ctx          : System.Address;
      Internal_Pub : array (0 .. 63) of unsigned_char
      with Convention => C;
      Out_Len      : aliased size_t := 33;
      Rc           : int;
   begin
      Pubkey := [others => 0];
      Ok := False;

      Ctx := Context_Create (SECP256K1_CONTEXT_NONE);
      if Ctx = System.Null_Address then
         return;
      end if;

      Rc := Ec_Pubkey_Create (Ctx, Internal_Pub'Address, Privkey'Address);
      if Rc /= 1 then
         Context_Destroy (Ctx);
         return;
      end if;

      Rc :=
        Ec_Pubkey_Serialize
          (Ctx,
           Pubkey'Address,
           Out_Len'Access,
           Internal_Pub'Address,
           SECP256K1_EC_COMPRESSED);
      Ok := Rc = 1 and then Out_Len = 33;
      Context_Destroy (Ctx);
   end FFI_Pubkey_Create;

end Signing;
