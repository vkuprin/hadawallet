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
    SPARK_Mode    => On,
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

   procedure Load_Privkey (Key : in Hadawallet.Privkey_Bytes)
   with
     Refined_Global  => (Output => (Stored_Key, Key_Is_Loaded)),
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
     Refined_Global  => (Input => (Stored_Key, Key_Is_Loaded)),
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
     Refined_Global  => (Output => (Stored_Key, Key_Is_Loaded)),
     Refined_Depends => ((Stored_Key, Key_Is_Loaded) => null)
   is
   begin
      Stored_Key := [others => 0];
      Key_Is_Loaded := False;
   end Wipe;

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
        Import        => True,
        Convention    => C,
        External_Name => "secp256k1_context_create";

      procedure Context_Destroy (Ctx : System.Address)
      with
        Import        => True,
        Convention    => C,
        External_Name => "secp256k1_context_destroy";

      function Ecdsa_Sign
        (Ctx      : System.Address;
         Sig_Out  : System.Address;
         Msg32    : System.Address;
         Seckey   : System.Address;
         Nonce_Fn : System.Address;
         Ndata    : System.Address) return int
      with
        Import        => True,
        Convention    => C,
        External_Name => "secp256k1_ecdsa_sign";

      function Ecdsa_Sig_Serialize_Der
        (Ctx        : System.Address;
         Output     : System.Address;
         Output_Len : access size_t;
         Sig        : System.Address) return int
      with
        Import        => True,
        Convention    => C,
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

end Signing;
