--  Secp256k1 — pure-SPARK curve math and ECDSA.
--
--  Phase D in the project plan. This is the SKELETON — the bodies of the
--  child packages are unimplemented (return failure / zero outputs) so
--  that BACKEND=ada builds compile and link cleanly without libsecp256k1.
--  Anything that needs a real signature must use BACKEND=c (the
--  libsecp256k1 FFI) until D1+D2+D3 land.
--
--  Planned child packages (see plan):
--    - Secp256k1.Field   : 256-bit modular arithmetic over p = 2^256 - 2^32 - 977
--    - Secp256k1.Scalar  : modular arithmetic over the curve order n
--    - Secp256k1.Group   : affine + Jacobian points, constant-time scalar mul
--    - Secp256k1.Ecdsa   : RFC 6979 deterministic sign + pubkey-from-priv
--    - Secp256k1.Der     : ASN.1 DER encode of (r, s) with BIP62 low-s
--
--  D1 effort estimate: 4–8 weeks solo. D2 (SPARK Silver): +3–4 weeks.
--  D3 (constant-time hardening): +2–3 weeks. D4 (Gold proofs): research-grade.

package Secp256k1
  with SPARK_Mode => On, Pure
is

   --  Sentinel. Bodies of child packages return failure outputs that
   --  callers must check; this constant lets diagnostic code identify
   --  the stubbed backend cleanly.
   Backend_Implemented : constant Boolean := False;

end Secp256k1;
