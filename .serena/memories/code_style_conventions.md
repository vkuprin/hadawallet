# Code Style & Conventions

## Language and tooling

- **Ada 2022** with **SPARK 2014** annotations (`with SPARK_Mode => On`).
- Build switches (from `hadawallet.gpr`):
  - `-g -O0` (dev), `-gnatwa` (all warnings), `-gnatVa` (all validity checks),
  - `-gnata` (assertions enabled), `-gnat2022`.
- Binder: `-Es` (symbolic traceback).
- Alire build-switches: `ada_version = "Ada2022"`, `contracts = "Yes"`.

## File layout per module

Each module is one package, in two files in `src/`:
- `foo.ads` — spec, `with SPARK_Mode => On`
- `foo.adb` — body, `with SPARK_Mode => Off` while stubbed, flip to `On` per
  procedure as real implementations land.

The root types-only package `hadawallet.ads` is `with SPARK_Mode => On, Pure`.

## Naming

- Packages: `Mixed_Case_With_Underscores` (e.g., `Key_Derivation`, `Comm`).
- Subtypes/types: `Mixed_Case` ending with a kind suffix when it adds clarity
  (`Privkey_Bytes`, `Digest_Bytes`, `Signature_Length`, `Derivation_Path`).
- Procedures/functions: `Mixed_Case` (`Load_Privkey`, `Mnemonic_To_Seed`).
- Parameters: `Mixed_Case` (`Digest`, `Signature`, `Chain_Code`).
- Constants: `Mixed_Case` (`Max_Path_Depth`, `Max_Address_Length`).

## Parameter mode style

Always explicit: `in`, `out`, `in out`. Aligned colons within a parameter list
(see `Key_Derivation.Mnemonic_To_Seed` in `src/key_derivation.ads`).

```ada
procedure Foo
  (Input  : in     T1;
   Output :    out T2;
   Ok     :    out Boolean);
```

## Comments

- Specs carry the docstring: a 1–3 line summary, then a blank `--` line, then
  expanded notes. Use `--` (Ada line comment), wrap ~80 cols.
- Mark architectural rules in ALL CAPS prefix: `ARCHITECTURAL INVARIANT`,
  `ARCHITECTURAL ROLE`.
- Bodies that are stubs explicitly say `--  STUB.` and point to the week the
  real implementation lands.

## SPARK proof targets per module

| Module           | Target                            |
|------------------|-----------------------------------|
| `Signing`        | Platinum (functional correctness) |
| `Key_Derivation` | Gold                              |
| `Hashing`        | Gold                              |
| `Address`        | Gold                              |
| `Transaction`    | Silver (no runtime errors)        |
| `Comm`           | Silver                            |

Baseline today is `--level=1 --report=fail` (no runtime errors). By week 4 this
moves to `--level=4` plus an explicit assertion of the key-isolation flow
contract on `Signing.Sign`.

## Error reporting

Out-parameter `Ok : out Boolean` is the convention for fallible operations
(see `Address.Pubkey_To_Address`, `Transaction.Parse/Sighash/Serialize`).
Length-style operations also return a `Length : out Natural` companion.
No exceptions — SPARK requires this anyway.

## Module imports

Strictly minimal `with` clauses. The compiler will reject unused withs at
`-gnatwa`. Architectural invariants are enforced by NOT importing — e.g.
non-`Comm` modules must not `with Ada.Text_IO`.
