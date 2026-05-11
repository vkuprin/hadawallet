# Task Completion Checklist

Run before declaring any task done. The order matters: build first, then prove.

## 1. Build cleanly

```bash
alr build
```

- Must complete with no warnings (compiler is configured with `-gnatwa`).
- If you touched `alire.toml` or `hadawallet.gpr`, run `alr update` first.

## 2. SPARK proof baseline still green

```bash
PATH="$HOME/.alire/bin:$PATH" alr exec -- gnatprove -P hadawallet.gpr --level=1 --report=fail
```

- `--level=1 --report=fail` is the current baseline (no runtime errors).
- Adding `SPARK_Mode => On` on a body that contains uncovered patterns
  (uninitialized out-params, side-effecting calls, unsupported features)
  will break this. Flip mode per procedure, not per package, when in doubt.
- For higher-confidence work approaching week 4 targets, run `--level=4 --report=all`.

## 3. Smoke run still works

```bash
./bin/hadawallet
```

- Prints the banner, runs the (stub) Comm loop, exits 0.
- CI also runs this; if you broke `main.adb` or any of its imports,
  the smoke-test step will fail.

## 4. No new I/O surfaces snuck in

`grep`/`search_for_pattern` for:

- `with Ada.Text_IO` outside `main.adb` and `comm.adb`
- `with Ada.Streams` anywhere outside `comm.adb`
- Anything importing a socket / network library

If a new I/O import shows up where it shouldn't, push back — the
single-boundary architecture is what makes the flow proof meaningful.

## 5. No raw `Privkey_Bytes` leaks

`grep` for `Privkey_Bytes` across modules. Allowed sites:
- `hadawallet.ads` (type declaration)
- `signing.{ads,adb}` (the module that owns the key)
- `key_derivation.{ads,adb}` (`out` param + `in` param to `Signing.Load_Privkey`)

Any other module touching `Privkey_Bytes` is a red flag — investigate before merging.

## 6. Tests (week 2+)

```bash
alr test
```

Not yet wired up in v0.1. Once tests land (planned week 2), add this step.

## 7. Format & lint

No project-wide formatter is configured yet. GNAT compiler warnings (`-gnatwa`)
act as the lint. If/when a `.gnatpp` or similar is added, document it here.

## 8. Git etiquette

- Don't push to `main` directly for non-trivial changes; open a PR.
- CI on push to `main`/`master` and on PRs runs build + level-1 proof + smoke
  run. Make sure GitHub Actions is green before merging.
- Commit messages: short imperative subject line, follow existing repo style
  (see `git log --oneline`).
