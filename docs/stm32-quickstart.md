# STM32F411 Nucleo quickstart

Phase C deliverable: cross-compile `hadawallet` to STM32F411 Nucleo.

**Status: scaffolding only.** The firmware brings up USART2, prints a
boot banner, runs a SHA-256 self-test, and halts. No PSBT signing on
hardware until Phase D ships pure-SPARK secp256k1 — `BACKEND=ada`'s
`Signing.Sign` currently returns `Length := 0`. See the project plan
at `~/.claude/plans/continue-based-on-our-reactive-charm.md` for the
full roadmap.

## Prerequisites

- An x86_64 Linux or macOS host (the Alire `gnat_arm_elf` crate has
  no aarch64 macOS binary, so M-series Macs need to run the cross-build
  in a Linux VM, container, or x86_64 emulator).
- `arm-none-eabi-gcc` and the matching binutils — bundled by the
  `gnat_arm_elf` crate.
- An ST-Link v2 / v2-1 programmer (the Nucleo's onboard ST-Link is fine).
- Optional: `picocom`, `screen`, or `minicom` to view UART output.

## Toolchain

```bash
alr toolchain --select gnat_arm_elf
# Confirm the cross-compiler is on PATH.
arm-eabi-gcc --version
```

## Build

```bash
alr build -P hadawallet_stm32.gpr
arm-eabi-size bin/hadawallet_stm32.elf
# Expected: text + data well under 512 KB; bss well under 128 KB.
```

If the build complains about a missing runtime, check `alr show
gnat_arm_elf` for the runtimes bundled with the toolchain. The GPR
defaults to `light-cortex-m4f`; alternatives include `light-tasking-stm32f4`
or hand-rolled zfp profiles.

## Flash

```bash
arm-eabi-objcopy -O binary bin/hadawallet_stm32.elf bin/hadawallet_stm32.bin
st-flash write bin/hadawallet_stm32.bin 0x08000000
```

Or via OpenOCD:

```bash
openocd -f board/st_nucleo_f4.cfg \
        -c "program bin/hadawallet_stm32.elf verify reset exit"
```

## Observe

The Nucleo's onboard ST-Link enumerates as a USB-CDC virtual COM
port — typically `/dev/tty.usbmodem*` (macOS) or `/dev/ttyACM0`
(Linux). Open it at 115200 8N1:

```bash
picocom -b 115200 /dev/tty.usbmodem*
# or
screen /dev/ttyACM0 115200
```

Reset the board (the black button) and you should see:

```text
hadawallet stm32f411 boot
sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
status: PASS
[signing backend: BACKEND=ada (stub) — see plan Phase D]
```

## What's missing

Tracked in the plan; in priority order:

1. **Pure-SPARK secp256k1** (Phase D) — without it, `BACKEND=ada`'s
   `Signing.Sign` and `Pubkey_From_Privkey` return failure outputs and
   the firmware can't actually sign.
2. **Comm Backend abstraction** — currently `Comm` and `Transaction`
   are excluded from the cross-build because they pull in `Ada.Text_IO`
   / `Ada.Streams.Stream_IO`, which don't exist in light runtimes. A
   future iteration should refactor `Comm`'s `Read_Stdin` /
   `Write_Stdout` into a `Comm.Backend` interface so the STM32 build
   can wire it to UART.
3. **Mnemonic provisioning** — bare metal has no filesystem; v0.4
   work should embed the mnemonic in flash via a build-time secret
   file or read from an external SPI EEPROM / secure element.
4. **Power / clocking / sleep** — the current driver runs on the
   default 16 MHz HSI clock. Production firmware should configure the
   PLL for 84–100 MHz and enter low-power mode between PSBT sessions.

## Cross-build verification on CI

`.github/workflows/ci.yml` runs the cross-build under
`ubuntu-latest` on `gnat_arm_elf` (x86_64). The job is marked
`continue-on-error: true` until the firmware is validated on real
hardware — file the GitHub issue with `arm-eabi-size` output and a
photo of the boot banner to flip it to required.
