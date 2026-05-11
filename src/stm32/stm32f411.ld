/*
 * Linker script for STM32F411RE Nucleo (Cortex-M4F).
 *   Flash: 512 KB at 0x0800_0000
 *   SRAM:  128 KB at 0x2000_0000
 *
 * The variant on Nucleo-F411VE / F411CE is 1 MB flash; adjust LENGTH
 * below if your board reports a different ID. The boot ROM expects
 * the initial SP at offset 0 of the flash region and the Reset_Handler
 * at offset 4 — both are placed by the .isr_vector section.
 */

ENTRY(Reset_Handler)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 512K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
    /* Vector table at the very start of flash. Slot 0 is the initial
       stack pointer (SP); slot 1 is the reset handler. */
    .isr_vector :
    {
        LONG(_estack)
        KEEP(*(.isr_vector))
    } > FLASH

    .text :
    {
        *(.text*)
        *(.rodata*)
        _etext = .;
    } > FLASH

    /* Initialised data: lives in flash, copied to RAM by the runtime
       startup. The light-* runtimes shipped with gnat_arm_elf perform
       this copy in their crt0 equivalent. */
    .data : AT(_etext)
    {
        _sdata = .;
        *(.data*)
        _edata = .;
    } > RAM

    .bss :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    } > RAM

    /* Top of the heap; runtime malloc (if present) grows downward
       from _estack. With light-tasking runtimes there is no heap. */
    end = .;
    _end = .;
}
