MEMORY
{
  ROM (rx)  : ORIGIN = 0x00001000, LENGTH = 0x1000
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 16M
}

SECTIONS
{
  /* 1. Codice di Boot (EntryPoint) */
  .boot : {
    KEEP(*(.boot))
  } > ROM

  /* 2. Codice Principale */
  .text : {
    . = ALIGN(4);
    *(.text)
    *(.text.*)
  } > RAM

  /* 3. Dati Read-Only (Costanti, stringhe) */
  .rodata : {
    . = ALIGN(8);
    *(.rodata)
    *(.rodata.*)
    *(.srodata)
    *(.srodata.*)
  } > RAM

  /* 4. Dati Inizializzati (Variabili globali con valore) */
  .data : {
    . = ALIGN(8);
    *(.data)
    *(.data.*)
    *(.sdata)
    *(.sdata.*)
  } > RAM

  /* 5. Dati Non Inizializzati (BSS - azzerati all'avvio) */
  .bss : {
    . = ALIGN(8);
    *(.bss)
    *(.bss.*)
    *(.sbss)
    *(.sbss.*)
    *(COMMON)
  } > RAM

  /* 6. Sezione per la comunicazione Spike (Host/Target) */
  .tohost : { 
    *(.tohost) 
  } > RAM
}