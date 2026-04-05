OUTPUT_ARCH( "riscv" )
ENTRY( _start )

SECTIONS
{
  /* Spike usually starts here */
  . = 0x80000000;
  
  .text : {
    *(.text)
  }

  .data : {
    *(.data)
  }

  /DISCARD/ : {
    *(.comment)
    *(.riscv.attributes)
  }
}