.section .boot, "ax"
.global _boot
_boot:
    la t0, _start
    jr t0

.section .text, "ax"
.global _start

_start:
    li x1, 0
    li x2, 1
loop:
    add x1, x1, x2
    li x3, 10
    blt x1, x3, loop

    ecall               

finish:
    j finish