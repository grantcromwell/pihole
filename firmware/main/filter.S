.macro rd32 dst, base, off, tmp
    lbu \dst, \off(\base)
    lbu \tmp, \off+1(\base)
    slli \tmp, \tmp, 8
    or \dst, \dst, \tmp
    lbu \tmp, \off+2(\base)
    slli \tmp, \tmp, 16
    or \dst, \dst, \tmp
    lbu \tmp, \off+3(\base)
    slli \tmp, \tmp, 24
    or \dst, \dst, \tmp
.endm


.macro bump name
    la t0, \name
    lw t1, 0(t0)
    addi t1, t1, 1
    sw t1, 0(t0)
.endm


    .section .bss
    .align 2
    .globl net
    .globl mask
    .globl passed
    .globl foreign
    .globl ported
    .globl stranger
net:
    .space 4
mask:
    .space 4
passed:
    .space 4
foreign:
    .space 4
ported:
    .space 4
stranger:
    .space 4


    .section .text.subnet, "ax"
    .align 2
    .globl subnet
    .type subnet, @function
subnet:
    and a0, a0, a1
    la t0, net
    sw a0, 0(t0)
    la t0, mask
    sw a1, 0(t0)
    ret
    .size subnet, .-subnet


    .section .text.gatekeep, "ax"
    .align 2
    .globl gatekeep
    .type gatekeep, @function
gatekeep:
    la t0, mask
    lw t1, 0(t0)
    beqz t1, .Lstranger

    lhu t2, 10(a0)
    li t3, 20
    bltu t2, t3, .Lstranger

    la t0, net
    lw t4, 0(t0)
    and t5, a1, t1
    beq t5, t4, .Lpass

    lw a2, 4(a0)
    lbu t5, 12(a2)
    slli t5, t5, 24
    lbu t6, 13(a2)
    slli t6, t6, 16
    or t5, t5, t6
    lbu t6, 14(a2)
    slli t6, t6, 8
    or t5, t5, t6
    lbu t6, 15(a2)
    or t5, t5, t6
    and t5, t5, t1
    bne t5, t4, .Lstranger

    li a3, -1
    lbu t5, 9(a2)
    li t6, 6
    beq t5, t6, .Lfour
    li t6, 17
    bne t5, t6, .Lports

.Lfour:
    lbu t5, 6(a2)
    andi t5, t5, 0x1F
    lbu t6, 7(a2)
    or t5, t5, t6
    bnez t5, .Lports

    lbu t5, 0(a2)
    andi t5, t5, 15
    slli t5, t5, 2
    addi t6, t5, 4
    bltu t2, t6, .Lports

    add t6, a2, t5
    lbu a3, 2(t6)
    slli a3, a3, 8
    lbu t5, 3(t6)
    or a3, a3, t5

.Lports:
    la t0, nports
    lw t1, 0(t0)
    la t0, ports

.Lportloop:
    beqz t1, .Ldeny
    lw t5, 0(t0)
    beq t5, a3, .Lported
    addi t0, t0, 4
    addi t1, t1, -1
    j .Lportloop

.Ldeny:
    la t0, ndeny
    lw t1, 0(t0)
    la t0, deny

.Ldenyloop:
    beqz t1, .Lrange
    lw t5, 0(t0)
    bltu a1, t5, .Ldenynext
    lw t6, 4(t0)
    bgtu a1, t6, .Ldenynext
    j .Lforeign

.Ldenynext:
    addi t0, t0, 8
    addi t1, t1, -1
    j .Ldenyloop

.Lrange:
    la t0, _binary_ranges_bin_start
    rd32 a4, t0, 0, t1
    addi a5, t0, 4
    li a6, 0
    addi a7, a4, -1
    li t2, -1

.Lsearch:
    blt a7, a6, .Lfound
    add t3, a6, a7
    srai t3, t3, 1
    slli t4, t3, 3
    add t4, a5, t4
    rd32 t5, t4, 0, t1
    bgtu t5, a1, .Llower
    mv t2, t3
    addi a6, t3, 1
    j .Lsearch

.Llower:
    addi a7, t3, -1
    j .Lsearch

.Lfound:
    bltz t2, .Lforeign
    slli t4, t2, 3
    add t4, a5, t4
    rd32 t5, t4, 4, t1
    bgtu a1, t5, .Lforeign

.Lpass:
    bump passed
    li a0, 1
    ret

.Lported:
    bump ported
    li a0, 0
    ret

.Lforeign:
    bump foreign
    li a0, 0
    ret

.Lstranger:
    bump stranger
    li a0, 0
    ret
    .size gatekeep, .-gatekeep