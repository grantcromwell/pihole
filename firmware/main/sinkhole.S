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


    .section .bss
    .align 2
friends:
    .space 192


    .section .text.fnv, "ax"
    .align 2
    .globl fnv
    .type fnv, @function
fnv:
    li a1, 0xcbf29ce4
    li a2, 0x84222325
    li a3, 0x1b3

.Lfnvloop:
    lbu t0, 0(a0)
    beqz t0, .Lfnvdone
    xor a2, a2, t0
    mul t1, a2, a3
    mulhu t2, a2, a3
    mul t3, a1, a3
    add t3, t3, t2
    slli t4, a2, 8
    add a1, t3, t4
    mv a2, t1
    addi a0, a0, 1
    j .Lfnvloop

.Lfnvdone:
    mv a0, a2
    ret
    .size fnv, .-fnv


    .section .text.listed, "ax"
    .align 2
    .globl listed
    .type listed, @function
listed:
    addi sp, sp, -16
    sw ra, 12(sp)
    call fnv
    lw ra, 12(sp)
    addi sp, sp, 16

    la t0, _binary_domains_bin_start
    rd32 a2, t0, 0, t1
    addi t0, t0, 4
    li a3, 0
    addi a4, a2, -1

.Llistloop:
    blt a4, a3, .Lmissing
    add a5, a3, a4
    srai a5, a5, 1
    slli t2, a5, 3
    add t2, t0, t2
    rd32 t3, t2, 0, t1
    rd32 t4, t2, 4, t1
    bne t4, a1, .Lhigh
    bne t3, a0, .Llow
    li a0, 1
    ret

.Lhigh:
    bltu t4, a1, .Lup
    addi a4, a5, -1
    j .Llistloop

.Llow:
    bltu t3, a0, .Lup
    addi a4, a5, -1
    j .Llistloop

.Lup:
    addi a3, a5, 1
    j .Llistloop

.Lmissing:
    li a0, 0
    ret
    .size listed, .-listed


    .section .text.question, "ax"
    .align 2
    .globl question
    .type question, @function
question:
    li t0, 12
    blt a1, t0, .Lno
    lbu t1, 2(a0)
    andi t1, t1, 0x80
    bnez t1, .Lno
    lbu t1, 4(a0)
    bnez t1, .Lno
    lbu t1, 5(a0)
    li t2, 1
    bne t1, t2, .Lno

    li t0, 12
    li t3, 0

.Llabel:
    bge t0, a1, .Lno
    add t4, a0, t0
    lbu t5, 0(t4)
    beqz t5, .Lend
    li t6, 63
    bgtu t5, t6, .Lno
    addi t6, t0, 1
    add t6, t6, t5
    bge t6, a1, .Lno
    add t6, t3, t5
    addi t6, t6, 1
    li a5, 253
    bgt t6, a5, .Lno
    beqz t3, .Lcopy
    add t6, a2, t3
    li a5, '.'
    sb a5, 0(t6)
    addi t3, t3, 1

.Lcopy:
    li a6, 0

.Lchar:
    bge a6, t5, .Lnext
    add t6, t4, a6
    lbu a5, 1(t6)
    li a7, 'A'
    bltu a5, a7, .Lstore
    li a7, 'Z'
    bgtu a5, a7, .Lstore
    addi a5, a5, 32

.Lstore:
    add t6, a2, t3
    sb a5, 0(t6)
    addi t3, t3, 1
    addi a6, a6, 1
    j .Lchar

.Lnext:
    addi t0, t0, 1
    add t0, t0, t5
    j .Llabel

.Lend:
    addi t6, t0, 5
    bgt t6, a1, .Lno
    add t6, a2, t3
    sb zero, 0(t6)
    add t6, a0, t0
    lbu a5, 1(t6)
    slli a5, a5, 8
    lbu a6, 2(t6)
    or a5, a5, a6
    sw a5, 0(a3)
    addi t6, t0, 5
    sw t6, 0(a4)
    beqz t3, .Lno
    li a0, 1
    ret

.Lno:
    li a0, 0
    ret
    .size question, .-question


    .section .text.sinkhole, "ax"
    .align 2
    .globl sinkhole
    .type sinkhole, @function
sinkhole:
    li t0, 0

.Lcopyq:
    bge t0, a1, .Lheader
    add t1, a0, t0
    lbu t2, 0(t1)
    add t1, a3, t0
    sb t2, 0(t1)
    addi t0, t0, 1
    j .Lcopyq

.Lheader:
    lbu t2, 2(a0)
    andi t2, t2, 0x79
    ori t2, t2, 0x80
    sb t2, 2(a3)
    li t2, 0x80
    sb t2, 3(a3)
    sb zero, 6(a3)
    sb zero, 7(a3)
    sb zero, 8(a3)
    sb zero, 9(a3)
    sb zero, 10(a3)
    sb zero, 11(a3)
    mv a0, a1
    li t3, 1
    beq a2, t3, .Lfour
    li t3, 28
    beq a2, t3, .Lsixteen
    ret

.Lfour:
    li t4, 4
    j .Lanswer

.Lsixteen:
    li t4, 16

.Lanswer:
    li t2, 1
    sb t2, 7(a3)
    add t5, a3, a0
    li t2, 0xC0
    sb t2, 0(t5)
    li t2, 0x0C
    sb t2, 1(t5)
    sb zero, 2(t5)
    sb a2, 3(t5)
    sb zero, 4(t5)
    li t2, 1
    sb t2, 5(t5)
    sb zero, 6(t5)
    sb zero, 7(t5)
    sb zero, 8(t5)
    li t2, 2
    sb t2, 9(t5)
    sb zero, 10(t5)
    sb t4, 11(t5)
    addi a0, a0, 12
    add t5, a3, a0
    li t0, 0

.Lzero:
    bge t0, t4, .Ldone
    add t1, t5, t0
    sb zero, 0(t1)
    addi t0, t0, 1
    j .Lzero

.Ldone:
    add a0, a0, t4
    ret
    .size sinkhole, .-sinkhole


    .section .text.calm, "ax"
    .align 2
    .globl calm
    .type calm, @function
calm:
    addi sp, sp, -16
    sw ra, 12(sp)
    sw s0, 8(sp)
    sw s1, 4(sp)
    mv s0, a0
    li a0, 0
    call time

    andi t0, s0, 15
    li t1, 12
    mul t0, t0, t1
    la t1, friends
    add s1, t1, t0

    lw t2, 0(s1)
    bne t2, s0, .Lfresh
    lw t2, 4(s1)
    bne t2, a0, .Lfresh
    j .Lcount

.Lfresh:
    sw s0, 0(s1)
    sw a0, 4(s1)
    sw zero, 8(s1)

.Lcount:
    lw t2, 8(s1)
    addi t2, t2, 1
    sw t2, 8(s1)
    li t3, 50
    slt a0, t3, t2
    xori a0, a0, 1

    lw ra, 12(sp)
    lw s0, 8(sp)
    lw s1, 4(sp)
    addi sp, sp, 16
    ret
    .size calm, .-calm