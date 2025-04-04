.text
.align 1024
.rep 80         # modify this to adjust the first load PC
nop
.endr
.global stld_probe_1
stld_probe_1:
    rdtscp
    shl $32, %rdx
    or %rdx, %rax 
    mov %rax, %r10

    mov	$-8, %r9
    .rep 50
    lea	0x40(%rdi,%r9,8), %rdi
    .endr
    mov	%rdi, (%rdi)
    mov	(%rsi), %rax
    .rep 50
    lea	0x40(%rax,%r9,8), %rax
    .endr

    lfence
    rdtscp
    shl $32, %rdx
    or %rdx, %rax
    sub %r10, %rax
    ret

.align 1024
.rep 107        # modify this to adjust the second load PC
nop
.endr
.global stld_probe_2
stld_probe_2:
    rdtscp
    shl $32, %rdx
    or %rdx, %rax 
    mov %rax, %r10

    mov	$-8, %r9
    .rep 50
    lea	0x40(%rdi,%r9,8), %rdi
    .endr
    mov	%rdi, (%rdi)
    mov	(%rsi), %rax
    .rep 50
    lea	0x40(%rax,%r9,8), %rax
    .endr

    lfence
    rdtscp
    shl $32, %rdx
    or %rdx, %rax
    sub %r10, %rax
    ret