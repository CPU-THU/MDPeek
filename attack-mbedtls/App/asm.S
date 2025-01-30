.align 1024
.global stld_1
.rep 247  // target load: 0x24e33 (sub-step 1-0)
nop
.endr
stld_1:
    rdtscp
    shl $32, %rdx
    or %rdx, %rax 
    mov %rax, %r10
    .rep 10
    imul $1, %rdi, %rdi
    .endr
    movq $0, (%rdi)
    movl (%rsi), %eax
    .rep 10
    imul $1, %eax, %eax
    .endr
    lfence
    rdtscp
    shl $32, %rdx
    or %rdx, %rax
    sub %r10, %rax
    ret

.align 1024
.global stld_2  // target load: 0x253ae (sub-step 1-1)
.rep 114
nop
.endr
stld_2:
    rdtscp
    shl $32, %rdx
    or %rdx, %rax 
    mov %rax, %r10
    .rep 10
    imul $1, %rdi, %rdi
    .endr
    movq $0, (%rdi)
    movl (%rsi), %eax
    .rep 10
    imul $1, %eax, %eax
    .endr
    lfence
    rdtscp
    shl $32, %rdx
    or %rdx, %rax
    sub %r10, %rax
    ret


.align 1024
.global stld_3  // target load: 0x25005 (sub-step 2-0)
.rep 201
nop
.endr
stld_3:
    rdtscp
    shl $32, %rdx
    or %rdx, %rax 
    mov %rax, %r10
    .rep 10
    imul $1, %rdi, %rdi
    .endr
    movq $0, (%rdi)
    movl (%rsi), %eax
    .rep 10
    imul $1, %eax, %eax
    .endr
    lfence
    rdtscp
    shl $32, %rdx
    or %rdx, %rax
    sub %r10, %rax
    ret

.align 1024
.global stld_4  // target load: 0x25580 (sub-step 2-1)
.rep 68
nop
.endr
stld_4:
    rdtscp
    shl $32, %rdx
    or %rdx, %rax 
    mov %rax, %r10
    .rep 10
    imul $1, %rdi, %rdi
    .endr
    movq $0, (%rdi)
    movl (%rsi), %eax
    .rep 10
    imul $1, %eax, %eax
    .endr
    lfence
    rdtscp
    shl $32, %rdx
    or %rdx, %rax
    sub %r10, %rax
    ret

.align 1024
.global stld_5  // target load: 0x251d7 (sub-step 3-0)
.rep 155
nop
.endr
stld_5:
    rdtscp
    shl $32, %rdx
    or %rdx, %rax 
    mov %rax, %r10
    .rep 10
    imul $1, %rdi, %rdi
    .endr
    movq $0, (%rdi)
    movl (%rsi), %eax
    .rep 10
    imul $1, %eax, %eax
    .endr
    lfence
    rdtscp
    shl $32, %rdx
    or %rdx, %rax
    sub %r10, %rax
    ret

.align 1024
.global stld_6  // target load: 0x256e0 (sub-step 3-1)
.rep 164
nop
.endr
stld_6:
    rdtscp
    shl $32, %rdx
    or %rdx, %rax 
    mov %rax, %r10
    .rep 10
    imul $1, %rdi, %rdi
    .endr
    movq $0, (%rdi)
    movl (%rsi), %eax
    .rep 10
    imul $1, %eax, %eax
    .endr
    lfence
    rdtscp
    shl $32, %rdx
    or %rdx, %rax
    sub %r10, %rax
    ret