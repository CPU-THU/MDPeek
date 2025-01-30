# Attack-MbedTLS

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
