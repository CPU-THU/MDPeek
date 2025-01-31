#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

volatile char junk;
char buf[BUFSIZ] = "MDPeek PoC.";  // secret

/** 
 * Invokes OCALL to display the enclave buffer to the terminal.
 * This function is used only for debugging.
 */
int printf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

/**
 * Execute a secret-dependent branch. The secret bit is chosen
 * by parameters.
 * @param idx_secret: byte index of the secret string
 * @param idx_byte_offset: bit offset of a specific secret byte
 */
void __attribute__((aligned(4096))) secretDependentBranch(
    int idx_secret, int idx_byte_offset)
{
    // bound check
    if (idx_secret == -1) {
        return;
    }
    volatile size_t tmp[2], tmp_3;
    tmp[1] = 0;
    // extract one bit from the secret string
    int secret_bit = (buf[idx_secret] >> idx_byte_offset) & 1;
    // secret-dependent branch
    if (secret_bit) {
        tmp[tmp[1]] = 0;    // delayed store
        tmp_3 += 1;         // load
    }
    else {
        tmp[tmp[1]] = 0;    // delayed store
        tmp_3 += 1;         // load
    }
    return;
}
