#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

volatile char junk;
char buf[BUFSIZ] = "MDPeek PoC.";  // secret

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
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

void sprintf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    return;
}

void __attribute__((aligned(4096))) secretDependentBranch(int idx_secret, int idx_byte_offset){
    if (idx_secret == -1) {
        return;
    }
    volatile size_t tmp[2], tmp_3;
    tmp[1] = 0;
    int secret_bit = (buf[idx_secret] >> idx_byte_offset) & 1;
    if (secret_bit) {
        tmp[tmp[1]] = 0;
        tmp_3 += 1;
    }
    else {
        tmp[tmp[1]] = 0;
        tmp_3 += 1;
    }
    return;
}
