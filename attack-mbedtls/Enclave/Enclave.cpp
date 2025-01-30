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
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "mbedtls/bignum.h"
#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/rsa.h"
#include "mbedtls/platform.h"
#include <cstdio>

#define FAIL_SHA	0x1
#define FAIL_AES	0x2
#define FAIL_ECDSA	0x4

#define mbedtls_printf       printf

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 *   'printf' function is required for sgx protobuf logging module.
 */
int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return 0;
}

static int mbedtls_crypto_sha256()
{
    unsigned char output[65];
    memset(output, 0x00, 65);
    if (mbedtls_sha256( (const unsigned char*)"", 0, output, 0 ) != 0 )
    {
        mbedtls_printf ("SHA256 failed\n");
	return -1;
    } else {
        for (int i = 0; i < 32; i++)
            mbedtls_printf("%02x", output[i]);
    }
    mbedtls_printf("\nSHA256 PASSED\n");
    return 0;
}

static int mbedtls_crypto_aes_ctr_enc_dec_buf()
{
    int ret = -1;
    size_t length = 49, outlen, total_len, i, block_size, iv_len;
    unsigned char key[64];
    unsigned char iv[16];
    unsigned char ad[13];
    unsigned char tag[16];
    unsigned char inbuf[64];
    unsigned char encbuf[64];
    unsigned char decbuf[64];

    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_context_t ctx_dec;
    mbedtls_cipher_context_t ctx_enc;

    /*
     * Prepare contexts
     */
    mbedtls_cipher_init( &ctx_dec );
    mbedtls_cipher_init( &ctx_enc );

    memset( key, 0x2a, sizeof( key ) );

    /* Check and get info structures */
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR);
    if( NULL == cipher_info ) goto exit;
    if( mbedtls_cipher_info_from_string( "AES-128-CTR" ) != cipher_info ) goto exit;
    if( strcmp( mbedtls_cipher_info_get_name( cipher_info ),
                         "AES-128-CTR" ) != 0 ) goto exit;

    /* Initialise enc and dec contexts */
    if( 0 != mbedtls_cipher_setup( &ctx_dec, cipher_info ) ) goto exit;
    if( 0 != mbedtls_cipher_setup( &ctx_enc, cipher_info ) ) goto exit;

    if( 0 != mbedtls_cipher_setkey( &ctx_dec, key, 128, MBEDTLS_DECRYPT ) ) goto exit;
    if( 0 != mbedtls_cipher_setkey( &ctx_enc, key, 128, MBEDTLS_ENCRYPT ) ) goto exit;

    /*
     * Do a few encode/decode cycles
     */
    for( i = 0; i < 3; i++ )
    {
    memset( iv , 0x00 + (int)i, sizeof( iv ) );
    memset( ad, 0x10 + (int)i, sizeof( ad ) );
    memset( inbuf, 0x20 + (int)i, sizeof( inbuf ) );

    memset( encbuf, 0, sizeof( encbuf ) );
    memset( decbuf, 0, sizeof( decbuf ) );
    memset( tag, 0, sizeof( tag ) );

    iv_len = sizeof(iv);

    if( 0 != mbedtls_cipher_set_iv( &ctx_dec, iv, iv_len ) ) goto exit;
    if( 0 != mbedtls_cipher_set_iv( &ctx_enc, iv, iv_len ) ) goto exit;

    if( 0 != mbedtls_cipher_reset( &ctx_dec ) ) goto exit;
    if( 0 != mbedtls_cipher_reset( &ctx_enc ) ) goto exit;

    block_size = mbedtls_cipher_get_block_size( &ctx_enc );
    if( 0 == block_size ) goto exit;

    /* encode length number of bytes from inbuf */
    if( 0 != mbedtls_cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) ) goto exit;
    total_len = outlen;

    if( total_len != length ||
                 ( total_len % block_size == 0 &&
                   total_len < length &&
                   total_len + block_size > length ) ) goto exit;

    if( 0 != mbedtls_cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) ) goto exit;
    total_len += outlen;

    if( total_len != length ||
                 ( total_len % block_size == 0 &&
                   total_len > length &&
                   total_len <= length + block_size ) ) goto exit;

    /* decode the previously encoded string */
    if( 0 != mbedtls_cipher_update( &ctx_dec, encbuf, total_len, decbuf, &outlen ) ) goto exit;
    total_len = outlen;

    if( total_len != length ||
                 ( total_len % block_size == 0 &&
                   total_len < length &&
                   total_len + block_size >= length ) ) goto exit;

    if( 0 != mbedtls_cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) ) goto exit;
    total_len += outlen;

    /* check result */
    if( total_len != length ) goto exit;
    if( 0 != memcmp(inbuf, decbuf, length) ) goto exit;
    }
    mbedtls_printf("AES-CTR PASSED\n");
    ret = 0;
exit:
    mbedtls_cipher_free( &ctx_dec );
    mbedtls_cipher_free( &ctx_enc );
    return ret;
}

#define ECPARAMS    MBEDTLS_ECP_DP_SECP192R1

static int mbedtls_crypto_ecdsa()
{
    int ret = 1;
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char message[100];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;
    const char *pers = "ecdsa";

    mbedtls_ecdsa_init( &ctx_sign );
    mbedtls_ecdsa_init( &ctx_verify );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    memset( sig, 0, sizeof( sig ) );
    memset( message, 0x25, sizeof( message ) );

    /*
     * Generate a key pair for signing
     */
    mbedtls_printf( "  . Seeding the random number generator..." );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Generating key pair..." );

    if( ( ret = mbedtls_ecdsa_genkey( &ctx_sign, ECPARAMS,
                              mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok (key size: %d bits)\n", (int) ctx_sign.MBEDTLS_PRIVATE(grp).pbits );

    /*
     * Compute message hash
     */
    mbedtls_printf( "  . Computing message hash..." );

    if( ( ret = mbedtls_sha256( message, sizeof( message ), hash, 0 ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_sha256 returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * Sign message hash
     */
    mbedtls_printf( "  . Signing message hash..." );

    if( ( ret = mbedtls_ecdsa_write_signature( &ctx_sign, MBEDTLS_MD_SHA256,
                                       hash, sizeof( hash ),
                                       sig, sizeof( sig ), &sig_len,
                                       mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_write_signature returned %d\n", ret );
        goto exit;
    }
    mbedtls_printf( " ok (signature length = %u)\n", (unsigned int) sig_len );

    /*
     * Transfer public information to verifying context
     *
     * We could use the same context for verification and signatures, but we
     * chose to use a new one in order to make it clear that the verifying
     * context only needs the public key (Q), and not the private key (d).
     */
    mbedtls_printf( "  . Preparing verification context..." );

    if( ( ret = mbedtls_ecp_group_copy( &ctx_verify.MBEDTLS_PRIVATE(grp), &ctx_sign.MBEDTLS_PRIVATE(grp) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_copy returned %d\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ecp_copy( &ctx_verify.MBEDTLS_PRIVATE(Q), &ctx_sign.MBEDTLS_PRIVATE(Q) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_copy returned %d\n", ret );
        goto exit;
    }

    /*
     * Verify signature
     */
    mbedtls_printf( " ok\n  . Verifying signature..." );

    if( ( ret = mbedtls_ecdsa_read_signature( &ctx_verify,
                                      hash, sizeof( hash ),
                                      sig, sig_len ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_read_signature returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\nECDSA PASSED\n" );

exit:

    mbedtls_ecdsa_free( &ctx_verify );
    mbedtls_ecdsa_free( &ctx_sign );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return ret;
}

#define KEY_SIZE 2048
#define EXPONENT 65537

static int print_bignum(const char *p, const mbedtls_mpi *X) {
    char s[MBEDTLS_MPI_RW_BUFFER_SIZE];
    memset(s, 0, sizeof(s));
    int ret = 1;
    size_t n, slen, plen;

    if ((ret = mbedtls_mpi_write_string(X, 16, s, sizeof(s) - 2, &n)) != 0) {
        mbedtls_printf(" failed\n  ! cannot write bignum to string\n");
        goto exit;
    }
    if (p == NULL) {
        p = "";
    }

    plen = strlen(p);
    slen = strlen(s);
    s[slen++] = '\r';
    s[slen++] = '\n';

    mbedtls_printf("%s%s", p, s);

exit:
    return ret;
}

static int mbedtls_crypto_rsa()
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    const char *pers = "rsa_genkey";


    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_rsa_init(&rsa);
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);

    mbedtls_printf("\n  . Seeding the random number generator...");

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n  . Generating the RSA key [ %d-bit ]...\n", KEY_SIZE);

    if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                   EXPONENT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E)) != 0 ||
        (ret = mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP))      != 0) {
        mbedtls_printf(" failed\n  ! could not export RSA parameters\n\n");
        goto exit;
    }


    mbedtls_printf(" ok\n  . Exporting the private key to stdout...\n");


    if ((ret = print_bignum("N = ", &N)) != 0 ||
        (ret = print_bignum("E = ", &E)) != 0 ||
        (ret = print_bignum("D = ", &D)) != 0 ||
        (ret = print_bignum("P = ", &P)) != 0 ||
        (ret = print_bignum("Q = ", &Q)) != 0 ||
        (ret = print_bignum("DP = ", &DP)) != 0 ||
        (ret = print_bignum("DQ = ", &DQ)) != 0 ||
        (ret = print_bignum("QP = ", &QP)) != 0) {
        mbedtls_printf(" failed\n  ! print_bignum returned %d\n\n", ret);
        goto exit;
    }
    mbedtls_printf(" ok\n\n");
    printf("\nAddr of mbedtls_mpi_inv_mod: 0x%lx\n", mbedtls_mpi_inv_mod);
    printf("Addr of mbedtls_mpi_cmp_mpi: 0x%lx\n", mbedtls_mpi_cmp_mpi);
    printf("Addr of mbedtls_mpi_gen_prime: 0x%lx\n", mbedtls_mpi_gen_prime);
    printf("Addr of mbedtls_rsa_gen_key: 0x%lx\n", mbedtls_rsa_gen_key);
    printf("Addr of mbedtls_mpi_shift_r: 0x%lx\n", mbedtls_mpi_shift_r);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int ecall_mbedtls_crypto()
{
    int ret = 0;
    // if ( 0 != mbedtls_crypto_sha256()) ret |= FAIL_SHA;
    // if ( 0 != mbedtls_crypto_aes_ctr_enc_dec_buf())  ret |= FAIL_AES;
    // if ( 0 != mbedtls_crypto_ecdsa()) ret |= FAIL_ECDSA;
    if ( 0 != mbedtls_crypto_rsa()) ret |= FAIL_ECDSA;
    return ret;

}
