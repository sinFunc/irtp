#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_pkcs1_v15.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/main_test.function
 *      Platform code file  : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/host_test.function
 *      Helper file         : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/helpers.function
 *      Test suite file     : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_pkcs1_v15.function
 *      Test suite data     : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_pkcs1_v15.data
 *
 */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L // for fileno() from <stdio.h>
#endif
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_TEST_HOOKS)
#include "mbedtls/error.h"
#endif

/* Test code may use deprecated identifiers only if the preprocessor symbol
 * MBEDTLS_TEST_DEPRECATED is defined. When building tests, set
 * MBEDTLS_TEST_DEPRECATED explicitly if MBEDTLS_DEPRECATED_WARNING is
 * enabled but the corresponding warnings are not treated as errors.
 */
#if !defined(MBEDTLS_DEPRECATED_REMOVED) && !defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_TEST_DEPRECATED
#endif

/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 2 "suites/helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <test/macros.h>
#include <test/helpers.h>
#include <test/random.h>
#include <test/psa_crypto_helpers.h>

#include <stdlib.h>

#include "mbedtls/platform.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
#include <setjmp.h>
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT8 uint8_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <stdint.h>
#endif

#include <string.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <strings.h>
#endif

/*----------------------------------------------------------------------------*/
/* Status and error constants */

#define DEPENDENCY_SUPPORTED            0   /* Dependency supported by build */
#define KEY_VALUE_MAPPING_FOUND         0   /* Integer expression found */
#define DISPATCH_TEST_SUCCESS           0   /* Test dispatch successful */

#define KEY_VALUE_MAPPING_NOT_FOUND     -1  /* Integer expression not found */
#define DEPENDENCY_NOT_SUPPORTED        -2  /* Dependency not supported */
#define DISPATCH_TEST_FN_NOT_FOUND      -3  /* Test function not found */
#define DISPATCH_INVALID_TEST_DATA      -4  /* Invalid test parameter type.
                                               Only int, string, binary data
                                               and integer expressions are
                                               allowed */
#define DISPATCH_UNSUPPORTED_SUITE      -5  /* Test suite not supported by the
                                               build */

/*----------------------------------------------------------------------------*/
/* Global variables */

#if defined(MBEDTLS_CHECK_PARAMS)
jmp_buf jmp_tmp;
#endif

/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if defined(MBEDTLS_TEST_NULL_ENTROPY) ||             \
    (!defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
    (!defined(MBEDTLS_NO_PLATFORM_ENTROPY)  ||     \
    defined(MBEDTLS_HAVEGE_C)             ||     \
    defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||     \
    defined(ENTROPY_NV_SEED)))
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output(FILE *out_stream, const char *path)
{
    int out_fd, dup_fd;
    FILE *path_stream;

    out_fd = fileno(out_stream);
    dup_fd = dup(out_fd);

    if (dup_fd == -1) {
        return -1;
    }

    path_stream = fopen(path, "w");
    if (path_stream == NULL) {
        close(dup_fd);
        return -1;
    }

    fflush(out_stream);
    if (dup2(fileno(path_stream), out_fd) == -1) {
        close(dup_fd);
        fclose(path_stream);
        return -1;
    }

    fclose(path_stream);
    return dup_fd;
}

static int restore_output(FILE *out_stream, int dup_fd)
{
    int out_fd = fileno(out_stream);

    fflush(out_stream);
    if (dup2(dup_fd, out_fd) == -1) {
        close(out_fd);
        close(dup_fd);
        return -1;
    }

    close(dup_fd);
    return 0;
}
#endif /* __unix__ || __APPLE__ __MACH__ */


#line 55 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test Suite Code */


#define TEST_SUITE_ACTIVE

#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_SHA1_C)
#line 2 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_pkcs1_v15.function"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#line 12 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_pkcs1_v15.function"
void test_pkcs1_rsaes_v15_encrypt(int mod, char *input_N,
                             char *input_E, int hash,
                             data_t *message_str, data_t *rnd_buf,
                             data_t *result_str, int result)
{
    unsigned char output[128];
    mbedtls_rsa_context ctx;
    mbedtls_test_rnd_buf_info info;
    mbedtls_mpi N, E;

    info.fallback_f_rng = mbedtls_test_rnd_std_rand;
    info.fallback_p_rng = NULL;
    info.buf = rnd_buf->x;
    info.length = rnd_buf->len;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, hash);
    memset(output, 0x00, sizeof(output));

    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    TEST_ASSERT(mbedtls_rsa_import(&ctx, &N, NULL, NULL, NULL, &E) == 0);
    TEST_ASSERT(mbedtls_rsa_get_len(&ctx) == (size_t) ((mod + 7) / 8));
    TEST_ASSERT(mbedtls_rsa_check_pubkey(&ctx) == 0);

    if (message_str->len == 0) {
        message_str->x = NULL;
    }
    TEST_ASSERT(mbedtls_rsa_pkcs1_encrypt(&ctx,
                                          &mbedtls_test_rnd_buffer_rand,
                                          &info, MBEDTLS_RSA_PUBLIC,
                                          message_str->len, message_str->x,
                                          output) == result);

    if (result == 0) {
        TEST_ASSERT(mbedtls_test_hexcmp(output, result_str->x,
                                        ctx.len, result_str->len) == 0);
    }

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&E);
    mbedtls_rsa_free(&ctx);
}

void test_pkcs1_rsaes_v15_encrypt_wrapper( void ** params )
{
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};

    test_pkcs1_rsaes_v15_encrypt( *( (int *) params[0] ), (char *) params[1], (char *) params[2], *( (int *) params[3] ), &data4, &data6, &data8, *( (int *) params[10] ) );
}
#line 58 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_pkcs1_v15.function"
void test_pkcs1_rsaes_v15_decrypt(int mod, char *input_P, char *input_Q,
                             char *input_N, char *input_E, int hash,
                             data_t *result_str, char *seed,
                             data_t *message_str, int result)
{
    unsigned char output[128];
    mbedtls_rsa_context ctx;
    size_t output_len;
    mbedtls_test_rnd_pseudo_info rnd_info;
    mbedtls_mpi N, P, Q, E;
    ((void) seed);

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q); mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, hash);

    memset(output, 0x00, sizeof(output));
    memset(&rnd_info, 0, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);

    TEST_ASSERT(mbedtls_rsa_import(&ctx, &N, &P, &Q, NULL, &E) == 0);
    TEST_ASSERT(mbedtls_rsa_get_len(&ctx) == (size_t) ((mod + 7) / 8));
    TEST_ASSERT(mbedtls_rsa_complete(&ctx) == 0);
    TEST_ASSERT(mbedtls_rsa_check_privkey(&ctx) == 0);

    if (result_str->len == 0) {
        TEST_ASSERT(mbedtls_rsa_pkcs1_decrypt(&ctx,
                                              &mbedtls_test_rnd_pseudo_rand,
                                              &rnd_info,
                                              MBEDTLS_RSA_PRIVATE,
                                              &output_len, message_str->x,
                                              NULL, 0) == result);
    } else {
        TEST_ASSERT(mbedtls_rsa_pkcs1_decrypt(&ctx,
                                              &mbedtls_test_rnd_pseudo_rand,
                                              &rnd_info, MBEDTLS_RSA_PRIVATE,
                                              &output_len, message_str->x,
                                              output, 1000) == result);
        if (result == 0) {
            TEST_ASSERT(mbedtls_test_hexcmp(output, result_str->x,
                                            output_len,
                                            result_str->len) == 0);
        }
    }

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q); mbedtls_mpi_free(&E);
    mbedtls_rsa_free(&ctx);
}

void test_pkcs1_rsaes_v15_decrypt_wrapper( void ** params )
{
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data9 = {(uint8_t *) params[9], *( (uint32_t *) params[10] )};

    test_pkcs1_rsaes_v15_decrypt( *( (int *) params[0] ), (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], *( (int *) params[5] ), &data6, (char *) params[8], &data9, *( (int *) params[11] ) );
}
#line 115 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_pkcs1_v15.function"
void test_pkcs1_v15_decode(int mode,
                      data_t *input,
                      int expected_plaintext_length_arg,
                      int output_size_arg,
                      int expected_result)
{
    size_t expected_plaintext_length = expected_plaintext_length_arg;
    size_t output_size = output_size_arg;
    mbedtls_test_rnd_pseudo_info rnd_info;
    mbedtls_mpi Nmpi, Empi, Pmpi, Qmpi;
    mbedtls_rsa_context ctx;
    static unsigned char N[128] = {
        0xc4, 0x79, 0x4c, 0x6d, 0xb2, 0xe9, 0xdf, 0xc5,
        0xe5, 0xd7, 0x55, 0x4b, 0xfb, 0x6c, 0x2e, 0xec,
        0x84, 0xd0, 0x88, 0x12, 0xaf, 0xbf, 0xb4, 0xf5,
        0x47, 0x3c, 0x7e, 0x92, 0x4c, 0x58, 0xc8, 0x73,
        0xfe, 0x8f, 0x2b, 0x8f, 0x8e, 0xc8, 0x5c, 0xf5,
        0x05, 0xeb, 0xfb, 0x0d, 0x7b, 0x2a, 0x93, 0xde,
        0x15, 0x0d, 0xc8, 0x13, 0xcf, 0xd2, 0x6f, 0x0d,
        0x9d, 0xad, 0x30, 0xe5, 0x70, 0x20, 0x92, 0x9e,
        0xb3, 0x6b, 0xba, 0x5c, 0x50, 0x0f, 0xc3, 0xb2,
        0x7e, 0x64, 0x07, 0x94, 0x7e, 0xc9, 0x4e, 0xc1,
        0x65, 0x04, 0xaf, 0xb3, 0x9f, 0xde, 0xa8, 0x46,
        0xfa, 0x6c, 0xf3, 0x03, 0xaf, 0x1c, 0x1b, 0xec,
        0x75, 0x44, 0x66, 0x77, 0xc9, 0xde, 0x51, 0x33,
        0x64, 0x27, 0xb0, 0xd4, 0x8d, 0x31, 0x6a, 0x11,
        0x27, 0x3c, 0x99, 0xd4, 0x22, 0xc0, 0x9d, 0x12,
        0x01, 0xc7, 0x4a, 0x73, 0xac, 0xbf, 0xc2, 0xbb
    };
    static unsigned char E[1] = { 0x03 };
    static unsigned char P[64] = {
        0xe5, 0x53, 0x1f, 0x88, 0x51, 0xee, 0x59, 0xf8,
        0xc1, 0xe4, 0xcc, 0x5b, 0xb3, 0x75, 0x8d, 0xc8,
        0xe8, 0x95, 0x2f, 0xd0, 0xef, 0x37, 0xb4, 0xcd,
        0xd3, 0x9e, 0x48, 0x8b, 0x81, 0x58, 0x60, 0xb9,
        0x27, 0x1d, 0xb6, 0x28, 0x92, 0x64, 0xa3, 0xa5,
        0x64, 0xbd, 0xcc, 0x53, 0x68, 0xdd, 0x3e, 0x55,
        0xea, 0x9d, 0x5e, 0xcd, 0x1f, 0x96, 0x87, 0xf1,
        0x29, 0x75, 0x92, 0x70, 0x8f, 0x28, 0xfb, 0x2b
    };
    static unsigned char Q[64] = {
        0xdb, 0x53, 0xef, 0x74, 0x61, 0xb4, 0x20, 0x3b,
        0x3b, 0x87, 0x76, 0x75, 0x81, 0x56, 0x11, 0x03,
        0x59, 0x31, 0xe3, 0x38, 0x4b, 0x8c, 0x7a, 0x9c,
        0x05, 0xd6, 0x7f, 0x1e, 0x5e, 0x60, 0xf0, 0x4e,
        0x0b, 0xdc, 0x34, 0x54, 0x1c, 0x2e, 0x90, 0x83,
        0x14, 0xef, 0xc0, 0x96, 0x5c, 0x30, 0x10, 0xcc,
        0xc1, 0xba, 0xa0, 0x54, 0x3f, 0x96, 0x24, 0xca,
        0xa3, 0xfb, 0x55, 0xbc, 0x71, 0x29, 0x4e, 0xb1
    };
    unsigned char original[128];
    unsigned char intermediate[128];
    static unsigned char default_content[128] = {
        /* A randomly generated pattern. */
        0x4c, 0x27, 0x54, 0xa0, 0xce, 0x0d, 0x09, 0x4a,
        0x1c, 0x38, 0x8e, 0x2d, 0xa3, 0xc4, 0xe0, 0x19,
        0x4c, 0x99, 0xb2, 0xbf, 0xe6, 0x65, 0x7e, 0x58,
        0xd7, 0xb6, 0x8a, 0x05, 0x2f, 0xa5, 0xec, 0xa4,
        0x35, 0xad, 0x10, 0x36, 0xff, 0x0d, 0x08, 0x50,
        0x74, 0x47, 0xc9, 0x9c, 0x4a, 0xe7, 0xfd, 0xfa,
        0x83, 0x5f, 0x14, 0x5a, 0x1e, 0xe7, 0x35, 0x08,
        0xad, 0xf7, 0x0d, 0x86, 0xdf, 0xb8, 0xd4, 0xcf,
        0x32, 0xb9, 0x5c, 0xbe, 0xa3, 0xd2, 0x89, 0x70,
        0x7b, 0xc6, 0x48, 0x7e, 0x58, 0x4d, 0xf3, 0xef,
        0x34, 0xb7, 0x57, 0x54, 0x79, 0xc5, 0x8e, 0x0a,
        0xa3, 0xbf, 0x6d, 0x42, 0x83, 0x25, 0x13, 0xa2,
        0x95, 0xc0, 0x0d, 0x32, 0xec, 0x77, 0x91, 0x2b,
        0x68, 0xb6, 0x8c, 0x79, 0x15, 0xfb, 0x94, 0xde,
        0xb9, 0x2b, 0x94, 0xb3, 0x28, 0x23, 0x86, 0x3d,
        0x37, 0x00, 0xe6, 0xf1, 0x1f, 0x4e, 0xd4, 0x42
    };
    unsigned char final[128];
    size_t output_length = 0x7EA0;

    memset(&rnd_info, 0, sizeof(mbedtls_test_rnd_pseudo_info));
    mbedtls_mpi_init(&Nmpi); mbedtls_mpi_init(&Empi);
    mbedtls_mpi_init(&Pmpi); mbedtls_mpi_init(&Qmpi);
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&Nmpi, N, sizeof(N)) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&Empi, E, sizeof(E)) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&Pmpi, P, sizeof(P)) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&Qmpi, Q, sizeof(Q)) == 0);

    TEST_ASSERT(mbedtls_rsa_import(&ctx, &Nmpi, &Pmpi, &Qmpi,
                                   NULL, &Empi) == 0);
    TEST_ASSERT(mbedtls_rsa_complete(&ctx) == 0);

    TEST_ASSERT(input->len <= sizeof(N));
    memcpy(original, input->x, input->len);
    memset(original + input->len, 'd', sizeof(original) - input->len);
    if (mode == MBEDTLS_RSA_PRIVATE) {
        TEST_ASSERT(mbedtls_rsa_public(&ctx, original, intermediate) == 0);
    } else {
        TEST_ASSERT(mbedtls_rsa_private(&ctx, &mbedtls_test_rnd_pseudo_rand,
                                        &rnd_info, original,
                                        intermediate) == 0);
    }

    memcpy(final, default_content, sizeof(final));
    TEST_ASSERT(mbedtls_rsa_pkcs1_decrypt(&ctx,
                                          &mbedtls_test_rnd_pseudo_rand,
                                          &rnd_info, mode, &output_length,
                                          intermediate, final,
                                          output_size) == expected_result);
    if (expected_result == 0) {
        TEST_ASSERT(output_length == expected_plaintext_length);
        TEST_ASSERT(memcmp(original + sizeof(N) - output_length,
                           final,
                           output_length) == 0);
    } else if (expected_result == MBEDTLS_ERR_RSA_INVALID_PADDING ||
               expected_result == MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE) {
        size_t max_payload_length =
            output_size > sizeof(N) - 11 ? sizeof(N) - 11 : output_size;
        size_t i;
        size_t count = 0;

#if !defined(MBEDTLS_RSA_ALT)
        /* Check that the output in invalid cases is what the default
         * implementation currently does. Alternative implementations
         * may produce different output, so we only perform these precise
         * checks when using the default implementation. */
        TEST_ASSERT(output_length == max_payload_length);
        for (i = 0; i < max_payload_length; i++) {
            TEST_ASSERT(final[i] == 0);
        }
#endif
        /* Even in alternative implementations, the outputs must have
         * changed, otherwise it indicates at least a timing vulnerability
         * because no write to the outputs is performed in the bad case. */
        TEST_ASSERT(output_length != 0x7EA0);
        for (i = 0; i < max_payload_length; i++) {
            count += (final[i] == default_content[i]);
        }
        /* If more than 16 bytes are unchanged in final, that's evidence
         * that final wasn't overwritten. */
        TEST_ASSERT(count < 16);
    }

exit:
    mbedtls_mpi_free(&Nmpi); mbedtls_mpi_free(&Empi);
    mbedtls_mpi_free(&Pmpi); mbedtls_mpi_free(&Qmpi);
    mbedtls_rsa_free(&ctx);
}

void test_pkcs1_v15_decode_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_pkcs1_v15_decode( *( (int *) params[0] ), &data1, *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ) );
}
#line 262 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_pkcs1_v15.function"
void test_pkcs1_rsassa_v15_sign(int mod, char *input_P,
                           char *input_Q, char *input_N,
                           char *input_E, int digest, int hash,
                           data_t *message_str, data_t *rnd_buf,
                           data_t *result_str, int result)
{
    unsigned char hash_result[MBEDTLS_MD_MAX_SIZE];
    unsigned char output[128];
    mbedtls_rsa_context ctx;
    mbedtls_mpi N, P, Q, E;
    mbedtls_test_rnd_buf_info info;

    info.fallback_f_rng = mbedtls_test_rnd_std_rand;
    info.fallback_p_rng = NULL;
    info.buf = rnd_buf->x;
    info.length = rnd_buf->len;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q); mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, hash);

    memset(hash_result, 0x00, sizeof(hash_result));
    memset(output, 0x00, sizeof(output));

    TEST_ASSERT(mbedtls_test_read_mpi(&P, input_P) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q, input_Q) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);

    TEST_ASSERT(mbedtls_rsa_import(&ctx, &N, &P, &Q, NULL, &E) == 0);
    TEST_ASSERT(mbedtls_rsa_get_len(&ctx) == (size_t) ((mod + 7) / 8));
    TEST_ASSERT(mbedtls_rsa_complete(&ctx) == 0);
    TEST_ASSERT(mbedtls_rsa_check_privkey(&ctx) == 0);


    if (mbedtls_md_info_from_type(digest) != NULL) {
        TEST_ASSERT(mbedtls_md(mbedtls_md_info_from_type(digest), message_str->x, message_str->len,
                               hash_result) == 0);
    }

    TEST_ASSERT(mbedtls_rsa_pkcs1_sign(&ctx, &mbedtls_test_rnd_buffer_rand,
                                       &info, MBEDTLS_RSA_PRIVATE, digest,
                                       0, hash_result, output) == result);
    if (result == 0) {

        TEST_ASSERT(mbedtls_test_hexcmp(output, result_str->x,
                                        ctx.len, result_str->len) == 0);
    }

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q); mbedtls_mpi_free(&E);
    mbedtls_rsa_free(&ctx);
}

void test_pkcs1_rsassa_v15_sign_wrapper( void ** params )
{
    data_t data7 = {(uint8_t *) params[7], *( (uint32_t *) params[8] )};
    data_t data9 = {(uint8_t *) params[9], *( (uint32_t *) params[10] )};
    data_t data11 = {(uint8_t *) params[11], *( (uint32_t *) params[12] )};

    test_pkcs1_rsassa_v15_sign( *( (int *) params[0] ), (char *) params[1], (char *) params[2], (char *) params[3], (char *) params[4], *( (int *) params[5] ), *( (int *) params[6] ), &data7, &data9, &data11, *( (int *) params[13] ) );
}
#line 319 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_pkcs1_v15.function"
void test_pkcs1_rsassa_v15_verify(int mod, char *input_N, char *input_E,
                             int digest, int hash, data_t *message_str,
                             char *salt, data_t *result_str, int result)
{
    unsigned char hash_result[MBEDTLS_MD_MAX_SIZE];
    mbedtls_rsa_context ctx;
    mbedtls_mpi N, E;
    ((void) salt);

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, hash);
    memset(hash_result, 0x00, sizeof(hash_result));

    TEST_ASSERT(mbedtls_test_read_mpi(&N, input_N) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&E, input_E) == 0);
    TEST_ASSERT(mbedtls_rsa_import(&ctx, &N, NULL, NULL, NULL, &E) == 0);
    TEST_ASSERT(mbedtls_rsa_get_len(&ctx) == (size_t) ((mod + 7) / 8));
    TEST_ASSERT(mbedtls_rsa_check_pubkey(&ctx) == 0);


    if (mbedtls_md_info_from_type(digest) != NULL) {
        TEST_ASSERT(mbedtls_md(mbedtls_md_info_from_type(digest), message_str->x, message_str->len,
                               hash_result) == 0);
    }

    TEST_ASSERT(mbedtls_rsa_pkcs1_verify(&ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC, digest, 0,
                                         hash_result, result_str->x) == result);

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&E);
    mbedtls_rsa_free(&ctx);
}

void test_pkcs1_rsassa_v15_verify_wrapper( void ** params )
{
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};

    test_pkcs1_rsassa_v15_verify( *( (int *) params[0] ), (char *) params[1], (char *) params[2], *( (int *) params[3] ), *( (int *) params[4] ), &data5, (char *) params[7], &data8, *( (int *) params[10] ) );
}
#endif /* MBEDTLS_SHA1_C */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PKCS1_V15 */


#line 66 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */


/**
 * \brief       Evaluates an expression/macro into its literal integer value.
 *              For optimizing space for embedded targets each expression/macro
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and evaluation code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Expression identifier.
 * \param out_value Pointer to int to hold the integer.
 *
 * \return       0 if exp_id is found. 1 otherwise.
 */
int get_expression(int32_t exp_id, int32_t *out_value)
{
    int ret = KEY_VALUE_MAPPING_FOUND;

    (void) exp_id;
    (void) out_value;

    switch (exp_id) {
    
#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)

        case 0:
            {
                *out_value = MBEDTLS_MD_NONE;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_MD_SHA1;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_ERR_RSA_INVALID_PADDING;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_RSA_PRIVATE;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_RSA_PUBLIC;
            }
            break;
#endif

#line 94 "suites/main_test.function"
        default:
        {
            ret = KEY_VALUE_MAPPING_NOT_FOUND;
        }
        break;
    }
    return ret;
}


/**
 * \brief       Checks if the dependency i.e. the compile flag is set.
 *              For optimizing space for embedded targets each dependency
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and check code is generated by script:
 *              generate_test_code.py
 *
 * \param dep_id    Dependency identifier.
 *
 * \return       DEPENDENCY_SUPPORTED if set else DEPENDENCY_NOT_SUPPORTED
 */
int dep_check(int dep_id)
{
    int ret = DEPENDENCY_NOT_SUPPORTED;

    (void) dep_id;

    switch (dep_id) {
    
#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)

#endif

#line 124 "suites/main_test.function"
        default:
            break;
    }
    return ret;
}


/**
 * \brief       Function pointer type for test function wrappers.
 *
 * A test function wrapper decodes the parameters and passes them to the
 * underlying test function. Both the wrapper and the underlying function
 * return void. Test wrappers assume that they are passed a suitable
 * parameter array and do not perform any error detection.
 *
 * \param param_array   The array of parameters. Each element is a `void *`
 *                      which the wrapper casts to the correct type and
 *                      dereferences. Each wrapper function hard-codes the
 *                      number and types of the parameters.
 */
typedef void (*TestWrapper_t)(void **param_array);


/**
 * \brief       Table of test function wrappers. Used by dispatch_test().
 *              This table is populated by script:
 *              generate_test_code.py
 *
 */
TestWrapper_t test_funcs[] =
{
    /* Function Id: 0 */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)
    test_pkcs1_rsaes_v15_encrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)
    test_pkcs1_rsaes_v15_decrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)
    test_pkcs1_v15_decode_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)
    test_pkcs1_rsassa_v15_sign_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA1_C)
    test_pkcs1_rsassa_v15_verify_wrapper,
#else
    NULL,
#endif

#line 157 "suites/main_test.function"
};

/**
 * \brief        Execute the test function.
 *
 *               This is a wrapper function around the test function execution
 *               to allow the setjmp() call used to catch any calls to the
 *               parameter failure callback, to be used. Calls to setjmp()
 *               can invalidate the state of any local auto variables.
 *
 * \param fp     Function pointer to the test function.
 * \param params Parameters to pass to the #TestWrapper_t wrapper function.
 *
 */
void execute_function_ptr(TestWrapper_t fp, void **params)
{
#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    mbedtls_test_enable_insecure_external_rng();
#endif

#if defined(MBEDTLS_CHECK_PARAMS)
    mbedtls_test_param_failed_location_record_t location_record;

    if (setjmp(mbedtls_test_param_failed_get_state_buf()) == 0) {
        fp(params);
    } else {
        /* Unexpected parameter validation error */
        mbedtls_test_param_failed_get_location_record(&location_record);
        mbedtls_test_fail(location_record.failure_condition,
                          location_record.line,
                          location_record.file);
    }

    mbedtls_test_param_failed_reset_state();
#else
    fp(params);
#endif

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_check();
#endif /* MBEDTLS_TEST_MUTEX_USAGE */
}

/**
 * \brief        Dispatches test functions based on function index.
 *
 * \param func_idx    Test function index.
 * \param params      The array of parameters to pass to the test function.
 *                    It will be decoded by the #TestWrapper_t wrapper function.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int dispatch_test(size_t func_idx, void **params)
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if (func_idx < (int) (sizeof(test_funcs) / sizeof(TestWrapper_t))) {
        fp = test_funcs[func_idx];
        if (fp) {
            execute_function_ptr(fp, params);
        } else {
            ret = DISPATCH_UNSUPPORTED_SUITE;
        }
    } else {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return ret;
}


/**
 * \brief       Checks if test function is supported in this build-time
 *              configuration.
 *
 * \param func_idx    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int check_test(size_t func_idx)
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if (func_idx < (int) (sizeof(test_funcs)/sizeof(TestWrapper_t))) {
        fp = test_funcs[func_idx];
        if (fp == NULL) {
            ret = DISPATCH_UNSUPPORTED_SUITE;
        }
    } else {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return ret;
}


#line 2 "suites/host_test.function"

/**
 * \brief       Verifies that string is in string parameter format i.e. "<str>"
 *              It also strips enclosing '"' from the input string.
 *
 * \param str   String parameter.
 *
 * \return      0 if success else 1
 */
int verify_string(char **str)
{
    if ((*str)[0] != '"' ||
        (*str)[strlen(*str) - 1] != '"') {
        mbedtls_fprintf(stderr,
                        "Expected string (with \"\") for parameter and got: %s\n", *str);
        return -1;
    }

    (*str)++;
    (*str)[strlen(*str) - 1] = '\0';

    return 0;
}

/**
 * \brief       Verifies that string is an integer. Also gives the converted
 *              integer value.
 *
 * \param str   Input string.
 * \param value Pointer to int for output value.
 *
 * \return      0 if success else 1
 */
int verify_int(char *str, int32_t *value)
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for (i = 0; i < strlen(str); i++) {
        if (i == 0 && str[i] == '-') {
            minus = 1;
            continue;
        }

        if (((minus && i == 2) || (!minus && i == 1)) &&
            str[i - 1] == '0' && (str[i] == 'x' || str[i] == 'X')) {
            hex = 1;
            continue;
        }

        if (!((str[i] >= '0' && str[i] <= '9') ||
              (hex && ((str[i] >= 'a' && str[i] <= 'f') ||
                       (str[i] >= 'A' && str[i] <= 'F'))))) {
            digits = 0;
            break;
        }
    }

    if (digits) {
        if (hex) {
            *value = strtol(str, NULL, 16);
        } else {
            *value = strtol(str, NULL, 10);
        }

        return 0;
    }

    mbedtls_fprintf(stderr,
                    "Expected integer for parameter and got: %s\n", str);
    return KEY_VALUE_MAPPING_NOT_FOUND;
}


/**
 * \brief       Usage string.
 *
 */
#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data files. If no file is\n" \
    "                       specified the following default test case\n" \
    "                       file is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "TESTCASE_FILENAME"


/**
 * \brief       Read a line from the passed file pointer.
 *
 * \param f     FILE pointer
 * \param buf   Pointer to memory to hold read line.
 * \param len   Length of the buf.
 *
 * \return      0 if success else -1
 */
int get_line(FILE *f, char *buf, size_t len)
{
    char *ret;
    int i = 0, str_len = 0, has_string = 0;

    /* Read until we get a valid line */
    do {
        ret = fgets(buf, len, f);
        if (ret == NULL) {
            return -1;
        }

        str_len = strlen(buf);

        /* Skip empty line and comment */
        if (str_len == 0 || buf[0] == '#') {
            continue;
        }
        has_string = 0;
        for (i = 0; i < str_len; i++) {
            char c = buf[i];
            if (c != ' ' && c != '\t' && c != '\n' &&
                c != '\v' && c != '\f' && c != '\r') {
                has_string = 1;
                break;
            }
        }
    } while (!has_string);

    /* Strip new line and carriage return */
    ret = buf + strlen(buf);
    if (ret-- > buf && *ret == '\n') {
        *ret = '\0';
    }
    if (ret-- > buf && *ret == '\r') {
        *ret = '\0';
    }

    return 0;
}

/**
 * \brief       Splits string delimited by ':'. Ignores '\:'.
 *
 * \param buf           Input string
 * \param len           Input string length
 * \param params        Out params found
 * \param params_len    Out params array len
 *
 * \return      Count of strings found.
 */
static int parse_arguments(char *buf, size_t len, char **params,
                           size_t params_len)
{
    size_t cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while (*p != '\0' && p < (buf + len)) {
        if (*p == '\\') {
            p++;
            p++;
            continue;
        }
        if (*p == ':') {
            if (p + 1 < buf + len) {
                cur = p + 1;
                TEST_HELPER_ASSERT(cnt < params_len);
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace newlines, question marks and colons in strings */
    for (i = 0; i < cnt; i++) {
        p = params[i];
        q = params[i];

        while (*p != '\0') {
            if (*p == '\\' && *(p + 1) == 'n') {
                p += 2;
                *(q++) = '\n';
            } else if (*p == '\\' && *(p + 1) == ':') {
                p += 2;
                *(q++) = ':';
            } else if (*p == '\\' && *(p + 1) == '?') {
                p += 2;
                *(q++) = '?';
            } else {
                *(q++) = *(p++);
            }
        }
        *q = '\0';
    }

    return cnt;
}

/**
 * \brief       Converts parameters into test function consumable parameters.
 *              Example: Input:  {"int", "0", "char*", "Hello",
 *                                "hex", "abef", "exp", "1"}
 *                      Output:  {
 *                                0,                // Verified int
 *                                "Hello",          // Verified string
 *                                2, { 0xab, 0xef },// Converted len,hex pair
 *                                9600              // Evaluated expression
 *                               }
 *
 *
 * \param cnt               Parameter array count.
 * \param params            Out array of found parameters.
 * \param int_params_store  Memory for storing processed integer parameters.
 *
 * \return      0 for success else 1
 */
static int convert_params(size_t cnt, char **params, int32_t *int_params_store)
{
    char **cur = params;
    char **out = params;
    int ret = DISPATCH_TEST_SUCCESS;

    while (cur < params + cnt) {
        char *type = *cur++;
        char *val = *cur++;

        if (strcmp(type, "char*") == 0) {
            if (verify_string(&val) == 0) {
                *out++ = val;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "int") == 0) {
            if (verify_int(val, int_params_store) == 0) {
                *out++ = (char *) int_params_store++;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "hex") == 0) {
            if (verify_string(&val) == 0) {
                size_t len;

                TEST_HELPER_ASSERT(
                    mbedtls_test_unhexify((unsigned char *) val, strlen(val),
                                          val, &len) == 0);

                *int_params_store = len;
                *out++ = val;
                *out++ = (char *) (int_params_store++);
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "exp") == 0) {
            int exp_id = strtol(val, NULL, 10);
            if (get_expression(exp_id, int_params_store) == 0) {
                *out++ = (char *) int_params_store++;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else {
            ret = (DISPATCH_INVALID_TEST_DATA);
            break;
        }
    }
    return ret;
}

/**
 * \brief       Tests snprintf implementation with test input.
 *
 * \note
 * At high optimization levels (e.g. gcc -O3), this function may be
 * inlined in run_test_snprintf. This can trigger a spurious warning about
 * potential misuse of snprintf from gcc -Wformat-truncation (observed with
 * gcc 7.2). This warning makes tests in run_test_snprintf redundant on gcc
 * only. They are still valid for other compilers. Avoid this warning by
 * forbidding inlining of this function by gcc.
 *
 * \param n         Buffer test length.
 * \param ref_buf   Expected buffer.
 * \param ref_ret   Expected snprintf return value.
 *
 * \return      0 for success else 1
 */
#if defined(__GNUC__)
__attribute__((__noinline__))
#endif
static int test_snprintf(size_t n, const char *ref_buf, int ref_ret)
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    if (n >= sizeof(buf)) {
        return -1;
    }
    ret = mbedtls_snprintf(buf, n, "%s", "123");
    if (ret < 0 || (size_t) ret >= n) {
        ret = -1;
    }

    if (strncmp(ref_buf, buf, sizeof(buf)) != 0 ||
        ref_ret != ret ||
        memcmp(buf + n, ref + n, sizeof(buf) - n) != 0) {
        return 1;
    }

    return 0;
}

/**
 * \brief       Tests snprintf implementation.
 *
 * \return      0 for success else 1
 */
static int run_test_snprintf(void)
{
    return test_snprintf(0, "xxxxxxxxx",  -1) != 0 ||
           test_snprintf(1, "",           -1) != 0 ||
           test_snprintf(2, "1",          -1) != 0 ||
           test_snprintf(3, "12",         -1) != 0 ||
           test_snprintf(4, "123",         3) != 0 ||
           test_snprintf(5, "123",         3) != 0;
}

/** \brief Write the description of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param argv0         The test suite name.
 * \param test_case     The test case description.
 */
static void write_outcome_entry(FILE *outcome_file,
                                const char *argv0,
                                const char *test_case)
{
    /* The non-varying fields are initialized on first use. */
    static const char *platform = NULL;
    static const char *configuration = NULL;
    static const char *test_suite = NULL;

    if (outcome_file == NULL) {
        return;
    }

    if (platform == NULL) {
        platform = getenv("MBEDTLS_TEST_PLATFORM");
        if (platform == NULL) {
            platform = "unknown";
        }
    }
    if (configuration == NULL) {
        configuration = getenv("MBEDTLS_TEST_CONFIGURATION");
        if (configuration == NULL) {
            configuration = "unknown";
        }
    }
    if (test_suite == NULL) {
        test_suite = strrchr(argv0, '/');
        if (test_suite != NULL) {
            test_suite += 1; // skip the '/'
        } else {
            test_suite = argv0;
        }
    }

    /* Write the beginning of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    mbedtls_fprintf(outcome_file, "%s;%s;%s;%s;",
                    platform, configuration, test_suite, test_case);
}

/** \brief Write the result of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param unmet_dep_count            The number of unmet dependencies.
 * \param unmet_dependencies         The array of unmet dependencies.
 * \param missing_unmet_dependencies Non-zero if there was a problem tracking
 *                                   all unmet dependencies, 0 otherwise.
 * \param ret                        The test dispatch status (DISPATCH_xxx).
 * \param info                       A pointer to the test info structure.
 */
static void write_outcome_result(FILE *outcome_file,
                                 size_t unmet_dep_count,
                                 int unmet_dependencies[],
                                 int missing_unmet_dependencies,
                                 int ret,
                                 const mbedtls_test_info_t *info)
{
    if (outcome_file == NULL) {
        return;
    }

    /* Write the end of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    switch (ret) {
        case DISPATCH_TEST_SUCCESS:
            if (unmet_dep_count > 0) {
                size_t i;
                mbedtls_fprintf(outcome_file, "SKIP");
                for (i = 0; i < unmet_dep_count; i++) {
                    mbedtls_fprintf(outcome_file, "%c%d",
                                    i == 0 ? ';' : ':',
                                    unmet_dependencies[i]);
                }
                if (missing_unmet_dependencies) {
                    mbedtls_fprintf(outcome_file, ":...");
                }
                break;
            }
            switch (info->result) {
                case MBEDTLS_TEST_RESULT_SUCCESS:
                    mbedtls_fprintf(outcome_file, "PASS;");
                    break;
                case MBEDTLS_TEST_RESULT_SKIPPED:
                    mbedtls_fprintf(outcome_file, "SKIP;Runtime skip");
                    break;
                default:
                    mbedtls_fprintf(outcome_file, "FAIL;%s:%d:%s",
                                    info->filename, info->line_no,
                                    info->test);
                    break;
            }
            break;
        case DISPATCH_TEST_FN_NOT_FOUND:
            mbedtls_fprintf(outcome_file, "FAIL;Test function not found");
            break;
        case DISPATCH_INVALID_TEST_DATA:
            mbedtls_fprintf(outcome_file, "FAIL;Invalid test data");
            break;
        case DISPATCH_UNSUPPORTED_SUITE:
            mbedtls_fprintf(outcome_file, "SKIP;Unsupported suite");
            break;
        default:
            mbedtls_fprintf(outcome_file, "FAIL;Unknown cause");
            break;
    }
    mbedtls_fprintf(outcome_file, "\n");
    fflush(outcome_file);
}

/**
 * \brief       Desktop implementation of execute_tests().
 *              Parses command line and executes tests from
 *              supplied or default data file.
 *
 * \param argc  Command line argument count.
 * \param argv  Argument array.
 *
 * \return      Program exit status.
 */
int execute_tests(int argc, const char **argv)
{
    /* Local Configurations and options */
    const char *default_filename = "./test_suite_pkcs1_v15.datax";
    const char *test_filename = NULL;
    const char **test_files = NULL;
    size_t testfile_count = 0;
    int option_verbose = 0;
    size_t function_id = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    size_t testfile_index, i, cnt;
    int ret;
    unsigned total_errors = 0, total_tests = 0, total_skipped = 0;
    FILE *file;
    char buf[5000];
    char *params[50];
    /* Store for processed integer params. */
    int32_t int_params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */
    const char *outcome_file_name = getenv("MBEDTLS_TEST_OUTCOME_FILE");
    FILE *outcome_file = NULL;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_init();
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset(&pointer, 0, sizeof(void *));
    if (pointer != NULL) {
        mbedtls_fprintf(stderr, "all-bits-zero is not a NULL pointer\n");
        return 1;
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if (run_test_snprintf() != 0) {
        mbedtls_fprintf(stderr, "the snprintf implementation is broken\n");
        return 1;
    }

    if (outcome_file_name != NULL && *outcome_file_name != '\0') {
        outcome_file = fopen(outcome_file_name, "a");
        if (outcome_file == NULL) {
            mbedtls_fprintf(stderr, "Unable to open outcome file. Continuing anyway.\n");
        }
    }

    while (arg_index < argc) {
        next_arg = argv[arg_index];

        if (strcmp(next_arg, "--verbose") == 0 ||
            strcmp(next_arg, "-v") == 0) {
            option_verbose = 1;
        } else if (strcmp(next_arg, "--help") == 0 ||
                   strcmp(next_arg, "-h") == 0) {
            mbedtls_fprintf(stdout, USAGE);
            mbedtls_exit(EXIT_SUCCESS);
        } else {
            /* Not an option, therefore treat all further arguments as the file
             * list.
             */
            test_files = &argv[arg_index];
            testfile_count = argc - arg_index;
            break;
        }

        arg_index++;
    }

    /* If no files were specified, assume a default */
    if (test_files == NULL || testfile_count == 0) {
        test_files = &default_filename;
        testfile_count = 1;
    }

    /* Initialize the struct that holds information about the last test */
    mbedtls_test_info_reset();

    /* Now begin to execute the tests in the testfiles */
    for (testfile_index = 0;
         testfile_index < testfile_count;
         testfile_index++) {
        size_t unmet_dep_count = 0;
        int unmet_dependencies[20];
        int missing_unmet_dependencies = 0;

        test_filename = test_files[testfile_index];

        file = fopen(test_filename, "r");
        if (file == NULL) {
            mbedtls_fprintf(stderr, "Failed to open test file: %s\n",
                            test_filename);
            if (outcome_file != NULL) {
                fclose(outcome_file);
            }
            return 1;
        }

        while (!feof(file)) {
            if (unmet_dep_count > 0) {
                mbedtls_fprintf(stderr,
                                "FATAL: Dep count larger than zero at start of loop\n");
                mbedtls_exit(MBEDTLS_EXIT_FAILURE);
            }
            unmet_dep_count = 0;
            missing_unmet_dependencies = 0;

            if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                break;
            }
            mbedtls_fprintf(stdout, "%s%.66s",
                            mbedtls_test_info.result == MBEDTLS_TEST_RESULT_FAILED ?
                            "\n" : "", buf);
            mbedtls_fprintf(stdout, " ");
            for (i = strlen(buf) + 1; i < 67; i++) {
                mbedtls_fprintf(stdout, ".");
            }
            mbedtls_fprintf(stdout, " ");
            fflush(stdout);
            write_outcome_entry(outcome_file, argv[0], buf);

            total_tests++;

            if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                break;
            }
            cnt = parse_arguments(buf, strlen(buf), params,
                                  sizeof(params) / sizeof(params[0]));

            if (strcmp(params[0], "depends_on") == 0) {
                for (i = 1; i < cnt; i++) {
                    int dep_id = strtol(params[i], NULL, 10);
                    if (dep_check(dep_id) != DEPENDENCY_SUPPORTED) {
                        if (unmet_dep_count <
                            ARRAY_LENGTH(unmet_dependencies)) {
                            unmet_dependencies[unmet_dep_count] = dep_id;
                            unmet_dep_count++;
                        } else {
                            missing_unmet_dependencies = 1;
                        }
                    }
                }

                if ((ret = get_line(file, buf, sizeof(buf))) != 0) {
                    break;
                }
                cnt = parse_arguments(buf, strlen(buf), params,
                                      sizeof(params) / sizeof(params[0]));
            }

            // If there are no unmet dependencies execute the test
            if (unmet_dep_count == 0) {
                mbedtls_test_info_reset();

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                /* Suppress all output from the library unless we're verbose
                 * mode
                 */
                if (!option_verbose) {
                    stdout_fd = redirect_output(stdout, "/dev/null");
                    if (stdout_fd == -1) {
                        /* Redirection has failed with no stdout so exit */
                        exit(1);
                    }
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

                function_id = strtoul(params[0], NULL, 10);
                if ((ret = check_test(function_id)) == DISPATCH_TEST_SUCCESS) {
                    ret = convert_params(cnt - 1, params + 1, int_params);
                    if (DISPATCH_TEST_SUCCESS == ret) {
                        ret = dispatch_test(function_id, (void **) (params + 1));
                    }
                }

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                if (!option_verbose && restore_output(stdout, stdout_fd)) {
                    /* Redirection has failed with no stdout so exit */
                    exit(1);
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

            }

            write_outcome_result(outcome_file,
                                 unmet_dep_count, unmet_dependencies,
                                 missing_unmet_dependencies,
                                 ret, &mbedtls_test_info);
            if (unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE) {
                total_skipped++;
                mbedtls_fprintf(stdout, "----");

                if (1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE) {
                    mbedtls_fprintf(stdout, "\n   Test Suite not enabled");
                }

                if (1 == option_verbose && unmet_dep_count > 0) {
                    mbedtls_fprintf(stdout, "\n   Unmet dependencies: ");
                    for (i = 0; i < unmet_dep_count; i++) {
                        mbedtls_fprintf(stdout, "%d ",
                                        unmet_dependencies[i]);
                    }
                    if (missing_unmet_dependencies) {
                        mbedtls_fprintf(stdout, "...");
                    }
                }
                mbedtls_fprintf(stdout, "\n");
                fflush(stdout);

                unmet_dep_count = 0;
                missing_unmet_dependencies = 0;
            } else if (ret == DISPATCH_TEST_SUCCESS) {
                if (mbedtls_test_info.result == MBEDTLS_TEST_RESULT_SUCCESS) {
                    mbedtls_fprintf(stdout, "PASS\n");
                } else if (mbedtls_test_info.result == MBEDTLS_TEST_RESULT_SKIPPED) {
                    mbedtls_fprintf(stdout, "----\n");
                    total_skipped++;
                } else {
                    total_errors++;
                    mbedtls_fprintf(stdout, "FAILED\n");
                    mbedtls_fprintf(stdout, "  %s\n  at ",
                                    mbedtls_test_info.test);
                    if (mbedtls_test_info.step != (unsigned long) (-1)) {
                        mbedtls_fprintf(stdout, "step %lu, ",
                                        mbedtls_test_info.step);
                    }
                    mbedtls_fprintf(stdout, "line %d, %s",
                                    mbedtls_test_info.line_no,
                                    mbedtls_test_info.filename);
                    if (mbedtls_test_info.line1[0] != 0) {
                        mbedtls_fprintf(stdout, "\n  %s",
                                        mbedtls_test_info.line1);
                    }
                    if (mbedtls_test_info.line2[0] != 0) {
                        mbedtls_fprintf(stdout, "\n  %s",
                                        mbedtls_test_info.line2);
                    }
                }
                fflush(stdout);
            } else if (ret == DISPATCH_INVALID_TEST_DATA) {
                mbedtls_fprintf(stderr, "FAILED: FATAL PARSE ERROR\n");
                fclose(file);
                mbedtls_exit(2);
            } else if (ret == DISPATCH_TEST_FN_NOT_FOUND) {
                mbedtls_fprintf(stderr, "FAILED: FATAL TEST FUNCTION NOT FOUND\n");
                fclose(file);
                mbedtls_exit(2);
            } else {
                total_errors++;
            }
        }
        fclose(file);
    }

    if (outcome_file != NULL) {
        fclose(outcome_file);
    }

    mbedtls_fprintf(stdout,
                    "\n----------------------------------------------------------------------------\n\n");
    if (total_errors == 0) {
        mbedtls_fprintf(stdout, "PASSED");
    } else {
        mbedtls_fprintf(stdout, "FAILED");
    }

    mbedtls_fprintf(stdout, " (%u / %u tests (%u skipped))\n",
                    total_tests - total_errors, total_tests, total_skipped);

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

    return total_errors != 0;
}


#line 262 "suites/main_test.function"

/*----------------------------------------------------------------------------*/
/* Main Test code */


/**
 * \brief       Program main. Invokes platform specific execute_tests().
 *
 * \param argc      Command line arguments count.
 * \param argv      Array of command line arguments.
 *
 * \return       Exit code.
 */
int main(int argc, const char *argv[])
{
#if defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_ERROR_C)
    mbedtls_test_hook_error_add = &mbedtls_test_err_add_check;
#endif

    int ret = mbedtls_test_platform_setup();
    if (ret != 0) {
        mbedtls_fprintf(stderr,
                        "FATAL: Failed to initialize platform - error %d\n",
                        ret);
        return -1;
    }

    ret = execute_tests(argc, argv);
    mbedtls_test_platform_teardown();
    return ret;
}
