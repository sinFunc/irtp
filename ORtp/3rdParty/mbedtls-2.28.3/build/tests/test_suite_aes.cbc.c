#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_aes.cbc.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/main_test.function
 *      Platform code file  : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/host_test.function
 *      Helper file         : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/helpers.function
 *      Test suite file     : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function
 *      Test suite data     : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.cbc.data
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

#if defined(MBEDTLS_AES_C)
#line 2 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
#include "mbedtls/aes.h"

/* Test AES with a copied context.
 *
 * enc and dec must be AES context objects. They don't need to
 * be initialized, and are left freed.
 */
static int test_ctx_alignment(const data_t *key,
                              mbedtls_aes_context *enc,
                              mbedtls_aes_context *dec)
{
    unsigned char plaintext[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    unsigned char ciphertext[16];
    unsigned char output[16];

    // Set key and encrypt with original context
    mbedtls_aes_init(enc);
    TEST_ASSERT(mbedtls_aes_setkey_enc(enc, key->x, key->len * 8) == 0);
    TEST_ASSERT(mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_ENCRYPT,
                                      plaintext, ciphertext) == 0);

    // Set key for decryption with original context
    mbedtls_aes_init(dec);
    TEST_ASSERT(mbedtls_aes_setkey_dec(dec, key->x, key->len * 8) == 0);

    // Wipe the original context to make sure nothing from it is used
    memset(enc, 0, sizeof(*enc));
    mbedtls_aes_free(enc);

    // Decrypt
    TEST_ASSERT(mbedtls_aes_crypt_ecb(dec, MBEDTLS_AES_DECRYPT,
                                      ciphertext, output) == 0);
    ASSERT_COMPARE(plaintext, 16, output, 16);

    mbedtls_aes_free(dec);

    return 1;

exit:
    /* Bug: we may be leaving something unfreed. This is harmless
     * in our built-in implementations, but might cause a memory leak
     * with alternative implementations. */
    return 0;
}

#line 58 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_encrypt_ecb(data_t *key_str, data_t *src_str,
                     data_t *dst, int setkey_result)
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);

    mbedtls_aes_init(&ctx);

    TEST_ASSERT(mbedtls_aes_setkey_enc(&ctx, key_str->x, key_str->len * 8) == setkey_result);
    if (setkey_result == 0) {
        TEST_ASSERT(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, src_str->x, output) == 0);

        TEST_ASSERT(mbedtls_test_hexcmp(output, dst->x, 16, dst->len) == 0);
    }

exit:
    mbedtls_aes_free(&ctx);
}

void test_aes_encrypt_ecb_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_aes_encrypt_ecb( &data0, &data2, &data4, *( (int *) params[6] ) );
}
#line 81 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_decrypt_ecb(data_t *key_str, data_t *src_str,
                     data_t *dst, int setkey_result)
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);

    mbedtls_aes_init(&ctx);

    TEST_ASSERT(mbedtls_aes_setkey_dec(&ctx, key_str->x, key_str->len * 8) == setkey_result);
    if (setkey_result == 0) {
        TEST_ASSERT(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, src_str->x, output) == 0);

        TEST_ASSERT(mbedtls_test_hexcmp(output, dst->x, 16, dst->len) == 0);
    }

exit:
    mbedtls_aes_free(&ctx);
}

void test_aes_decrypt_ecb_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_aes_decrypt_ecb( &data0, &data2, &data4, *( (int *) params[6] ) );
}
#if defined(MBEDTLS_CIPHER_MODE_CBC)
#line 104 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_encrypt_cbc(data_t *key_str, data_t *iv_str,
                     data_t *src_str, data_t *dst,
                     int cbc_result)
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);

    mbedtls_aes_init(&ctx);

    TEST_ASSERT(mbedtls_aes_setkey_enc(&ctx, key_str->x, key_str->len * 8) == 0);
    TEST_ASSERT(mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, src_str->len, iv_str->x,
                                      src_str->x, output) == cbc_result);
    if (cbc_result == 0) {

        TEST_ASSERT(mbedtls_test_hexcmp(output, dst->x,
                                        src_str->len, dst->len) == 0);
    }

exit:
    mbedtls_aes_free(&ctx);
}

void test_aes_encrypt_cbc_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_encrypt_cbc( &data0, &data2, &data4, &data6, *( (int *) params[8] ) );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#if defined(MBEDTLS_CIPHER_MODE_CBC)
#line 130 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_decrypt_cbc(data_t *key_str, data_t *iv_str,
                     data_t *src_str, data_t *dst,
                     int cbc_result)
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);
    mbedtls_aes_init(&ctx);

    TEST_ASSERT(mbedtls_aes_setkey_dec(&ctx, key_str->x, key_str->len * 8) == 0);
    TEST_ASSERT(mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, src_str->len, iv_str->x,
                                      src_str->x, output) == cbc_result);
    if (cbc_result == 0) {

        TEST_ASSERT(mbedtls_test_hexcmp(output, dst->x,
                                        src_str->len, dst->len) == 0);
    }

exit:
    mbedtls_aes_free(&ctx);
}

void test_aes_decrypt_cbc_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_decrypt_cbc( &data0, &data2, &data4, &data6, *( (int *) params[8] ) );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#if defined(MBEDTLS_CIPHER_MODE_XTS)
#line 155 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_encrypt_xts(char *hex_key_string, char *hex_data_unit_string,
                     char *hex_src_string, char *hex_dst_string)
{
    enum { AES_BLOCK_SIZE = 16 };
    unsigned char *data_unit = NULL;
    unsigned char *key = NULL;
    unsigned char *src = NULL;
    unsigned char *dst = NULL;
    unsigned char *output = NULL;
    mbedtls_aes_xts_context ctx;
    size_t key_len, src_len, dst_len, data_unit_len;

    mbedtls_aes_xts_init(&ctx);

    data_unit = mbedtls_test_unhexify_alloc(hex_data_unit_string,
                                            &data_unit_len);
    TEST_ASSERT(data_unit_len == AES_BLOCK_SIZE);

    key = mbedtls_test_unhexify_alloc(hex_key_string, &key_len);
    TEST_ASSERT(key_len % 2 == 0);

    src = mbedtls_test_unhexify_alloc(hex_src_string, &src_len);
    dst = mbedtls_test_unhexify_alloc(hex_dst_string, &dst_len);
    TEST_ASSERT(src_len == dst_len);

    output = mbedtls_test_zero_alloc(dst_len);

    TEST_ASSERT(mbedtls_aes_xts_setkey_enc(&ctx, key, key_len * 8) == 0);
    TEST_ASSERT(mbedtls_aes_crypt_xts(&ctx, MBEDTLS_AES_ENCRYPT, src_len,
                                      data_unit, src, output) == 0);

    TEST_ASSERT(memcmp(output, dst, dst_len) == 0);

exit:
    mbedtls_aes_xts_free(&ctx);
    mbedtls_free(data_unit);
    mbedtls_free(key);
    mbedtls_free(src);
    mbedtls_free(dst);
    mbedtls_free(output);
}

void test_aes_encrypt_xts_wrapper( void ** params )
{

    test_aes_encrypt_xts( (char *) params[0], (char *) params[1], (char *) params[2], (char *) params[3] );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */
#if defined(MBEDTLS_CIPHER_MODE_XTS)
#line 199 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_decrypt_xts(char *hex_key_string, char *hex_data_unit_string,
                     char *hex_dst_string, char *hex_src_string)
{
    enum { AES_BLOCK_SIZE = 16 };
    unsigned char *data_unit = NULL;
    unsigned char *key = NULL;
    unsigned char *src = NULL;
    unsigned char *dst = NULL;
    unsigned char *output = NULL;
    mbedtls_aes_xts_context ctx;
    size_t key_len, src_len, dst_len, data_unit_len;

    mbedtls_aes_xts_init(&ctx);

    data_unit = mbedtls_test_unhexify_alloc(hex_data_unit_string,
                                            &data_unit_len);
    TEST_ASSERT(data_unit_len == AES_BLOCK_SIZE);

    key = mbedtls_test_unhexify_alloc(hex_key_string, &key_len);
    TEST_ASSERT(key_len % 2 == 0);

    src = mbedtls_test_unhexify_alloc(hex_src_string, &src_len);
    dst = mbedtls_test_unhexify_alloc(hex_dst_string, &dst_len);
    TEST_ASSERT(src_len == dst_len);

    output = mbedtls_test_zero_alloc(dst_len);

    TEST_ASSERT(mbedtls_aes_xts_setkey_dec(&ctx, key, key_len * 8) == 0);
    TEST_ASSERT(mbedtls_aes_crypt_xts(&ctx, MBEDTLS_AES_DECRYPT, src_len,
                                      data_unit, src, output) == 0);

    TEST_ASSERT(memcmp(output, dst, dst_len) == 0);

exit:
    mbedtls_aes_xts_free(&ctx);
    mbedtls_free(data_unit);
    mbedtls_free(key);
    mbedtls_free(src);
    mbedtls_free(dst);
    mbedtls_free(output);
}

void test_aes_decrypt_xts_wrapper( void ** params )
{

    test_aes_decrypt_xts( (char *) params[0], (char *) params[1], (char *) params[2], (char *) params[3] );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */
#if defined(MBEDTLS_CIPHER_MODE_XTS)
#line 243 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_crypt_xts_size(int size, int retval)
{
    mbedtls_aes_xts_context ctx;
    const unsigned char src[16] = { 0 };
    unsigned char output[16];
    unsigned char data_unit[16];
    size_t length = size;

    mbedtls_aes_xts_init(&ctx);
    memset(data_unit, 0x00, sizeof(data_unit));


    /* Valid pointers are passed for builds with MBEDTLS_CHECK_PARAMS, as
     * otherwise we wouldn't get to the size check we're interested in. */
    TEST_ASSERT(mbedtls_aes_crypt_xts(&ctx, MBEDTLS_AES_ENCRYPT, length, data_unit, src,
                                      output) == retval);
exit:
    mbedtls_aes_xts_free(&ctx);
}

void test_aes_crypt_xts_size_wrapper( void ** params )
{

    test_aes_crypt_xts_size( *( (int *) params[0] ), *( (int *) params[1] ) );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */
#if defined(MBEDTLS_CIPHER_MODE_XTS)
#line 265 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_crypt_xts_keysize(int size, int retval)
{
    mbedtls_aes_xts_context ctx;
    const unsigned char key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    size_t key_len = size;

    mbedtls_aes_xts_init(&ctx);

    TEST_ASSERT(mbedtls_aes_xts_setkey_enc(&ctx, key, key_len * 8) == retval);
    TEST_ASSERT(mbedtls_aes_xts_setkey_dec(&ctx, key, key_len * 8) == retval);
exit:
    mbedtls_aes_xts_free(&ctx);
}

void test_aes_crypt_xts_keysize_wrapper( void ** params )
{

    test_aes_crypt_xts_keysize( *( (int *) params[0] ), *( (int *) params[1] ) );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */
#if defined(MBEDTLS_CIPHER_MODE_CFB)
#line 282 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_encrypt_cfb128(data_t *key_str, data_t *iv_str,
                        data_t *src_str, data_t *dst)
{
    unsigned char output[100];
    mbedtls_aes_context ctx;
    size_t iv_offset = 0;

    memset(output, 0x00, 100);
    mbedtls_aes_init(&ctx);


    TEST_ASSERT(mbedtls_aes_setkey_enc(&ctx, key_str->x, key_str->len * 8) == 0);
    TEST_ASSERT(mbedtls_aes_crypt_cfb128(&ctx, MBEDTLS_AES_ENCRYPT, 16, &iv_offset, iv_str->x,
                                         src_str->x, output) == 0);

    TEST_ASSERT(mbedtls_test_hexcmp(output, dst->x, 16, dst->len) == 0);

exit:
    mbedtls_aes_free(&ctx);
}

void test_aes_encrypt_cfb128_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_encrypt_cfb128( &data0, &data2, &data4, &data6 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */
#if defined(MBEDTLS_CIPHER_MODE_CFB)
#line 305 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_decrypt_cfb128(data_t *key_str, data_t *iv_str,
                        data_t *src_str, data_t *dst)
{
    unsigned char output[100];
    mbedtls_aes_context ctx;
    size_t iv_offset = 0;

    memset(output, 0x00, 100);
    mbedtls_aes_init(&ctx);


    TEST_ASSERT(mbedtls_aes_setkey_enc(&ctx, key_str->x, key_str->len * 8) == 0);
    TEST_ASSERT(mbedtls_aes_crypt_cfb128(&ctx, MBEDTLS_AES_DECRYPT, 16, &iv_offset, iv_str->x,
                                         src_str->x, output) == 0);

    TEST_ASSERT(mbedtls_test_hexcmp(output, dst->x, 16, dst->len) == 0);

exit:
    mbedtls_aes_free(&ctx);
}

void test_aes_decrypt_cfb128_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_decrypt_cfb128( &data0, &data2, &data4, &data6 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */
#if defined(MBEDTLS_CIPHER_MODE_CFB)
#line 328 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_encrypt_cfb8(data_t *key_str, data_t *iv_str,
                      data_t *src_str, data_t *dst)
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);
    mbedtls_aes_init(&ctx);


    TEST_ASSERT(mbedtls_aes_setkey_enc(&ctx, key_str->x, key_str->len * 8) == 0);
    TEST_ASSERT(mbedtls_aes_crypt_cfb8(&ctx, MBEDTLS_AES_ENCRYPT, src_str->len, iv_str->x,
                                       src_str->x, output) == 0);

    TEST_ASSERT(mbedtls_test_hexcmp(output, dst->x,
                                    src_str->len, dst->len) == 0);

exit:
    mbedtls_aes_free(&ctx);
}

void test_aes_encrypt_cfb8_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_encrypt_cfb8( &data0, &data2, &data4, &data6 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */
#if defined(MBEDTLS_CIPHER_MODE_CFB)
#line 351 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_decrypt_cfb8(data_t *key_str, data_t *iv_str,
                      data_t *src_str, data_t *dst)
{
    unsigned char output[100];
    mbedtls_aes_context ctx;

    memset(output, 0x00, 100);
    mbedtls_aes_init(&ctx);


    TEST_ASSERT(mbedtls_aes_setkey_enc(&ctx, key_str->x, key_str->len * 8) == 0);
    TEST_ASSERT(mbedtls_aes_crypt_cfb8(&ctx, MBEDTLS_AES_DECRYPT, src_str->len, iv_str->x,
                                       src_str->x, output) == 0);

    TEST_ASSERT(mbedtls_test_hexcmp(output, dst->x,
                                    src_str->len, dst->len) == 0);

exit:
    mbedtls_aes_free(&ctx);
}

void test_aes_decrypt_cfb8_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_aes_decrypt_cfb8( &data0, &data2, &data4, &data6 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */
#if defined(MBEDTLS_CIPHER_MODE_OFB)
#line 374 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_encrypt_ofb(int fragment_size, data_t *key_str,
                     data_t *iv_str, data_t *src_str,
                     data_t *expected_output)
{
    unsigned char output[32];
    mbedtls_aes_context ctx;
    size_t iv_offset = 0;
    int in_buffer_len;
    unsigned char *src_str_next;

    memset(output, 0x00, sizeof(output));
    mbedtls_aes_init(&ctx);

    TEST_ASSERT((size_t) fragment_size < sizeof(output));

    TEST_ASSERT(mbedtls_aes_setkey_enc(&ctx, key_str->x,
                                       key_str->len * 8) == 0);
    in_buffer_len = src_str->len;
    src_str_next = src_str->x;

    while (in_buffer_len > 0) {
        TEST_ASSERT(mbedtls_aes_crypt_ofb(&ctx, fragment_size, &iv_offset,
                                          iv_str->x, src_str_next, output) == 0);

        TEST_ASSERT(memcmp(output, expected_output->x, fragment_size) == 0);

        in_buffer_len -= fragment_size;
        expected_output->x += fragment_size;
        src_str_next += fragment_size;

        if (in_buffer_len < fragment_size) {
            fragment_size = in_buffer_len;
        }
    }

exit:
    mbedtls_aes_free(&ctx);
}

void test_aes_encrypt_ofb_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};
    data_t data7 = {(uint8_t *) params[7], *( (uint32_t *) params[8] )};

    test_aes_encrypt_ofb( *( (int *) params[0] ), &data1, &data3, &data5, &data7 );
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */
#if defined(MBEDTLS_CHECK_PARAMS)
#if !defined(MBEDTLS_PARAM_FAILED_ALT)
#line 415 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_check_params()
{
    mbedtls_aes_context aes_ctx;
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    mbedtls_aes_xts_context xts_ctx;
#endif
    const unsigned char key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const unsigned char in[16] = { 0 };
    unsigned char out[16];
    size_t size;
    const int valid_mode = MBEDTLS_AES_ENCRYPT;
    const int invalid_mode = 42;

    TEST_INVALID_PARAM(mbedtls_aes_init(NULL));
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    TEST_INVALID_PARAM(mbedtls_aes_xts_init(NULL));
#endif

    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_setkey_enc(NULL, key, 128));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_setkey_enc(&aes_ctx, NULL, 128));

    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_setkey_dec(NULL, key, 128));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_setkey_dec(&aes_ctx, NULL, 128));

#if defined(MBEDTLS_CIPHER_MODE_XTS)
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_xts_setkey_enc(NULL, key, 128));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_xts_setkey_enc(&xts_ctx, NULL, 128));

    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_xts_setkey_dec(NULL, key, 128));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_xts_setkey_dec(&xts_ctx, NULL, 128));
#endif


    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ecb(NULL,
                                                 valid_mode, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ecb(&aes_ctx,
                                                 invalid_mode, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ecb(&aes_ctx,
                                                 valid_mode, NULL, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ecb(&aes_ctx,
                                                 valid_mode, in, NULL));

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cbc(NULL,
                                                 valid_mode, 16,
                                                 out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cbc(&aes_ctx,
                                                 invalid_mode, 16,
                                                 out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cbc(&aes_ctx,
                                                 valid_mode, 16,
                                                 NULL, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cbc(&aes_ctx,
                                                 valid_mode, 16,
                                                 out, NULL, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cbc(&aes_ctx,
                                                 valid_mode, 16,
                                                 out, in, NULL));
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_XTS)
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_xts(NULL,
                                                 valid_mode, 16,
                                                 in, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_xts(&xts_ctx,
                                                 invalid_mode, 16,
                                                 in, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_xts(&xts_ctx,
                                                 valid_mode, 16,
                                                 NULL, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_xts(&xts_ctx,
                                                 valid_mode, 16,
                                                 in, NULL, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_xts(&xts_ctx,
                                                 valid_mode, 16,
                                                 in, in, NULL));
#endif /* MBEDTLS_CIPHER_MODE_XTS */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb128(NULL,
                                                    valid_mode, 16,
                                                    &size, out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb128(&aes_ctx,
                                                    invalid_mode, 16,
                                                    &size, out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb128(&aes_ctx,
                                                    valid_mode, 16,
                                                    NULL, out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb128(&aes_ctx,
                                                    valid_mode, 16,
                                                    &size, NULL, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb128(&aes_ctx,
                                                    valid_mode, 16,
                                                    &size, out, NULL, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb128(&aes_ctx,
                                                    valid_mode, 16,
                                                    &size, out, in, NULL));


    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb8(NULL,
                                                  valid_mode, 16,
                                                  out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb8(&aes_ctx,
                                                  invalid_mode, 16,
                                                  out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb8(&aes_ctx,
                                                  valid_mode, 16,
                                                  NULL, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb8(&aes_ctx,
                                                  valid_mode, 16,
                                                  out, NULL, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_cfb8(&aes_ctx,
                                                  valid_mode, 16,
                                                  out, in, NULL));
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ofb(NULL, 16,
                                                 &size, out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ofb(&aes_ctx, 16,
                                                 NULL, out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ofb(&aes_ctx, 16,
                                                 &size, NULL, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ofb(&aes_ctx, 16,
                                                 &size, out, NULL, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ofb(&aes_ctx, 16,
                                                 &size, out, in, NULL));
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ctr(NULL, 16, &size, out,
                                                 out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ctr(&aes_ctx, 16, NULL, out,
                                                 out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ctr(&aes_ctx, 16, &size, NULL,
                                                 out, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ctr(&aes_ctx, 16, &size, out,
                                                 NULL, in, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ctr(&aes_ctx, 16, &size, out,
                                                 out, NULL, out));
    TEST_INVALID_PARAM_RET(MBEDTLS_ERR_AES_BAD_INPUT_DATA,
                           mbedtls_aes_crypt_ctr(&aes_ctx, 16, &size, out,
                                                 out, in, NULL));
#endif /* MBEDTLS_CIPHER_MODE_CTR */
exit:
    ;
}

void test_aes_check_params_wrapper( void ** params )
{
    (void)params;

    test_aes_check_params(  );
}
#endif /* !MBEDTLS_PARAM_FAILED_ALT */
#endif /* MBEDTLS_CHECK_PARAMS */
#line 606 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_misc_params()
{
#if defined(MBEDTLS_CIPHER_MODE_CBC) || \
    defined(MBEDTLS_CIPHER_MODE_XTS) || \
    defined(MBEDTLS_CIPHER_MODE_CFB) || \
    defined(MBEDTLS_CIPHER_MODE_OFB)
    const unsigned char in[16] = { 0 };
    unsigned char out[16];
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC) || \
    defined(MBEDTLS_CIPHER_MODE_CFB) || \
    defined(MBEDTLS_CIPHER_MODE_OFB)
    mbedtls_aes_context aes_ctx;
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    mbedtls_aes_xts_context xts_ctx;
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB) || \
    defined(MBEDTLS_CIPHER_MODE_OFB)
    size_t size;
#endif

    /* These calls accept NULL */
    TEST_VALID_PARAM(mbedtls_aes_free(NULL));
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    TEST_VALID_PARAM(mbedtls_aes_xts_free(NULL));
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    TEST_ASSERT(mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT,
                                      15,
                                      out, in, out)
                == MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH);
    TEST_ASSERT(mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT,
                                      17,
                                      out, in, out)
                == MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH);
#endif

#if defined(MBEDTLS_CIPHER_MODE_XTS)
    TEST_ASSERT(mbedtls_aes_crypt_xts(&xts_ctx, MBEDTLS_AES_ENCRYPT,
                                      15,
                                      in, in, out)
                == MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH);
    TEST_ASSERT(mbedtls_aes_crypt_xts(&xts_ctx, MBEDTLS_AES_ENCRYPT,
                                      (1 << 24) + 1,
                                      in, in, out)
                == MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH);
#endif

#if defined(MBEDTLS_CIPHER_MODE_CFB)
    size = 16;
    TEST_ASSERT(mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_ENCRYPT, 16,
                                         &size, out, in, out)
                == MBEDTLS_ERR_AES_BAD_INPUT_DATA);
#endif

#if defined(MBEDTLS_CIPHER_MODE_OFB)
    size = 16;
    TEST_ASSERT(mbedtls_aes_crypt_ofb(&aes_ctx, 16, &size, out, in, out)
                == MBEDTLS_ERR_AES_BAD_INPUT_DATA);
#endif
exit:
    ;
}

void test_aes_misc_params_wrapper( void ** params )
{
    (void)params;

    test_aes_misc_params(  );
}
#line 672 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_ecb_context_alignment(data_t *key)
{
    /* We test alignment multiple times, with different alignments
     * of the context and of the plaintext/ciphertext. */

    struct align0 {
        mbedtls_aes_context ctx;
    };
    struct align0 *enc0 = NULL;
    struct align0 *dec0 = NULL;

    struct align1 {
        char bump;
        mbedtls_aes_context ctx;
    };
    struct align1 *enc1 = NULL;
    struct align1 *dec1 = NULL;

    /* All peak alignment */
    ASSERT_ALLOC(enc0, 1);
    ASSERT_ALLOC(dec0, 1);
    if (!test_ctx_alignment(key, &enc0->ctx, &dec0->ctx)) {
        goto exit;
    }
    mbedtls_free(enc0);
    enc0 = NULL;
    mbedtls_free(dec0);
    dec0 = NULL;

    /* Enc aligned, dec not */
    ASSERT_ALLOC(enc0, 1);
    ASSERT_ALLOC(dec1, 1);
    if (!test_ctx_alignment(key, &enc0->ctx, &dec1->ctx)) {
        goto exit;
    }
    mbedtls_free(enc0);
    enc0 = NULL;
    mbedtls_free(dec1);
    dec1 = NULL;

    /* Dec aligned, enc not */
    ASSERT_ALLOC(enc1, 1);
    ASSERT_ALLOC(dec0, 1);
    if (!test_ctx_alignment(key, &enc1->ctx, &dec0->ctx)) {
        goto exit;
    }
    mbedtls_free(enc1);
    enc1 = NULL;
    mbedtls_free(dec0);
    dec0 = NULL;

    /* Both shifted */
    ASSERT_ALLOC(enc1, 1);
    ASSERT_ALLOC(dec1, 1);
    if (!test_ctx_alignment(key, &enc1->ctx, &dec1->ctx)) {
        goto exit;
    }
    mbedtls_free(enc1);
    enc1 = NULL;
    mbedtls_free(dec1);
    dec1 = NULL;

exit:
    mbedtls_free(enc0);
    mbedtls_free(dec0);
    mbedtls_free(enc1);
    mbedtls_free(dec1);
}

void test_aes_ecb_context_alignment_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};

    test_aes_ecb_context_alignment( &data0 );
}
#if defined(MBEDTLS_SELF_TEST)
#line 743 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_aes.function"
void test_aes_selftest()
{
    TEST_ASSERT(mbedtls_aes_self_test(1) == 0);
exit:
    ;
}

void test_aes_selftest_wrapper( void ** params )
{
    (void)params;

    test_aes_selftest(  );
}
#endif /* MBEDTLS_SELF_TEST */
#endif /* MBEDTLS_AES_C */


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
    
#if defined(MBEDTLS_AES_C)

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
    
#if defined(MBEDTLS_AES_C)

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

#if defined(MBEDTLS_AES_C)
    test_aes_encrypt_ecb_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_AES_C)
    test_aes_decrypt_ecb_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    test_aes_encrypt_cbc_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    test_aes_decrypt_cbc_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_XTS)
    test_aes_encrypt_xts_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_XTS)
    test_aes_decrypt_xts_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_XTS)
    test_aes_crypt_xts_size_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_XTS)
    test_aes_crypt_xts_keysize_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CFB)
    test_aes_encrypt_cfb128_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CFB)
    test_aes_decrypt_cfb128_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CFB)
    test_aes_encrypt_cfb8_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CFB)
    test_aes_decrypt_cfb8_wrapper,
#else
    NULL,
#endif
/* Function Id: 12 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_OFB)
    test_aes_encrypt_ofb_wrapper,
#else
    NULL,
#endif
/* Function Id: 13 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CHECK_PARAMS) && !defined(MBEDTLS_PARAM_FAILED_ALT)
    test_aes_check_params_wrapper,
#else
    NULL,
#endif
/* Function Id: 14 */

#if defined(MBEDTLS_AES_C)
    test_aes_misc_params_wrapper,
#else
    NULL,
#endif
/* Function Id: 15 */

#if defined(MBEDTLS_AES_C)
    test_aes_ecb_context_alignment_wrapper,
#else
    NULL,
#endif
/* Function Id: 16 */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_SELF_TEST)
    test_aes_selftest_wrapper,
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
    const char *default_filename = "./test_suite_aes.cbc.datax";
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
