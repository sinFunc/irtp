#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_psa_crypto.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/main_test.function
 *      Platform code file  : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/host_test.function
 *      Helper file         : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/helpers.function
 *      Test suite file     : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function
 *      Test suite data     : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.data
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

#if defined(MBEDTLS_PSA_CRYPTO_C)
#line 2 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
#include <stdint.h>

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "common.h"

/* For MBEDTLS_CTR_DRBG_MAX_REQUEST, knowing that psa_generate_random()
 * uses mbedtls_ctr_drbg internally. */
#include "mbedtls/ctr_drbg.h"

#include "psa/crypto.h"
#include "psa_crypto_slot_management.h"

#include "test/asn1_helpers.h"
#include "test/psa_crypto_helpers.h"
#include "test/psa_exercise_key.h"

/* If this comes up, it's a bug in the test code or in the test data. */
#define UNUSED 0xdeadbeef

/* Assert that an operation is (not) active.
 * This serves as a proxy for checking if the operation is aborted. */
#define ASSERT_OPERATION_IS_ACTIVE(operation) TEST_ASSERT(operation.id != 0)
#define ASSERT_OPERATION_IS_INACTIVE(operation) TEST_ASSERT(operation.id == 0)

/** An invalid export length that will never be set by psa_export_key(). */
static const size_t INVALID_EXPORT_LENGTH = ~0U;

/** Test if a buffer contains a constant byte value.
 *
 * `mem_is_char(buffer, c, size)` is true after `memset(buffer, c, size)`.
 *
 * \param buffer    Pointer to the beginning of the buffer.
 * \param c         Expected value of every byte.
 * \param size      Size of the buffer in bytes.
 *
 * \return          1 if the buffer is all-bits-zero.
 * \return          0 if there is at least one nonzero byte.
 */
static int mem_is_char(void *buffer, unsigned char c, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++) {
        if (((unsigned char *) buffer)[i] != c) {
            return 0;
        }
    }
    return 1;
}
#if defined(MBEDTLS_ASN1_WRITE_C)
/* Write the ASN.1 INTEGER with the value 2^(bits-1)+x backwards from *p. */
static int asn1_write_10x(unsigned char **p,
                          unsigned char *start,
                          size_t bits,
                          unsigned char x)
{
    int ret;
    int len = bits / 8 + 1;
    if (bits == 0) {
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    if (bits <= 8 && x >= 1 << (bits - 1)) {
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }
    if (*p < start || *p - start < (ptrdiff_t) len) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    *p -= len;
    (*p)[len-1] = x;
    if (bits % 8 == 0) {
        (*p)[1] |= 1;
    } else {
        (*p)[0] |= 1 << (bits % 8);
    }
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_INTEGER));
    return len;
}

static int construct_fake_rsa_key(unsigned char *buffer,
                                  size_t buffer_size,
                                  unsigned char **p,
                                  size_t bits,
                                  int keypair)
{
    size_t half_bits = (bits + 1) / 2;
    int ret;
    int len = 0;
    /* Construct something that looks like a DER encoding of
     * as defined by PKCS#1 v2.2 (RFC 8017) section A.1.2:
     *   RSAPrivateKey ::= SEQUENCE {
     *       version           Version,
     *       modulus           INTEGER,  -- n
     *       publicExponent    INTEGER,  -- e
     *       privateExponent   INTEGER,  -- d
     *       prime1            INTEGER,  -- p
     *       prime2            INTEGER,  -- q
     *       exponent1         INTEGER,  -- d mod (p-1)
     *       exponent2         INTEGER,  -- d mod (q-1)
     *       coefficient       INTEGER,  -- (inverse of q) mod p
     *       otherPrimeInfos   OtherPrimeInfos OPTIONAL
     *   }
     * Or, for a public key, the same structure with only
     * version, modulus and publicExponent.
     */
    *p = buffer + buffer_size;
    if (keypair) {
        MBEDTLS_ASN1_CHK_ADD(len,  /* pq */
                             asn1_write_10x(p, buffer, half_bits, 1));
        MBEDTLS_ASN1_CHK_ADD(len,  /* dq */
                             asn1_write_10x(p, buffer, half_bits, 1));
        MBEDTLS_ASN1_CHK_ADD(len,  /* dp */
                             asn1_write_10x(p, buffer, half_bits, 1));
        MBEDTLS_ASN1_CHK_ADD(len,  /* q */
                             asn1_write_10x(p, buffer, half_bits, 1));
        MBEDTLS_ASN1_CHK_ADD(len,  /* p != q to pass mbedtls sanity checks */
                             asn1_write_10x(p, buffer, half_bits, 3));
        MBEDTLS_ASN1_CHK_ADD(len,  /* d */
                             asn1_write_10x(p, buffer, bits, 1));
    }
    MBEDTLS_ASN1_CHK_ADD(len,  /* e = 65537 */
                         asn1_write_10x(p, buffer, 17, 1));
    MBEDTLS_ASN1_CHK_ADD(len,  /* n */
                         asn1_write_10x(p, buffer, bits, 1));
    if (keypair) {
        MBEDTLS_ASN1_CHK_ADD(len,  /* version = 0 */
                             mbedtls_asn1_write_int(p, buffer, 0));
    }
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, buffer, len));
    {
        const unsigned char tag =
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, buffer, tag));
    }
    return len;
}
#endif /* MBEDTLS_ASN1_WRITE_C */

int exercise_mac_setup(psa_key_type_t key_type,
                       const unsigned char *key_bytes,
                       size_t key_length,
                       psa_algorithm_t alg,
                       psa_mac_operation_t *operation,
                       psa_status_t *status)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);
    PSA_ASSERT(psa_import_key(&attributes, key_bytes, key_length, &key));

    *status = psa_mac_sign_setup(operation, key, alg);
    /* Whether setup succeeded or failed, abort must succeed. */
    PSA_ASSERT(psa_mac_abort(operation));
    /* If setup failed, reproduce the failure, so that the caller can
     * test the resulting state of the operation object. */
    if (*status != PSA_SUCCESS) {
        TEST_EQUAL(psa_mac_sign_setup(operation, key, alg), *status);
    }

    psa_destroy_key(key);
    return 1;

exit:
    psa_destroy_key(key);
    return 0;
}

int exercise_cipher_setup(psa_key_type_t key_type,
                          const unsigned char *key_bytes,
                          size_t key_length,
                          psa_algorithm_t alg,
                          psa_cipher_operation_t *operation,
                          psa_status_t *status)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);
    PSA_ASSERT(psa_import_key(&attributes, key_bytes, key_length, &key));

    *status = psa_cipher_encrypt_setup(operation, key, alg);
    /* Whether setup succeeded or failed, abort must succeed. */
    PSA_ASSERT(psa_cipher_abort(operation));
    /* If setup failed, reproduce the failure, so that the caller can
     * test the resulting state of the operation object. */
    if (*status != PSA_SUCCESS) {
        TEST_EQUAL(psa_cipher_encrypt_setup(operation, key, alg),
                   *status);
    }

    psa_destroy_key(key);
    return 1;

exit:
    psa_destroy_key(key);
    return 0;
}

static int test_operations_on_invalid_key(mbedtls_svc_key_id_t key)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(1, 0x6964);
    uint8_t buffer[1];
    size_t length;
    int ok = 0;

    psa_set_key_id(&attributes, key_id);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    TEST_EQUAL(psa_get_key_attributes(key, &attributes),
               PSA_ERROR_INVALID_HANDLE);
    TEST_EQUAL(
        MBEDTLS_SVC_KEY_ID_GET_KEY_ID(psa_get_key_id(&attributes)), 0);
    TEST_EQUAL(
        MBEDTLS_SVC_KEY_ID_GET_OWNER_ID(psa_get_key_id(&attributes)), 0);
    TEST_EQUAL(psa_get_key_lifetime(&attributes), 0);
    TEST_EQUAL(psa_get_key_usage_flags(&attributes), 0);
    TEST_EQUAL(psa_get_key_algorithm(&attributes), 0);
    TEST_EQUAL(psa_get_key_type(&attributes), 0);
    TEST_EQUAL(psa_get_key_bits(&attributes), 0);

    TEST_EQUAL(psa_export_key(key, buffer, sizeof(buffer), &length),
               PSA_ERROR_INVALID_HANDLE);
    TEST_EQUAL(psa_export_public_key(key,
                                     buffer, sizeof(buffer), &length),
               PSA_ERROR_INVALID_HANDLE);

    ok = 1;

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    return ok;
}

/* Assert that a key isn't reported as having a slot number. */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
#define ASSERT_NO_SLOT_NUMBER(attributes)                             \
    do                                                                  \
    {                                                                   \
        psa_key_slot_number_t ASSERT_NO_SLOT_NUMBER_slot_number;        \
        TEST_EQUAL(psa_get_key_slot_number(                            \
                       attributes,                                     \
                       &ASSERT_NO_SLOT_NUMBER_slot_number),           \
                   PSA_ERROR_INVALID_ARGUMENT);                       \
    }                                                                   \
    while (0)
#else /* MBEDTLS_PSA_CRYPTO_SE_C */
#define ASSERT_NO_SLOT_NUMBER(attributes)     \
    ((void) 0)
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

/* An overapproximation of the amount of storage needed for a key of the
 * given type and with the given content. The API doesn't make it easy
 * to find a good value for the size. The current implementation doesn't
 * care about the value anyway. */
#define KEY_BITS_FROM_DATA(type, data)        \
    (data)->len

typedef enum {
    IMPORT_KEY = 0,
    GENERATE_KEY = 1,
    DERIVE_KEY = 2
} generate_method;

#line 287 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_static_checks()
{
    size_t max_truncated_mac_size =
        PSA_ALG_MAC_TRUNCATION_MASK >> PSA_MAC_TRUNCATION_OFFSET;

    /* Check that the length for a truncated MAC always fits in the algorithm
     * encoding. The shifted mask is the maximum truncated value. The
     * untruncated algorithm may be one byte larger. */
    TEST_LE_U(PSA_MAC_MAX_SIZE, 1 + max_truncated_mac_size);

#if defined(MBEDTLS_TEST_DEPRECATED)
    /* Check deprecated constants. */
    TEST_EQUAL(PSA_ERROR_UNKNOWN_ERROR, PSA_ERROR_GENERIC_ERROR);
    TEST_EQUAL(PSA_ERROR_OCCUPIED_SLOT, PSA_ERROR_ALREADY_EXISTS);
    TEST_EQUAL(PSA_ERROR_EMPTY_SLOT, PSA_ERROR_DOES_NOT_EXIST);
    TEST_EQUAL(PSA_ERROR_INSUFFICIENT_CAPACITY, PSA_ERROR_INSUFFICIENT_DATA);
    TEST_EQUAL(PSA_ERROR_TAMPERING_DETECTED, PSA_ERROR_CORRUPTION_DETECTED);
    TEST_EQUAL(PSA_KEY_USAGE_SIGN, PSA_KEY_USAGE_SIGN_HASH);
    TEST_EQUAL(PSA_KEY_USAGE_VERIFY, PSA_KEY_USAGE_VERIFY_HASH);
    TEST_EQUAL(PSA_ASYMMETRIC_SIGNATURE_MAX_SIZE, PSA_SIGNATURE_MAX_SIZE);

    TEST_EQUAL(PSA_ECC_CURVE_SECP160K1, PSA_ECC_FAMILY_SECP_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP192K1, PSA_ECC_FAMILY_SECP_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP224K1, PSA_ECC_FAMILY_SECP_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP256K1, PSA_ECC_FAMILY_SECP_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP160R1, PSA_ECC_FAMILY_SECP_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP192R1, PSA_ECC_FAMILY_SECP_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP224R1, PSA_ECC_FAMILY_SECP_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP256R1, PSA_ECC_FAMILY_SECP_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP384R1, PSA_ECC_FAMILY_SECP_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP521R1, PSA_ECC_FAMILY_SECP_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP160R2, PSA_ECC_FAMILY_SECP_R2);
    TEST_EQUAL(PSA_ECC_CURVE_SECT163K1, PSA_ECC_FAMILY_SECT_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT233K1, PSA_ECC_FAMILY_SECT_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT239K1, PSA_ECC_FAMILY_SECT_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT283K1, PSA_ECC_FAMILY_SECT_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT409K1, PSA_ECC_FAMILY_SECT_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT571K1, PSA_ECC_FAMILY_SECT_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT163R1, PSA_ECC_FAMILY_SECT_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT193R1, PSA_ECC_FAMILY_SECT_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT233R1, PSA_ECC_FAMILY_SECT_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT283R1, PSA_ECC_FAMILY_SECT_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT409R1, PSA_ECC_FAMILY_SECT_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT571R1, PSA_ECC_FAMILY_SECT_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT163R2, PSA_ECC_FAMILY_SECT_R2);
    TEST_EQUAL(PSA_ECC_CURVE_SECT193R2, PSA_ECC_FAMILY_SECT_R2);
    TEST_EQUAL(PSA_ECC_CURVE_BRAINPOOL_P256R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1);
    TEST_EQUAL(PSA_ECC_CURVE_BRAINPOOL_P384R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1);
    TEST_EQUAL(PSA_ECC_CURVE_BRAINPOOL_P512R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1);
    TEST_EQUAL(PSA_ECC_CURVE_CURVE25519, PSA_ECC_FAMILY_MONTGOMERY);
    TEST_EQUAL(PSA_ECC_CURVE_CURVE448, PSA_ECC_FAMILY_MONTGOMERY);

    TEST_EQUAL(PSA_ECC_CURVE_SECP_K1, PSA_ECC_FAMILY_SECP_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP_R1, PSA_ECC_FAMILY_SECP_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECP_R2, PSA_ECC_FAMILY_SECP_R2);
    TEST_EQUAL(PSA_ECC_CURVE_SECT_K1, PSA_ECC_FAMILY_SECT_K1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT_R1, PSA_ECC_FAMILY_SECT_R1);
    TEST_EQUAL(PSA_ECC_CURVE_SECT_R2, PSA_ECC_FAMILY_SECT_R2);
    TEST_EQUAL(PSA_ECC_CURVE_BRAINPOOL_P_R1, PSA_ECC_FAMILY_BRAINPOOL_P_R1);
    TEST_EQUAL(PSA_ECC_CURVE_MONTGOMERY, PSA_ECC_FAMILY_MONTGOMERY);

    TEST_EQUAL(PSA_DH_GROUP_FFDHE2048, PSA_DH_FAMILY_RFC7919);
    TEST_EQUAL(PSA_DH_GROUP_FFDHE3072, PSA_DH_FAMILY_RFC7919);
    TEST_EQUAL(PSA_DH_GROUP_FFDHE4096, PSA_DH_FAMILY_RFC7919);
    TEST_EQUAL(PSA_DH_GROUP_FFDHE6144, PSA_DH_FAMILY_RFC7919);
    TEST_EQUAL(PSA_DH_GROUP_FFDHE8192, PSA_DH_FAMILY_RFC7919);

    TEST_EQUAL(PSA_DH_GROUP_RFC7919, PSA_DH_FAMILY_RFC7919);
    TEST_EQUAL(PSA_DH_GROUP_CUSTOM, PSA_DH_FAMILY_CUSTOM);
#endif
exit:
    ;
}

void test_static_checks_wrapper( void ** params )
{
    (void)params;

    test_static_checks(  );
}
#line 361 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_import_with_policy(int type_arg,
                        int usage_arg, int alg_arg,
                        int expected_status_arg)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t got_attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t type = type_arg;
    psa_key_usage_t usage = usage_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_status = expected_status_arg;
    const uint8_t key_material[16] = { 0 };
    psa_status_t status;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_type(&attributes, type);
    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, alg);

    status = psa_import_key(&attributes,
                            key_material, sizeof(key_material),
                            &key);
    TEST_EQUAL(status, expected_status);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    PSA_ASSERT(psa_get_key_attributes(key, &got_attributes));
    TEST_EQUAL(psa_get_key_type(&got_attributes), type);
    TEST_EQUAL(psa_get_key_usage_flags(&got_attributes),
               mbedtls_test_update_key_usage_flags(usage));
    TEST_EQUAL(psa_get_key_algorithm(&got_attributes), alg);
    ASSERT_NO_SLOT_NUMBER(&got_attributes);

    PSA_ASSERT(psa_destroy_key(key));
    test_operations_on_invalid_key(key);

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&got_attributes);

    psa_destroy_key(key);
    PSA_DONE();
}

void test_import_with_policy_wrapper( void ** params )
{

    test_import_with_policy( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ) );
}
#line 412 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_import_with_data(data_t *data, int type_arg,
                      int attr_bits_arg,
                      int expected_status_arg)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t got_attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t type = type_arg;
    size_t attr_bits = attr_bits_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_status_t status;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_type(&attributes, type);
    psa_set_key_bits(&attributes, attr_bits);

    status = psa_import_key(&attributes, data->x, data->len, &key);
    TEST_EQUAL(status, expected_status);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    PSA_ASSERT(psa_get_key_attributes(key, &got_attributes));
    TEST_EQUAL(psa_get_key_type(&got_attributes), type);
    if (attr_bits != 0) {
        TEST_EQUAL(attr_bits, psa_get_key_bits(&got_attributes));
    }
    ASSERT_NO_SLOT_NUMBER(&got_attributes);

    PSA_ASSERT(psa_destroy_key(key));
    test_operations_on_invalid_key(key);

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&got_attributes);

    psa_destroy_key(key);
    PSA_DONE();
}

void test_import_with_data_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};

    test_import_with_data( &data0, *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ) );
}
#line 458 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"

void test_import_large_key(int type_arg, int byte_size_arg,
                      int expected_status_arg)
{
    psa_key_type_t type = type_arg;
    size_t byte_size = byte_size_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t expected_status = expected_status_arg;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    uint8_t *buffer = NULL;
    size_t buffer_size = byte_size + 1;
    size_t n;

    /* Skip the test case if the target running the test cannot
     * accommodate large keys due to heap size constraints */
    ASSERT_ALLOC_WEAK(buffer, buffer_size);
    memset(buffer, 'K', byte_size);

    PSA_ASSERT(psa_crypto_init());

    /* Try importing the key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_type(&attributes, type);
    status = psa_import_key(&attributes, buffer, byte_size, &key);
    TEST_ASSUME(status != PSA_ERROR_INSUFFICIENT_MEMORY);
    TEST_EQUAL(status, expected_status);

    if (status == PSA_SUCCESS) {
        PSA_ASSERT(psa_get_key_attributes(key, &attributes));
        TEST_EQUAL(psa_get_key_type(&attributes), type);
        TEST_EQUAL(psa_get_key_bits(&attributes),
                   PSA_BYTES_TO_BITS(byte_size));
        ASSERT_NO_SLOT_NUMBER(&attributes);
        memset(buffer, 0, byte_size + 1);
        PSA_ASSERT(psa_export_key(key, buffer, byte_size, &n));
        for (n = 0; n < byte_size; n++) {
            TEST_EQUAL(buffer[n], 'K');
        }
        for (n = byte_size; n < buffer_size; n++) {
            TEST_EQUAL(buffer[n], 0);
        }
    }

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    psa_destroy_key(key);
    PSA_DONE();
    mbedtls_free(buffer);
}

void test_import_large_key_wrapper( void ** params )
{

    test_import_large_key( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#if defined(MBEDTLS_ASN1_WRITE_C)
#line 516 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"



void test_import_rsa_made_up(int bits_arg, int keypair, int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    size_t bits = bits_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_status_t status;
    psa_key_type_t type =
        keypair ? PSA_KEY_TYPE_RSA_KEY_PAIR : PSA_KEY_TYPE_RSA_PUBLIC_KEY;
    size_t buffer_size = /* Slight overapproximations */
                         keypair ? bits * 9 / 16 + 80 : bits / 8 + 20;
    unsigned char *buffer = NULL;
    unsigned char *p;
    int ret;
    size_t length;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());
    ASSERT_ALLOC(buffer, buffer_size);

    TEST_ASSERT((ret = construct_fake_rsa_key(buffer, buffer_size, &p,
                                              bits, keypair)) >= 0);
    length = ret;

    /* Try importing the key */
    psa_set_key_type(&attributes, type);
    status = psa_import_key(&attributes, p, length, &key);
    TEST_EQUAL(status, expected_status);

    if (status == PSA_SUCCESS) {
        PSA_ASSERT(psa_destroy_key(key));
    }

exit:
    mbedtls_free(buffer);
    PSA_DONE();
}

void test_import_rsa_made_up_wrapper( void ** params )
{

    test_import_rsa_made_up( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#endif /* MBEDTLS_ASN1_WRITE_C */
#line 558 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_import_export(data_t *data,
                   int type_arg,
                   int usage_arg, int alg_arg,
                   int expected_bits,
                   int export_size_delta,
                   int expected_export_status_arg,

                   int canonical_input)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t type = type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_export_status = expected_export_status_arg;
    psa_status_t status;
    unsigned char *exported = NULL;
    unsigned char *reexported = NULL;
    size_t export_size;
    size_t exported_length = INVALID_EXPORT_LENGTH;
    size_t reexported_length;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t got_attributes = PSA_KEY_ATTRIBUTES_INIT;

    export_size = (ptrdiff_t) data->len + export_size_delta;
    ASSERT_ALLOC(exported, export_size);
    if (!canonical_input) {
        ASSERT_ALLOC(reexported, export_size);
    }
    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, usage_arg);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, type);

    /* Import the key */
    PSA_ASSERT(psa_import_key(&attributes, data->x, data->len, &key));

    /* Test the key information */
    PSA_ASSERT(psa_get_key_attributes(key, &got_attributes));
    TEST_EQUAL(psa_get_key_type(&got_attributes), type);
    TEST_EQUAL(psa_get_key_bits(&got_attributes), (size_t) expected_bits);
    ASSERT_NO_SLOT_NUMBER(&got_attributes);

    /* Export the key */
    status = psa_export_key(key, exported, export_size, &exported_length);
    TEST_EQUAL(status, expected_export_status);

    /* The exported length must be set by psa_export_key() to a value between 0
     * and export_size. On errors, the exported length must be 0. */
    TEST_ASSERT(exported_length != INVALID_EXPORT_LENGTH);
    TEST_ASSERT(status == PSA_SUCCESS || exported_length == 0);
    TEST_LE_U(exported_length, export_size);

    TEST_ASSERT(mem_is_char(exported + exported_length, 0,
                            export_size - exported_length));
    if (status != PSA_SUCCESS) {
        TEST_EQUAL(exported_length, 0);
        goto destroy;
    }

    /* Run sanity checks on the exported key. For non-canonical inputs,
     * this validates the canonical representations. For canonical inputs,
     * this doesn't directly validate the implementation, but it still helps
     * by cross-validating the test data with the sanity check code. */
    if (!mbedtls_test_psa_exercise_key(key, usage_arg, 0)) {
        goto exit;
    }

    if (canonical_input) {
        ASSERT_COMPARE(data->x, data->len, exported, exported_length);
    } else {
        mbedtls_svc_key_id_t key2 = MBEDTLS_SVC_KEY_ID_INIT;
        PSA_ASSERT(psa_import_key(&attributes, exported, exported_length,
                                  &key2));
        PSA_ASSERT(psa_export_key(key2,
                                  reexported,
                                  export_size,
                                  &reexported_length));
        ASSERT_COMPARE(exported, exported_length,
                       reexported, reexported_length);
        PSA_ASSERT(psa_destroy_key(key2));
    }
    TEST_ASSERT(exported_length <=
                PSA_EXPORT_KEY_OUTPUT_SIZE(type,
                                           psa_get_key_bits(&got_attributes)));
    TEST_LE_U(exported_length, PSA_EXPORT_KEY_PAIR_MAX_SIZE);

destroy:
    /* Destroy the key */
    PSA_ASSERT(psa_destroy_key(key));
    test_operations_on_invalid_key(key);

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&got_attributes);

    mbedtls_free(exported);
    mbedtls_free(reexported);
    PSA_DONE();
}

void test_import_export_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};

    test_import_export( &data0, *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ), *( (int *) params[6] ), *( (int *) params[7] ), *( (int *) params[8] ) );
}
#line 663 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_import_export_public_key(data_t *data,
                              int type_arg,
                              int alg_arg,
                              int export_size_delta,
                              int expected_export_status_arg,
                              data_t *expected_public_key)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t type = type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_export_status = expected_export_status_arg;
    psa_status_t status;
    unsigned char *exported = NULL;
    size_t export_size = expected_public_key->len + export_size_delta;
    size_t exported_length = INVALID_EXPORT_LENGTH;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, type);

    /* Import the key */
    PSA_ASSERT(psa_import_key(&attributes, data->x, data->len, &key));

    /* Export the public key */
    ASSERT_ALLOC(exported, export_size);
    status = psa_export_public_key(key,
                                   exported, export_size,
                                   &exported_length);
    TEST_EQUAL(status, expected_export_status);
    if (status == PSA_SUCCESS) {
        psa_key_type_t public_type = PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type);
        size_t bits;
        PSA_ASSERT(psa_get_key_attributes(key, &attributes));
        bits = psa_get_key_bits(&attributes);
        TEST_LE_U(expected_public_key->len,
                  PSA_EXPORT_KEY_OUTPUT_SIZE(public_type, bits));
        TEST_LE_U(expected_public_key->len,
                  PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(public_type, bits));
        TEST_LE_U(expected_public_key->len,
                  PSA_EXPORT_PUBLIC_KEY_MAX_SIZE);
        ASSERT_COMPARE(expected_public_key->x, expected_public_key->len,
                       exported, exported_length);
    }

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    mbedtls_free(exported);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_import_export_public_key_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_import_export_public_key( &data0, *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ), &data6 );
}
#line 724 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_import_and_exercise_key(data_t *data,
                             int type_arg,
                             int bits_arg,
                             int alg_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t type = type_arg;
    size_t bits = bits_arg;
    psa_algorithm_t alg = alg_arg;
    psa_key_usage_t usage = mbedtls_test_psa_usage_to_exercise(type, alg);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t got_attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, type);

    /* Import the key */
    PSA_ASSERT(psa_import_key(&attributes, data->x, data->len, &key));

    /* Test the key information */
    PSA_ASSERT(psa_get_key_attributes(key, &got_attributes));
    TEST_EQUAL(psa_get_key_type(&got_attributes), type);
    TEST_EQUAL(psa_get_key_bits(&got_attributes), bits);

    /* Do something with the key according to its type and permitted usage. */
    if (!mbedtls_test_psa_exercise_key(key, usage, alg)) {
        goto exit;
    }

    PSA_ASSERT(psa_destroy_key(key));
    test_operations_on_invalid_key(key);

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&got_attributes);

    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_import_and_exercise_key_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};

    test_import_and_exercise_key( &data0, *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ) );
}
#line 773 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_effective_key_attributes(int type_arg, int expected_type_arg,
                              int bits_arg, int expected_bits_arg,
                              int usage_arg, int expected_usage_arg,
                              int alg_arg, int expected_alg_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = type_arg;
    psa_key_type_t expected_key_type = expected_type_arg;
    size_t bits = bits_arg;
    size_t expected_bits = expected_bits_arg;
    psa_algorithm_t alg = alg_arg;
    psa_algorithm_t expected_alg = expected_alg_arg;
    psa_key_usage_t usage = usage_arg;
    psa_key_usage_t expected_usage = expected_usage_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_bits(&attributes, bits);

    PSA_ASSERT(psa_generate_key(&attributes, &key));
    psa_reset_key_attributes(&attributes);

    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    TEST_EQUAL(psa_get_key_type(&attributes), expected_key_type);
    TEST_EQUAL(psa_get_key_bits(&attributes), expected_bits);
    TEST_EQUAL(psa_get_key_usage_flags(&attributes), expected_usage);
    TEST_EQUAL(psa_get_key_algorithm(&attributes), expected_alg);

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    psa_destroy_key(key);
    PSA_DONE();
}

void test_effective_key_attributes_wrapper( void ** params )
{

    test_effective_key_attributes( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ), *( (int *) params[6] ), *( (int *) params[7] ) );
}
#line 818 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_check_key_policy(int type_arg, int bits_arg,
                      int usage_arg, int alg_arg)
{
    test_effective_key_attributes(type_arg, type_arg, bits_arg, bits_arg,
                                  usage_arg,
                                  mbedtls_test_update_key_usage_flags(usage_arg),
                                  alg_arg, alg_arg);
    goto exit;
exit:
    ;
}

void test_check_key_policy_wrapper( void ** params )
{

    test_check_key_policy( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ) );
}
#line 830 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_key_attributes_init()
{
    /* Test each valid way of initializing the object, except for `= {0}`, as
     * Clang 5 complains when `-Wmissing-field-initializers` is used, even
     * though it's OK by the C standard. We could test for this, but we'd need
     * to suppress the Clang warning for the test. */
    psa_key_attributes_t func = psa_key_attributes_init();
    psa_key_attributes_t init = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t zero;

    memset(&zero, 0, sizeof(zero));

    TEST_EQUAL(psa_get_key_lifetime(&func), PSA_KEY_LIFETIME_VOLATILE);
    TEST_EQUAL(psa_get_key_lifetime(&init), PSA_KEY_LIFETIME_VOLATILE);
    TEST_EQUAL(psa_get_key_lifetime(&zero), PSA_KEY_LIFETIME_VOLATILE);

    TEST_EQUAL(psa_get_key_type(&func), 0);
    TEST_EQUAL(psa_get_key_type(&init), 0);
    TEST_EQUAL(psa_get_key_type(&zero), 0);

    TEST_EQUAL(psa_get_key_bits(&func), 0);
    TEST_EQUAL(psa_get_key_bits(&init), 0);
    TEST_EQUAL(psa_get_key_bits(&zero), 0);

    TEST_EQUAL(psa_get_key_usage_flags(&func), 0);
    TEST_EQUAL(psa_get_key_usage_flags(&init), 0);
    TEST_EQUAL(psa_get_key_usage_flags(&zero), 0);

    TEST_EQUAL(psa_get_key_algorithm(&func), 0);
    TEST_EQUAL(psa_get_key_algorithm(&init), 0);
    TEST_EQUAL(psa_get_key_algorithm(&zero), 0);
exit:
    ;
}

void test_key_attributes_init_wrapper( void ** params )
{
    (void)params;

    test_key_attributes_init(  );
}
#line 865 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_mac_key_policy(int policy_usage_arg,
                    int policy_alg_arg,
                    int key_type_arg,
                    data_t *key_data,
                    int exercise_alg_arg,
                    int expected_status_sign_arg,
                    int expected_status_verify_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t policy_alg = policy_alg_arg;
    psa_algorithm_t exercise_alg = exercise_alg_arg;
    psa_key_usage_t policy_usage = policy_usage_arg;
    psa_status_t status;
    psa_status_t expected_status_sign = expected_status_sign_arg;
    psa_status_t expected_status_verify = expected_status_verify_arg;
    unsigned char mac[PSA_MAC_MAX_SIZE];

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, policy_usage);
    psa_set_key_algorithm(&attributes, policy_alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    TEST_EQUAL(psa_get_key_usage_flags(&attributes),
               mbedtls_test_update_key_usage_flags(policy_usage));

    status = psa_mac_sign_setup(&operation, key, exercise_alg);
    TEST_EQUAL(status, expected_status_sign);

    /* Calculate the MAC, one-shot case. */
    uint8_t input[128] = { 0 };
    size_t mac_len;
    TEST_EQUAL(psa_mac_compute(key, exercise_alg,
                               input, 128,
                               mac, PSA_MAC_MAX_SIZE, &mac_len),
               expected_status_sign);

    /* Verify correct MAC, one-shot case. */
    status = psa_mac_verify(key, exercise_alg, input, 128,
                            mac, mac_len);

    if (expected_status_sign != PSA_SUCCESS && expected_status_verify == PSA_SUCCESS) {
        TEST_EQUAL(status, PSA_ERROR_INVALID_SIGNATURE);
    } else {
        TEST_EQUAL(status, expected_status_verify);
    }

    psa_mac_abort(&operation);

    memset(mac, 0, sizeof(mac));
    status = psa_mac_verify_setup(&operation, key, exercise_alg);
    TEST_EQUAL(status, expected_status_verify);

exit:
    psa_mac_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_mac_key_policy_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_mac_key_policy( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, *( (int *) params[5] ), *( (int *) params[6] ), *( (int *) params[7] ) );
}
#line 932 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_key_policy(int policy_usage_arg,
                       int policy_alg,
                       int key_type,
                       data_t *key_data,
                       int exercise_alg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    psa_key_usage_t policy_usage = policy_usage_arg;
    psa_status_t status;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, policy_usage);
    psa_set_key_algorithm(&attributes, policy_alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    /* Check if no key usage flag implication is done */
    TEST_EQUAL(policy_usage,
               mbedtls_test_update_key_usage_flags(policy_usage));

    status = psa_cipher_encrypt_setup(&operation, key, exercise_alg);
    if (policy_alg == exercise_alg &&
        (policy_usage & PSA_KEY_USAGE_ENCRYPT) != 0) {
        PSA_ASSERT(status);
    } else {
        TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
    }
    psa_cipher_abort(&operation);

    status = psa_cipher_decrypt_setup(&operation, key, exercise_alg);
    if (policy_alg == exercise_alg &&
        (policy_usage & PSA_KEY_USAGE_DECRYPT) != 0) {
        PSA_ASSERT(status);
    } else {
        TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
    }

exit:
    psa_cipher_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_key_policy_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_cipher_key_policy( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, *( (int *) params[5] ) );
}
#line 982 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_aead_key_policy(int policy_usage_arg,
                     int policy_alg,
                     int key_type,
                     data_t *key_data,
                     int nonce_length_arg,
                     int tag_length_arg,
                     int exercise_alg,
                     int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_usage_t policy_usage = policy_usage_arg;
    psa_status_t status;
    psa_status_t expected_status = expected_status_arg;
    unsigned char nonce[16] = { 0 };
    size_t nonce_length = nonce_length_arg;
    unsigned char tag[16];
    size_t tag_length = tag_length_arg;
    size_t output_length;

    TEST_LE_U(nonce_length, sizeof(nonce));
    TEST_LE_U(tag_length, sizeof(tag));

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, policy_usage);
    psa_set_key_algorithm(&attributes, policy_alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    /* Check if no key usage implication is done */
    TEST_EQUAL(policy_usage,
               mbedtls_test_update_key_usage_flags(policy_usage));

    status = psa_aead_encrypt(key, exercise_alg,
                              nonce, nonce_length,
                              NULL, 0,
                              NULL, 0,
                              tag, tag_length,
                              &output_length);
    if ((policy_usage & PSA_KEY_USAGE_ENCRYPT) != 0) {
        TEST_EQUAL(status, expected_status);
    } else {
        TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
    }

    memset(tag, 0, sizeof(tag));
    status = psa_aead_decrypt(key, exercise_alg,
                              nonce, nonce_length,
                              NULL, 0,
                              tag, tag_length,
                              NULL, 0,
                              &output_length);
    if ((policy_usage & PSA_KEY_USAGE_DECRYPT) == 0) {
        TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
    } else if (expected_status == PSA_SUCCESS) {
        TEST_EQUAL(status, PSA_ERROR_INVALID_SIGNATURE);
    } else {
        TEST_EQUAL(status, expected_status);
    }

exit:
    psa_destroy_key(key);
    PSA_DONE();
}

void test_aead_key_policy_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_aead_key_policy( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, *( (int *) params[5] ), *( (int *) params[6] ), *( (int *) params[7] ), *( (int *) params[8] ) );
}
#line 1052 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_asymmetric_encryption_key_policy(int policy_usage_arg,
                                      int policy_alg,
                                      int key_type,
                                      data_t *key_data,
                                      int exercise_alg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_usage_t policy_usage = policy_usage_arg;
    psa_status_t status;
    size_t key_bits;
    size_t buffer_length;
    unsigned char *buffer = NULL;
    size_t output_length;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, policy_usage);
    psa_set_key_algorithm(&attributes, policy_alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    /* Check if no key usage implication is done */
    TEST_EQUAL(policy_usage,
               mbedtls_test_update_key_usage_flags(policy_usage));

    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);
    buffer_length = PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits,
                                                       exercise_alg);
    ASSERT_ALLOC(buffer, buffer_length);

    status = psa_asymmetric_encrypt(key, exercise_alg,
                                    NULL, 0,
                                    NULL, 0,
                                    buffer, buffer_length,
                                    &output_length);
    if (policy_alg == exercise_alg &&
        (policy_usage & PSA_KEY_USAGE_ENCRYPT) != 0) {
        PSA_ASSERT(status);
    } else {
        TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
    }

    if (buffer_length != 0) {
        memset(buffer, 0, buffer_length);
    }
    status = psa_asymmetric_decrypt(key, exercise_alg,
                                    buffer, buffer_length,
                                    NULL, 0,
                                    buffer, buffer_length,
                                    &output_length);
    if (policy_alg == exercise_alg &&
        (policy_usage & PSA_KEY_USAGE_DECRYPT) != 0) {
        TEST_EQUAL(status, PSA_ERROR_INVALID_PADDING);
    } else {
        TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
    }

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    psa_destroy_key(key);
    PSA_DONE();
    mbedtls_free(buffer);
}

void test_asymmetric_encryption_key_policy_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_asymmetric_encryption_key_policy( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, *( (int *) params[5] ) );
}
#line 1127 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_asymmetric_signature_key_policy(int policy_usage_arg,
                                     int policy_alg,
                                     int key_type,
                                     data_t *key_data,
                                     int exercise_alg,
                                     int payload_length_arg,
                                     int expected_usage_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_usage_t policy_usage = policy_usage_arg;
    psa_key_usage_t expected_usage = expected_usage_arg;
    psa_status_t status;
    unsigned char payload[PSA_HASH_MAX_SIZE] = { 1 };
    /* If `payload_length_arg > 0`, `exercise_alg` is supposed to be
     * compatible with the policy and `payload_length_arg` is supposed to be
     * a valid input length to sign. If `payload_length_arg <= 0`,
     * `exercise_alg` is supposed to be forbidden by the policy. */
    int compatible_alg = payload_length_arg > 0;
    size_t payload_length = compatible_alg ? payload_length_arg : 0;
    unsigned char signature[PSA_SIGNATURE_MAX_SIZE] = { 0 };
    size_t signature_length;

    /* Check if all implicit usage flags are deployed
       in the expected usage flags. */
    TEST_EQUAL(expected_usage,
               mbedtls_test_update_key_usage_flags(policy_usage));

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, policy_usage);
    psa_set_key_algorithm(&attributes, policy_alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    TEST_EQUAL(psa_get_key_usage_flags(&attributes), expected_usage);

    status = psa_sign_hash(key, exercise_alg,
                           payload, payload_length,
                           signature, sizeof(signature),
                           &signature_length);
    if (compatible_alg && (expected_usage & PSA_KEY_USAGE_SIGN_HASH) != 0) {
        PSA_ASSERT(status);
    } else {
        TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
    }

    memset(signature, 0, sizeof(signature));
    status = psa_verify_hash(key, exercise_alg,
                             payload, payload_length,
                             signature, sizeof(signature));
    if (compatible_alg && (expected_usage & PSA_KEY_USAGE_VERIFY_HASH) != 0) {
        TEST_EQUAL(status, PSA_ERROR_INVALID_SIGNATURE);
    } else {
        TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
    }

    if (PSA_ALG_IS_SIGN_HASH(exercise_alg) &&
        PSA_ALG_IS_HASH(PSA_ALG_SIGN_GET_HASH(exercise_alg))) {
        status = psa_sign_message(key, exercise_alg,
                                  payload, payload_length,
                                  signature, sizeof(signature),
                                  &signature_length);
        if (compatible_alg && (expected_usage & PSA_KEY_USAGE_SIGN_MESSAGE) != 0) {
            PSA_ASSERT(status);
        } else {
            TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
        }

        memset(signature, 0, sizeof(signature));
        status = psa_verify_message(key, exercise_alg,
                                    payload, payload_length,
                                    signature, sizeof(signature));
        if (compatible_alg && (expected_usage & PSA_KEY_USAGE_VERIFY_MESSAGE) != 0) {
            TEST_EQUAL(status, PSA_ERROR_INVALID_SIGNATURE);
        } else {
            TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
        }
    }

exit:
    psa_destroy_key(key);
    PSA_DONE();
}

void test_asymmetric_signature_key_policy_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_asymmetric_signature_key_policy( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, *( (int *) params[5] ), *( (int *) params[6] ), *( (int *) params[7] ) );
}
#line 1216 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_key_policy(int policy_usage,
                       int policy_alg,
                       int key_type,
                       data_t *key_data,
                       int exercise_alg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, policy_usage);
    psa_set_key_algorithm(&attributes, policy_alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    PSA_ASSERT(psa_key_derivation_setup(&operation, exercise_alg));

    if (PSA_ALG_IS_TLS12_PRF(exercise_alg) ||
        PSA_ALG_IS_TLS12_PSK_TO_MS(exercise_alg)) {
        PSA_ASSERT(psa_key_derivation_input_bytes(
                       &operation,
                       PSA_KEY_DERIVATION_INPUT_SEED,
                       (const uint8_t *) "", 0));
    }

    status = psa_key_derivation_input_key(&operation,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          key);

    if (policy_alg == exercise_alg &&
        (policy_usage & PSA_KEY_USAGE_DERIVE) != 0) {
        PSA_ASSERT(status);
    } else {
        TEST_EQUAL(status, PSA_ERROR_NOT_PERMITTED);
    }

exit:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_derive_key_policy_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_derive_key_policy( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, *( (int *) params[5] ) );
}
#line 1265 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_agreement_key_policy(int policy_usage,
                          int policy_alg,
                          int key_type_arg,
                          data_t *key_data,
                          int exercise_alg,
                          int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status;
    psa_status_t expected_status = expected_status_arg;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, policy_usage);
    psa_set_key_algorithm(&attributes, policy_alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    PSA_ASSERT(psa_key_derivation_setup(&operation, exercise_alg));
    status = mbedtls_test_psa_key_agreement_with_self(&operation, key);

    TEST_EQUAL(status, expected_status);

exit:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_agreement_key_policy_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_agreement_key_policy( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, *( (int *) params[5] ), *( (int *) params[6] ) );
}
#line 1301 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_key_policy_alg2(int key_type_arg, data_t *key_data,
                     int usage_arg, int alg_arg, int alg2_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t got_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_usage_t usage = usage_arg;
    psa_algorithm_t alg = alg_arg;
    psa_algorithm_t alg2 = alg2_arg;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_enrollment_algorithm(&attributes, alg2);
    psa_set_key_type(&attributes, key_type);
    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    /* Update the usage flags to obtain implicit usage flags */
    usage = mbedtls_test_update_key_usage_flags(usage);
    PSA_ASSERT(psa_get_key_attributes(key, &got_attributes));
    TEST_EQUAL(psa_get_key_usage_flags(&got_attributes), usage);
    TEST_EQUAL(psa_get_key_algorithm(&got_attributes), alg);
    TEST_EQUAL(psa_get_key_enrollment_algorithm(&got_attributes), alg2);

    if (!mbedtls_test_psa_exercise_key(key, usage, alg)) {
        goto exit;
    }
    if (!mbedtls_test_psa_exercise_key(key, usage, alg2)) {
        goto exit;
    }

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&got_attributes);

    psa_destroy_key(key);
    PSA_DONE();
}

void test_key_policy_alg2_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_key_policy_alg2( *( (int *) params[0] ), &data1, *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ) );
}
#line 1348 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_raw_agreement_key_policy(int policy_usage,
                              int policy_alg,
                              int key_type_arg,
                              data_t *key_data,
                              int exercise_alg,
                              int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status;
    psa_status_t expected_status = expected_status_arg;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, policy_usage);
    psa_set_key_algorithm(&attributes, policy_alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    status = mbedtls_test_psa_raw_key_agreement_with_self(exercise_alg, key);

    TEST_EQUAL(status, expected_status);

exit:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_raw_agreement_key_policy_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_raw_agreement_key_policy( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, *( (int *) params[5] ), *( (int *) params[6] ) );
}
#line 1383 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_copy_success(int source_usage_arg,
                  int source_alg_arg, int source_alg2_arg,
                  int type_arg, data_t *material,
                  int copy_attributes,
                  int target_usage_arg,
                  int target_alg_arg, int target_alg2_arg,
                  int expected_usage_arg,
                  int expected_alg_arg, int expected_alg2_arg)
{
    psa_key_attributes_t source_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t target_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_usage_t expected_usage = expected_usage_arg;
    psa_algorithm_t expected_alg = expected_alg_arg;
    psa_algorithm_t expected_alg2 = expected_alg2_arg;
    mbedtls_svc_key_id_t source_key = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_svc_key_id_t target_key = MBEDTLS_SVC_KEY_ID_INIT;
    uint8_t *export_buffer = NULL;

    PSA_ASSERT(psa_crypto_init());

    /* Prepare the source key. */
    psa_set_key_usage_flags(&source_attributes, source_usage_arg);
    psa_set_key_algorithm(&source_attributes, source_alg_arg);
    psa_set_key_enrollment_algorithm(&source_attributes, source_alg2_arg);
    psa_set_key_type(&source_attributes, type_arg);
    PSA_ASSERT(psa_import_key(&source_attributes,
                              material->x, material->len,
                              &source_key));
    PSA_ASSERT(psa_get_key_attributes(source_key, &source_attributes));

    /* Prepare the target attributes. */
    if (copy_attributes) {
        target_attributes = source_attributes;
        /* Set volatile lifetime to reset the key identifier to 0. */
        psa_set_key_lifetime(&target_attributes, PSA_KEY_LIFETIME_VOLATILE);
    }

    if (target_usage_arg != -1) {
        psa_set_key_usage_flags(&target_attributes, target_usage_arg);
    }
    if (target_alg_arg != -1) {
        psa_set_key_algorithm(&target_attributes, target_alg_arg);
    }
    if (target_alg2_arg != -1) {
        psa_set_key_enrollment_algorithm(&target_attributes, target_alg2_arg);
    }

    /* Copy the key. */
    PSA_ASSERT(psa_copy_key(source_key,
                            &target_attributes, &target_key));

    /* Destroy the source to ensure that this doesn't affect the target. */
    PSA_ASSERT(psa_destroy_key(source_key));

    /* Test that the target slot has the expected content and policy. */
    PSA_ASSERT(psa_get_key_attributes(target_key, &target_attributes));
    TEST_EQUAL(psa_get_key_type(&source_attributes),
               psa_get_key_type(&target_attributes));
    TEST_EQUAL(psa_get_key_bits(&source_attributes),
               psa_get_key_bits(&target_attributes));
    TEST_EQUAL(expected_usage, psa_get_key_usage_flags(&target_attributes));
    TEST_EQUAL(expected_alg, psa_get_key_algorithm(&target_attributes));
    TEST_EQUAL(expected_alg2,
               psa_get_key_enrollment_algorithm(&target_attributes));
    if (expected_usage & PSA_KEY_USAGE_EXPORT) {
        size_t length;
        ASSERT_ALLOC(export_buffer, material->len);
        PSA_ASSERT(psa_export_key(target_key, export_buffer,
                                  material->len, &length));
        ASSERT_COMPARE(material->x, material->len,
                       export_buffer, length);
    }

    if (!mbedtls_test_psa_exercise_key(target_key, expected_usage, expected_alg)) {
        goto exit;
    }
    if (!mbedtls_test_psa_exercise_key(target_key, expected_usage, expected_alg2)) {
        goto exit;
    }

    PSA_ASSERT(psa_destroy_key(target_key));

exit:
    /*
     * Source and target key attributes may have been returned by
     * psa_get_key_attributes() thus reset them as required.
     */
    psa_reset_key_attributes(&source_attributes);
    psa_reset_key_attributes(&target_attributes);

    PSA_DONE();
    mbedtls_free(export_buffer);
}

void test_copy_success_wrapper( void ** params )
{
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_copy_success( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), &data4, *( (int *) params[6] ), *( (int *) params[7] ), *( (int *) params[8] ), *( (int *) params[9] ), *( (int *) params[10] ), *( (int *) params[11] ), *( (int *) params[12] ) );
}
#line 1479 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_copy_fail(int source_usage_arg,
               int source_alg_arg, int source_alg2_arg,
               int type_arg, data_t *material,
               int target_type_arg, int target_bits_arg,
               int target_usage_arg,
               int target_alg_arg, int target_alg2_arg,
               int target_id_arg, int target_lifetime_arg,
               int expected_status_arg)
{
    psa_key_attributes_t source_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t target_attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t source_key = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_svc_key_id_t target_key = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(1, target_id_arg);

    PSA_ASSERT(psa_crypto_init());

    /* Prepare the source key. */
    psa_set_key_usage_flags(&source_attributes, source_usage_arg);
    psa_set_key_algorithm(&source_attributes, source_alg_arg);
    psa_set_key_enrollment_algorithm(&source_attributes, source_alg2_arg);
    psa_set_key_type(&source_attributes, type_arg);
    PSA_ASSERT(psa_import_key(&source_attributes,
                              material->x, material->len,
                              &source_key));

    /* Prepare the target attributes. */
    psa_set_key_id(&target_attributes, key_id);
    psa_set_key_lifetime(&target_attributes, target_lifetime_arg);
    psa_set_key_type(&target_attributes, target_type_arg);
    psa_set_key_bits(&target_attributes, target_bits_arg);
    psa_set_key_usage_flags(&target_attributes, target_usage_arg);
    psa_set_key_algorithm(&target_attributes, target_alg_arg);
    psa_set_key_enrollment_algorithm(&target_attributes, target_alg2_arg);

    /* Try to copy the key. */
    TEST_EQUAL(psa_copy_key(source_key,
                            &target_attributes, &target_key),
               expected_status_arg);

    PSA_ASSERT(psa_destroy_key(source_key));

exit:
    psa_reset_key_attributes(&source_attributes);
    psa_reset_key_attributes(&target_attributes);
    PSA_DONE();
}

void test_copy_fail_wrapper( void ** params )
{
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_copy_fail( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), &data4, *( (int *) params[6] ), *( (int *) params[7] ), *( (int *) params[8] ), *( (int *) params[9] ), *( (int *) params[10] ), *( (int *) params[11] ), *( (int *) params[12] ), *( (int *) params[13] ) );
}
#line 1529 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_hash_operation_init()
{
    const uint8_t input[1] = { 0 };
    /* Test each valid way of initializing the object, except for `= {0}`, as
     * Clang 5 complains when `-Wmissing-field-initializers` is used, even
     * though it's OK by the C standard. We could test for this, but we'd need
     * to suppress the Clang warning for the test. */
    psa_hash_operation_t func = psa_hash_operation_init();
    psa_hash_operation_t init = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t zero;

    memset(&zero, 0, sizeof(zero));

    /* A freshly-initialized hash operation should not be usable. */
    TEST_EQUAL(psa_hash_update(&func, input, sizeof(input)),
               PSA_ERROR_BAD_STATE);
    TEST_EQUAL(psa_hash_update(&init, input, sizeof(input)),
               PSA_ERROR_BAD_STATE);
    TEST_EQUAL(psa_hash_update(&zero, input, sizeof(input)),
               PSA_ERROR_BAD_STATE);

    /* A default hash operation should be abortable without error. */
    PSA_ASSERT(psa_hash_abort(&func));
    PSA_ASSERT(psa_hash_abort(&init));
    PSA_ASSERT(psa_hash_abort(&zero));
exit:
    ;
}

void test_hash_operation_init_wrapper( void ** params )
{
    (void)params;

    test_hash_operation_init(  );
}
#line 1558 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_hash_setup(int alg_arg,
                int expected_status_arg)
{
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status;

    PSA_ASSERT(psa_crypto_init());

    status = psa_hash_setup(&operation, alg);
    TEST_EQUAL(status, expected_status);

    /* Whether setup succeeded or failed, abort must succeed. */
    PSA_ASSERT(psa_hash_abort(&operation));

    /* If setup failed, reproduce the failure, so as to
     * test the resulting state of the operation object. */
    if (status != PSA_SUCCESS) {
        TEST_EQUAL(psa_hash_setup(&operation, alg), status);
    }

    /* Now the operation object should be reusable. */
#if defined(KNOWN_SUPPORTED_HASH_ALG)
    PSA_ASSERT(psa_hash_setup(&operation, KNOWN_SUPPORTED_HASH_ALG));
    PSA_ASSERT(psa_hash_abort(&operation));
#endif

exit:
    PSA_DONE();
}

void test_hash_setup_wrapper( void ** params )
{

    test_hash_setup( *( (int *) params[0] ), *( (int *) params[1] ) );
}
#line 1592 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_hash_compute_fail(int alg_arg, data_t *input,
                       int output_size_arg, int expected_status_arg)
{
    psa_algorithm_t alg = alg_arg;
    uint8_t *output = NULL;
    size_t output_size = output_size_arg;
    size_t output_length = INVALID_EXPORT_LENGTH;
    psa_status_t expected_status = expected_status_arg;
    psa_status_t status;

    ASSERT_ALLOC(output, output_size);

    PSA_ASSERT(psa_crypto_init());

    status = psa_hash_compute(alg, input->x, input->len,
                              output, output_size, &output_length);
    TEST_EQUAL(status, expected_status);
    TEST_LE_U(output_length, output_size);

exit:
    mbedtls_free(output);
    PSA_DONE();
}

void test_hash_compute_fail_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_hash_compute_fail( *( (int *) params[0] ), &data1, *( (int *) params[3] ), *( (int *) params[4] ) );
}
#line 1618 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_hash_compare_fail(int alg_arg, data_t *input,
                       data_t *reference_hash,
                       int expected_status_arg)
{
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_status_t status;

    PSA_ASSERT(psa_crypto_init());

    status = psa_hash_compare(alg, input->x, input->len,
                              reference_hash->x, reference_hash->len);
    TEST_EQUAL(status, expected_status);

exit:
    PSA_DONE();
}

void test_hash_compare_fail_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_hash_compare_fail( *( (int *) params[0] ), &data1, &data3, *( (int *) params[5] ) );
}
#line 1638 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_hash_compute_compare(int alg_arg, data_t *input,
                          data_t *expected_output)
{
    psa_algorithm_t alg = alg_arg;
    uint8_t output[PSA_HASH_MAX_SIZE + 1];
    size_t output_length = INVALID_EXPORT_LENGTH;
    size_t i;

    PSA_ASSERT(psa_crypto_init());

    /* Compute with tight buffer */
    PSA_ASSERT(psa_hash_compute(alg, input->x, input->len,
                                output, PSA_HASH_LENGTH(alg),
                                &output_length));
    TEST_EQUAL(output_length, PSA_HASH_LENGTH(alg));
    ASSERT_COMPARE(output, output_length,
                   expected_output->x, expected_output->len);

    /* Compute with larger buffer */
    PSA_ASSERT(psa_hash_compute(alg, input->x, input->len,
                                output, sizeof(output),
                                &output_length));
    TEST_EQUAL(output_length, PSA_HASH_LENGTH(alg));
    ASSERT_COMPARE(output, output_length,
                   expected_output->x, expected_output->len);

    /* Compare with correct hash */
    PSA_ASSERT(psa_hash_compare(alg, input->x, input->len,
                                output, output_length));

    /* Compare with trailing garbage */
    TEST_EQUAL(psa_hash_compare(alg, input->x, input->len,
                                output, output_length + 1),
               PSA_ERROR_INVALID_SIGNATURE);

    /* Compare with truncated hash */
    TEST_EQUAL(psa_hash_compare(alg, input->x, input->len,
                                output, output_length - 1),
               PSA_ERROR_INVALID_SIGNATURE);

    /* Compare with corrupted value */
    for (i = 0; i < output_length; i++) {
        mbedtls_test_set_step(i);
        output[i] ^= 1;
        TEST_EQUAL(psa_hash_compare(alg, input->x, input->len,
                                    output, output_length),
                   PSA_ERROR_INVALID_SIGNATURE);
        output[i] ^= 1;
    }

exit:
    PSA_DONE();
}

void test_hash_compute_compare_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};

    test_hash_compute_compare( *( (int *) params[0] ), &data1, &data3 );
}
#if defined(PSA_WANT_ALG_SHA_256)
#line 1694 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_hash_bad_order()
{
    psa_algorithm_t alg = PSA_ALG_SHA_256;
    unsigned char input[] = "";
    /* SHA-256 hash of an empty string */
    const unsigned char valid_hash[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
        0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    unsigned char hash[sizeof(valid_hash)] = { 0 };
    size_t hash_len;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;

    PSA_ASSERT(psa_crypto_init());

    /* Call setup twice in a row. */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_hash_setup(&operation, alg),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_hash_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* Call update without calling setup beforehand. */
    TEST_EQUAL(psa_hash_update(&operation, input, sizeof(input)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_hash_abort(&operation));

    /* Check that update calls abort on error. */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    operation.id = UINT_MAX;
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_hash_update(&operation, input, sizeof(input)),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_hash_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* Call update after finish. */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    PSA_ASSERT(psa_hash_finish(&operation,
                               hash, sizeof(hash), &hash_len));
    TEST_EQUAL(psa_hash_update(&operation, input, sizeof(input)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_hash_abort(&operation));

    /* Call verify without calling setup beforehand. */
    TEST_EQUAL(psa_hash_verify(&operation,
                               valid_hash, sizeof(valid_hash)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_hash_abort(&operation));

    /* Call verify after finish. */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    PSA_ASSERT(psa_hash_finish(&operation,
                               hash, sizeof(hash), &hash_len));
    TEST_EQUAL(psa_hash_verify(&operation,
                               valid_hash, sizeof(valid_hash)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_hash_abort(&operation));

    /* Call verify twice in a row. */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    PSA_ASSERT(psa_hash_verify(&operation,
                               valid_hash, sizeof(valid_hash)));
    ASSERT_OPERATION_IS_INACTIVE(operation);
    TEST_EQUAL(psa_hash_verify(&operation,
                               valid_hash, sizeof(valid_hash)),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_hash_abort(&operation));

    /* Call finish without calling setup beforehand. */
    TEST_EQUAL(psa_hash_finish(&operation,
                               hash, sizeof(hash), &hash_len),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_hash_abort(&operation));

    /* Call finish twice in a row. */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    PSA_ASSERT(psa_hash_finish(&operation,
                               hash, sizeof(hash), &hash_len));
    TEST_EQUAL(psa_hash_finish(&operation,
                               hash, sizeof(hash), &hash_len),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_hash_abort(&operation));

    /* Call finish after calling verify. */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    PSA_ASSERT(psa_hash_verify(&operation,
                               valid_hash, sizeof(valid_hash)));
    TEST_EQUAL(psa_hash_finish(&operation,
                               hash, sizeof(hash), &hash_len),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_hash_abort(&operation));

exit:
    PSA_DONE();
}

void test_hash_bad_order_wrapper( void ** params )
{
    (void)params;

    test_hash_bad_order(  );
}
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_256)
#line 1799 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_hash_verify_bad_args()
{
    psa_algorithm_t alg = PSA_ALG_SHA_256;
    /* SHA-256 hash of an empty string with 2 extra bytes (0xaa and 0xbb)
     * appended to it */
    unsigned char hash[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
        0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55, 0xaa, 0xbb
    };
    size_t expected_size = PSA_HASH_LENGTH(alg);
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;

    PSA_ASSERT(psa_crypto_init());

    /* psa_hash_verify with a smaller hash than expected */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_hash_verify(&operation, hash, expected_size - 1),
               PSA_ERROR_INVALID_SIGNATURE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_hash_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* psa_hash_verify with a non-matching hash */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    TEST_EQUAL(psa_hash_verify(&operation, hash + 1, expected_size),
               PSA_ERROR_INVALID_SIGNATURE);

    /* psa_hash_verify with a hash longer than expected */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    TEST_EQUAL(psa_hash_verify(&operation, hash, sizeof(hash)),
               PSA_ERROR_INVALID_SIGNATURE);

exit:
    PSA_DONE();
}

void test_hash_verify_bad_args_wrapper( void ** params )
{
    (void)params;

    test_hash_verify_bad_args(  );
}
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_256)
#line 1839 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_hash_finish_bad_args()
{
    psa_algorithm_t alg = PSA_ALG_SHA_256;
    unsigned char hash[PSA_HASH_MAX_SIZE];
    size_t expected_size = PSA_HASH_LENGTH(alg);
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    size_t hash_len;

    PSA_ASSERT(psa_crypto_init());

    /* psa_hash_finish with a smaller hash buffer than expected */
    PSA_ASSERT(psa_hash_setup(&operation, alg));
    TEST_EQUAL(psa_hash_finish(&operation,
                               hash, expected_size - 1, &hash_len),
               PSA_ERROR_BUFFER_TOO_SMALL);

exit:
    PSA_DONE();
}

void test_hash_finish_bad_args_wrapper( void ** params )
{
    (void)params;

    test_hash_finish_bad_args(  );
}
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_256)
#line 1861 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_hash_clone_source_state()
{
    psa_algorithm_t alg = PSA_ALG_SHA_256;
    unsigned char hash[PSA_HASH_MAX_SIZE];
    psa_hash_operation_t op_source = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t op_init = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t op_setup = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t op_finished = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t op_aborted = PSA_HASH_OPERATION_INIT;
    size_t hash_len;

    PSA_ASSERT(psa_crypto_init());
    PSA_ASSERT(psa_hash_setup(&op_source, alg));

    PSA_ASSERT(psa_hash_setup(&op_setup, alg));
    PSA_ASSERT(psa_hash_setup(&op_finished, alg));
    PSA_ASSERT(psa_hash_finish(&op_finished,
                               hash, sizeof(hash), &hash_len));
    PSA_ASSERT(psa_hash_setup(&op_aborted, alg));
    PSA_ASSERT(psa_hash_abort(&op_aborted));

    TEST_EQUAL(psa_hash_clone(&op_source, &op_setup),
               PSA_ERROR_BAD_STATE);

    PSA_ASSERT(psa_hash_clone(&op_source, &op_init));
    PSA_ASSERT(psa_hash_finish(&op_init,
                               hash, sizeof(hash), &hash_len));
    PSA_ASSERT(psa_hash_clone(&op_source, &op_finished));
    PSA_ASSERT(psa_hash_finish(&op_finished,
                               hash, sizeof(hash), &hash_len));
    PSA_ASSERT(psa_hash_clone(&op_source, &op_aborted));
    PSA_ASSERT(psa_hash_finish(&op_aborted,
                               hash, sizeof(hash), &hash_len));

exit:
    psa_hash_abort(&op_source);
    psa_hash_abort(&op_init);
    psa_hash_abort(&op_setup);
    psa_hash_abort(&op_finished);
    psa_hash_abort(&op_aborted);
    PSA_DONE();
}

void test_hash_clone_source_state_wrapper( void ** params )
{
    (void)params;

    test_hash_clone_source_state(  );
}
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_256)
#line 1906 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_hash_clone_target_state()
{
    psa_algorithm_t alg = PSA_ALG_SHA_256;
    unsigned char hash[PSA_HASH_MAX_SIZE];
    psa_hash_operation_t op_init = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t op_setup = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t op_finished = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t op_aborted = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t op_target = PSA_HASH_OPERATION_INIT;
    size_t hash_len;

    PSA_ASSERT(psa_crypto_init());

    PSA_ASSERT(psa_hash_setup(&op_setup, alg));
    PSA_ASSERT(psa_hash_setup(&op_finished, alg));
    PSA_ASSERT(psa_hash_finish(&op_finished,
                               hash, sizeof(hash), &hash_len));
    PSA_ASSERT(psa_hash_setup(&op_aborted, alg));
    PSA_ASSERT(psa_hash_abort(&op_aborted));

    PSA_ASSERT(psa_hash_clone(&op_setup, &op_target));
    PSA_ASSERT(psa_hash_finish(&op_target,
                               hash, sizeof(hash), &hash_len));

    TEST_EQUAL(psa_hash_clone(&op_init, &op_target), PSA_ERROR_BAD_STATE);
    TEST_EQUAL(psa_hash_clone(&op_finished, &op_target),
               PSA_ERROR_BAD_STATE);
    TEST_EQUAL(psa_hash_clone(&op_aborted, &op_target),
               PSA_ERROR_BAD_STATE);

exit:
    psa_hash_abort(&op_target);
    psa_hash_abort(&op_init);
    psa_hash_abort(&op_setup);
    psa_hash_abort(&op_finished);
    psa_hash_abort(&op_aborted);
    PSA_DONE();
}

void test_hash_clone_target_state_wrapper( void ** params )
{
    (void)params;

    test_hash_clone_target_state(  );
}
#endif /* PSA_WANT_ALG_SHA_256 */
#line 1947 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_mac_operation_init()
{
    const uint8_t input[1] = { 0 };

    /* Test each valid way of initializing the object, except for `= {0}`, as
     * Clang 5 complains when `-Wmissing-field-initializers` is used, even
     * though it's OK by the C standard. We could test for this, but we'd need
     * to suppress the Clang warning for the test. */
    psa_mac_operation_t func = psa_mac_operation_init();
    psa_mac_operation_t init = PSA_MAC_OPERATION_INIT;
    psa_mac_operation_t zero;

    memset(&zero, 0, sizeof(zero));

    /* A freshly-initialized MAC operation should not be usable. */
    TEST_EQUAL(psa_mac_update(&func,
                              input, sizeof(input)),
               PSA_ERROR_BAD_STATE);
    TEST_EQUAL(psa_mac_update(&init,
                              input, sizeof(input)),
               PSA_ERROR_BAD_STATE);
    TEST_EQUAL(psa_mac_update(&zero,
                              input, sizeof(input)),
               PSA_ERROR_BAD_STATE);

    /* A default MAC operation should be abortable without error. */
    PSA_ASSERT(psa_mac_abort(&func));
    PSA_ASSERT(psa_mac_abort(&init));
    PSA_ASSERT(psa_mac_abort(&zero));
exit:
    ;
}

void test_mac_operation_init_wrapper( void ** params )
{
    (void)params;

    test_mac_operation_init(  );
}
#line 1980 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_mac_setup(int key_type_arg,
               data_t *key,
               int alg_arg,
               int expected_status_arg)
{
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
#if defined(KNOWN_SUPPORTED_MAC_ALG)
    const uint8_t smoke_test_key_data[16] = "kkkkkkkkkkkkkkkk";
#endif

    PSA_ASSERT(psa_crypto_init());

    if (!exercise_mac_setup(key_type, key->x, key->len, alg,
                            &operation, &status)) {
        goto exit;
    }
    TEST_EQUAL(status, expected_status);

    /* The operation object should be reusable. */
#if defined(KNOWN_SUPPORTED_MAC_ALG)
    if (!exercise_mac_setup(KNOWN_SUPPORTED_MAC_KEY_TYPE,
                            smoke_test_key_data,
                            sizeof(smoke_test_key_data),
                            KNOWN_SUPPORTED_MAC_ALG,
                            &operation, &status)) {
        goto exit;
    }
    TEST_EQUAL(status, PSA_SUCCESS);
#endif

exit:
    PSA_DONE();
}

void test_mac_setup_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_mac_setup( *( (int *) params[0] ), &data1, *( (int *) params[3] ), *( (int *) params[4] ) );
}
#if defined(PSA_WANT_KEY_TYPE_HMAC)
#if defined(PSA_WANT_ALG_HMAC)
#if defined(PSA_WANT_ALG_SHA_256)
#line 2020 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_mac_bad_order()
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = PSA_KEY_TYPE_HMAC;
    psa_algorithm_t alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
    const uint8_t key_data[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    };
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    uint8_t sign_mac[PSA_MAC_MAX_SIZE + 10] = { 0 };
    size_t sign_mac_length = 0;
    const uint8_t input[] = { 0xbb, 0xbb, 0xbb, 0xbb };
    const uint8_t verify_mac[] = {
        0x74, 0x65, 0x93, 0x8c, 0xeb, 0x1d, 0xb3, 0x76, 0x5a, 0x38, 0xe7, 0xdd,
        0x85, 0xc5, 0xad, 0x4f, 0x07, 0xe7, 0xd5, 0xb2, 0x64, 0xf0, 0x1a, 0x1a,
        0x2c, 0xf9, 0x18, 0xca, 0x59, 0x7e, 0x5d, 0xf6
    };

    PSA_ASSERT(psa_crypto_init());
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data, sizeof(key_data),
                              &key));

    /* Call update without calling setup beforehand. */
    TEST_EQUAL(psa_mac_update(&operation, input, sizeof(input)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_mac_abort(&operation));

    /* Call sign finish without calling setup beforehand. */
    TEST_EQUAL(psa_mac_sign_finish(&operation, sign_mac, sizeof(sign_mac),
                                   &sign_mac_length),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_mac_abort(&operation));

    /* Call verify finish without calling setup beforehand. */
    TEST_EQUAL(psa_mac_verify_finish(&operation,
                                     verify_mac, sizeof(verify_mac)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_mac_abort(&operation));

    /* Call setup twice in a row. */
    PSA_ASSERT(psa_mac_sign_setup(&operation, key, alg));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_mac_sign_setup(&operation, key, alg),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_mac_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* Call update after sign finish. */
    PSA_ASSERT(psa_mac_sign_setup(&operation, key, alg));
    PSA_ASSERT(psa_mac_update(&operation, input, sizeof(input)));
    PSA_ASSERT(psa_mac_sign_finish(&operation,
                                   sign_mac, sizeof(sign_mac),
                                   &sign_mac_length));
    TEST_EQUAL(psa_mac_update(&operation, input, sizeof(input)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_mac_abort(&operation));

    /* Call update after verify finish. */
    PSA_ASSERT(psa_mac_verify_setup(&operation, key, alg));
    PSA_ASSERT(psa_mac_update(&operation, input, sizeof(input)));
    PSA_ASSERT(psa_mac_verify_finish(&operation,
                                     verify_mac, sizeof(verify_mac)));
    TEST_EQUAL(psa_mac_update(&operation, input, sizeof(input)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_mac_abort(&operation));

    /* Call sign finish twice in a row. */
    PSA_ASSERT(psa_mac_sign_setup(&operation, key, alg));
    PSA_ASSERT(psa_mac_update(&operation, input, sizeof(input)));
    PSA_ASSERT(psa_mac_sign_finish(&operation,
                                   sign_mac, sizeof(sign_mac),
                                   &sign_mac_length));
    TEST_EQUAL(psa_mac_sign_finish(&operation,
                                   sign_mac, sizeof(sign_mac),
                                   &sign_mac_length),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_mac_abort(&operation));

    /* Call verify finish twice in a row. */
    PSA_ASSERT(psa_mac_verify_setup(&operation, key, alg));
    PSA_ASSERT(psa_mac_update(&operation, input, sizeof(input)));
    PSA_ASSERT(psa_mac_verify_finish(&operation,
                                     verify_mac, sizeof(verify_mac)));
    TEST_EQUAL(psa_mac_verify_finish(&operation,
                                     verify_mac, sizeof(verify_mac)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_mac_abort(&operation));

    /* Setup sign but try verify. */
    PSA_ASSERT(psa_mac_sign_setup(&operation, key, alg));
    PSA_ASSERT(psa_mac_update(&operation, input, sizeof(input)));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_mac_verify_finish(&operation,
                                     verify_mac, sizeof(verify_mac)),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_mac_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* Setup verify but try sign. */
    PSA_ASSERT(psa_mac_verify_setup(&operation, key, alg));
    PSA_ASSERT(psa_mac_update(&operation, input, sizeof(input)));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_mac_sign_finish(&operation,
                                   sign_mac, sizeof(sign_mac),
                                   &sign_mac_length),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_mac_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    PSA_ASSERT(psa_destroy_key(key));

exit:
    PSA_DONE();
}

void test_mac_bad_order_wrapper( void ** params )
{
    (void)params;

    test_mac_bad_order(  );
}
#endif /* PSA_WANT_ALG_SHA_256 */
#endif /* PSA_WANT_ALG_HMAC */
#endif /* PSA_WANT_KEY_TYPE_HMAC */
#line 2147 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_mac_sign(int key_type_arg,
              data_t *key_data,
              int alg_arg,
              data_t *input,
              data_t *expected_mac)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t *actual_mac = NULL;
    size_t mac_buffer_size =
        PSA_MAC_LENGTH(key_type, PSA_BYTES_TO_BITS(key_data->len), alg);
    size_t mac_length = 0;
    const size_t output_sizes_to_test[] = {
        0,
        1,
        expected_mac->len - 1,
        expected_mac->len,
        expected_mac->len + 1,
    };

    TEST_LE_U(mac_buffer_size, PSA_MAC_MAX_SIZE);
    /* We expect PSA_MAC_LENGTH to be exact. */
    TEST_ASSERT(expected_mac->len == mac_buffer_size);

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    for (size_t i = 0; i < ARRAY_LENGTH(output_sizes_to_test); i++) {
        const size_t output_size = output_sizes_to_test[i];
        psa_status_t expected_status =
            (output_size >= expected_mac->len ? PSA_SUCCESS :
             PSA_ERROR_BUFFER_TOO_SMALL);

        mbedtls_test_set_step(output_size);
        ASSERT_ALLOC(actual_mac, output_size);

        /* Calculate the MAC, one-shot case. */
        TEST_EQUAL(psa_mac_compute(key, alg,
                                   input->x, input->len,
                                   actual_mac, output_size, &mac_length),
                   expected_status);
        if (expected_status == PSA_SUCCESS) {
            ASSERT_COMPARE(expected_mac->x, expected_mac->len,
                           actual_mac, mac_length);
        }

        if (output_size > 0) {
            memset(actual_mac, 0, output_size);
        }

        /* Calculate the MAC, multi-part case. */
        PSA_ASSERT(psa_mac_sign_setup(&operation, key, alg));
        PSA_ASSERT(psa_mac_update(&operation,
                                  input->x, input->len));
        TEST_EQUAL(psa_mac_sign_finish(&operation,
                                       actual_mac, output_size,
                                       &mac_length),
                   expected_status);
        PSA_ASSERT(psa_mac_abort(&operation));

        if (expected_status == PSA_SUCCESS) {
            ASSERT_COMPARE(expected_mac->x, expected_mac->len,
                           actual_mac, mac_length);
        }
        mbedtls_free(actual_mac);
        actual_mac = NULL;
    }

exit:
    psa_mac_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
    mbedtls_free(actual_mac);
}

void test_mac_sign_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_mac_sign( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6 );
}
#line 2233 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_mac_verify(int key_type_arg,
                data_t *key_data,
                int alg_arg,
                data_t *input,
                data_t *expected_mac)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t *perturbed_mac = NULL;

    TEST_LE_U(expected_mac->len, PSA_MAC_MAX_SIZE);

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    /* Verify correct MAC, one-shot case. */
    PSA_ASSERT(psa_mac_verify(key, alg, input->x, input->len,
                              expected_mac->x, expected_mac->len));

    /* Verify correct MAC, multi-part case. */
    PSA_ASSERT(psa_mac_verify_setup(&operation, key, alg));
    PSA_ASSERT(psa_mac_update(&operation,
                              input->x, input->len));
    PSA_ASSERT(psa_mac_verify_finish(&operation,
                                     expected_mac->x,
                                     expected_mac->len));

    /* Test a MAC that's too short, one-shot case. */
    TEST_EQUAL(psa_mac_verify(key, alg,
                              input->x, input->len,
                              expected_mac->x,
                              expected_mac->len - 1),
               PSA_ERROR_INVALID_SIGNATURE);

    /* Test a MAC that's too short, multi-part case. */
    PSA_ASSERT(psa_mac_verify_setup(&operation, key, alg));
    PSA_ASSERT(psa_mac_update(&operation,
                              input->x, input->len));
    TEST_EQUAL(psa_mac_verify_finish(&operation,
                                     expected_mac->x,
                                     expected_mac->len - 1),
               PSA_ERROR_INVALID_SIGNATURE);

    /* Test a MAC that's too long, one-shot case. */
    ASSERT_ALLOC(perturbed_mac, expected_mac->len + 1);
    memcpy(perturbed_mac, expected_mac->x, expected_mac->len);
    TEST_EQUAL(psa_mac_verify(key, alg,
                              input->x, input->len,
                              perturbed_mac, expected_mac->len + 1),
               PSA_ERROR_INVALID_SIGNATURE);

    /* Test a MAC that's too long, multi-part case. */
    PSA_ASSERT(psa_mac_verify_setup(&operation, key, alg));
    PSA_ASSERT(psa_mac_update(&operation,
                              input->x, input->len));
    TEST_EQUAL(psa_mac_verify_finish(&operation,
                                     perturbed_mac,
                                     expected_mac->len + 1),
               PSA_ERROR_INVALID_SIGNATURE);

    /* Test changing one byte. */
    for (size_t i = 0; i < expected_mac->len; i++) {
        mbedtls_test_set_step(i);
        perturbed_mac[i] ^= 1;

        TEST_EQUAL(psa_mac_verify(key, alg,
                                  input->x, input->len,
                                  perturbed_mac, expected_mac->len),
                   PSA_ERROR_INVALID_SIGNATURE);

        PSA_ASSERT(psa_mac_verify_setup(&operation, key, alg));
        PSA_ASSERT(psa_mac_update(&operation,
                                  input->x, input->len));
        TEST_EQUAL(psa_mac_verify_finish(&operation,
                                         perturbed_mac,
                                         expected_mac->len),
                   PSA_ERROR_INVALID_SIGNATURE);
        perturbed_mac[i] ^= 1;
    }

exit:
    psa_mac_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
    mbedtls_free(perturbed_mac);
}

void test_mac_verify_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_mac_verify( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6 );
}
#line 2331 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_operation_init()
{
    const uint8_t input[1] = { 0 };
    unsigned char output[1] = { 0 };
    size_t output_length;
    /* Test each valid way of initializing the object, except for `= {0}`, as
     * Clang 5 complains when `-Wmissing-field-initializers` is used, even
     * though it's OK by the C standard. We could test for this, but we'd need
     * to suppress the Clang warning for the test. */
    psa_cipher_operation_t func = psa_cipher_operation_init();
    psa_cipher_operation_t init = PSA_CIPHER_OPERATION_INIT;
    psa_cipher_operation_t zero;

    memset(&zero, 0, sizeof(zero));

    /* A freshly-initialized cipher operation should not be usable. */
    TEST_EQUAL(psa_cipher_update(&func,
                                 input, sizeof(input),
                                 output, sizeof(output),
                                 &output_length),
               PSA_ERROR_BAD_STATE);
    TEST_EQUAL(psa_cipher_update(&init,
                                 input, sizeof(input),
                                 output, sizeof(output),
                                 &output_length),
               PSA_ERROR_BAD_STATE);
    TEST_EQUAL(psa_cipher_update(&zero,
                                 input, sizeof(input),
                                 output, sizeof(output),
                                 &output_length),
               PSA_ERROR_BAD_STATE);

    /* A default cipher operation should be abortable without error. */
    PSA_ASSERT(psa_cipher_abort(&func));
    PSA_ASSERT(psa_cipher_abort(&init));
    PSA_ASSERT(psa_cipher_abort(&zero));
exit:
    ;
}

void test_cipher_operation_init_wrapper( void ** params )
{
    (void)params;

    test_cipher_operation_init(  );
}
#line 2371 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_setup(int key_type_arg,
                  data_t *key,
                  int alg_arg,
                  int expected_status_arg)
{
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    psa_status_t status;
#if defined(KNOWN_SUPPORTED_CIPHER_ALG)
    const uint8_t smoke_test_key_data[16] = "kkkkkkkkkkkkkkkk";
#endif

    PSA_ASSERT(psa_crypto_init());

    if (!exercise_cipher_setup(key_type, key->x, key->len, alg,
                               &operation, &status)) {
        goto exit;
    }
    TEST_EQUAL(status, expected_status);

    /* The operation object should be reusable. */
#if defined(KNOWN_SUPPORTED_CIPHER_ALG)
    if (!exercise_cipher_setup(KNOWN_SUPPORTED_CIPHER_KEY_TYPE,
                               smoke_test_key_data,
                               sizeof(smoke_test_key_data),
                               KNOWN_SUPPORTED_CIPHER_ALG,
                               &operation, &status)) {
        goto exit;
    }
    TEST_EQUAL(status, PSA_SUCCESS);
#endif

exit:
    psa_cipher_abort(&operation);
    PSA_DONE();
}

void test_cipher_setup_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_cipher_setup( *( (int *) params[0] ), &data1, *( (int *) params[3] ), *( (int *) params[4] ) );
}
#if defined(PSA_WANT_KEY_TYPE_AES)
#if defined(PSA_WANT_ALG_CBC_PKCS7)
#line 2412 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_bad_order()
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = PSA_KEY_TYPE_AES;
    psa_algorithm_t alg = PSA_ALG_CBC_PKCS7;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    unsigned char iv[PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES)] = { 0 };
    const uint8_t key_data[] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa
    };
    const uint8_t text[] = {
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
        0xbb, 0xbb, 0xbb, 0xbb
    };
    uint8_t buffer[PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES)] = { 0 };
    size_t length = 0;

    PSA_ASSERT(psa_crypto_init());
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);
    PSA_ASSERT(psa_import_key(&attributes, key_data, sizeof(key_data),
                              &key));

    /* Call encrypt setup twice in a row. */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_cipher_encrypt_setup(&operation, key, alg),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_cipher_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* Call decrypt setup twice in a row. */
    PSA_ASSERT(psa_cipher_decrypt_setup(&operation, key, alg));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_cipher_decrypt_setup(&operation, key, alg),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_cipher_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* Generate an IV without calling setup beforehand. */
    TEST_EQUAL(psa_cipher_generate_iv(&operation,
                                      buffer, sizeof(buffer),
                                      &length),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_cipher_abort(&operation));

    /* Generate an IV twice in a row. */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    PSA_ASSERT(psa_cipher_generate_iv(&operation,
                                      buffer, sizeof(buffer),
                                      &length));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_cipher_generate_iv(&operation,
                                      buffer, sizeof(buffer),
                                      &length),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_cipher_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* Generate an IV after it's already set. */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    PSA_ASSERT(psa_cipher_set_iv(&operation,
                                 iv, sizeof(iv)));
    TEST_EQUAL(psa_cipher_generate_iv(&operation,
                                      buffer, sizeof(buffer),
                                      &length),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_cipher_abort(&operation));

    /* Set an IV without calling setup beforehand. */
    TEST_EQUAL(psa_cipher_set_iv(&operation,
                                 iv, sizeof(iv)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_cipher_abort(&operation));

    /* Set an IV after it's already set. */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    PSA_ASSERT(psa_cipher_set_iv(&operation,
                                 iv, sizeof(iv)));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_cipher_set_iv(&operation,
                                 iv, sizeof(iv)),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_cipher_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* Set an IV after it's already generated. */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    PSA_ASSERT(psa_cipher_generate_iv(&operation,
                                      buffer, sizeof(buffer),
                                      &length));
    TEST_EQUAL(psa_cipher_set_iv(&operation,
                                 iv, sizeof(iv)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_cipher_abort(&operation));

    /* Call update without calling setup beforehand. */
    TEST_EQUAL(psa_cipher_update(&operation,
                                 text, sizeof(text),
                                 buffer, sizeof(buffer),
                                 &length),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_cipher_abort(&operation));

    /* Call update without an IV where an IV is required. */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_cipher_update(&operation,
                                 text, sizeof(text),
                                 buffer, sizeof(buffer),
                                 &length),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_cipher_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* Call update after finish. */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    PSA_ASSERT(psa_cipher_set_iv(&operation,
                                 iv, sizeof(iv)));
    PSA_ASSERT(psa_cipher_finish(&operation,
                                 buffer, sizeof(buffer), &length));
    TEST_EQUAL(psa_cipher_update(&operation,
                                 text, sizeof(text),
                                 buffer, sizeof(buffer),
                                 &length),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_cipher_abort(&operation));

    /* Call finish without calling setup beforehand. */
    TEST_EQUAL(psa_cipher_finish(&operation,
                                 buffer, sizeof(buffer), &length),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_cipher_abort(&operation));

    /* Call finish without an IV where an IV is required. */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    /* Not calling update means we are encrypting an empty buffer, which is OK
     * for cipher modes with padding. */
    ASSERT_OPERATION_IS_ACTIVE(operation);
    TEST_EQUAL(psa_cipher_finish(&operation,
                                 buffer, sizeof(buffer), &length),
               PSA_ERROR_BAD_STATE);
    ASSERT_OPERATION_IS_INACTIVE(operation);
    PSA_ASSERT(psa_cipher_abort(&operation));
    ASSERT_OPERATION_IS_INACTIVE(operation);

    /* Call finish twice in a row. */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    PSA_ASSERT(psa_cipher_set_iv(&operation,
                                 iv, sizeof(iv)));
    PSA_ASSERT(psa_cipher_finish(&operation,
                                 buffer, sizeof(buffer), &length));
    TEST_EQUAL(psa_cipher_finish(&operation,
                                 buffer, sizeof(buffer), &length),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_cipher_abort(&operation));

    PSA_ASSERT(psa_destroy_key(key));

exit:
    psa_cipher_abort(&operation);
    PSA_DONE();
}

void test_cipher_bad_order_wrapper( void ** params )
{
    (void)params;

    test_cipher_bad_order(  );
}
#endif /* PSA_WANT_ALG_CBC_PKCS7 */
#endif /* PSA_WANT_KEY_TYPE_AES */
#line 2586 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_encrypt_fail(int alg_arg,
                         int key_type_arg,
                         data_t *key_data,
                         data_t *input,
                         int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_status = expected_status_arg;
    unsigned char *output = NULL;
    size_t output_buffer_size = 0;
    size_t output_length = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    if (PSA_ERROR_BAD_STATE != expected_status) {
        PSA_ASSERT(psa_crypto_init());

        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_type(&attributes, key_type);

        output_buffer_size = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg,
                                                            input->len);
        ASSERT_ALLOC(output, output_buffer_size);

        PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                                  &key));
    }

    status = psa_cipher_encrypt(key, alg, input->x, input->len, output,
                                output_buffer_size, &output_length);

    TEST_EQUAL(status, expected_status);

exit:
    mbedtls_free(output);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_encrypt_fail_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_cipher_encrypt_fail( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4, *( (int *) params[6] ) );
}
#line 2630 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_alg_without_iv(int alg_arg, int key_type_arg, data_t *key_data,
                           data_t *plaintext, data_t *ciphertext)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    uint8_t iv[1] = { 0x5a };
    unsigned char *output = NULL;
    size_t output_buffer_size = 0;
    size_t output_length, length;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    /* Validate size macros */
    TEST_LE_U(ciphertext->len,
              PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, plaintext->len));
    TEST_LE_U(PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, plaintext->len),
              PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(plaintext->len));
    TEST_LE_U(plaintext->len,
              PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, ciphertext->len));
    TEST_LE_U(PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, ciphertext->len),
              PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE(ciphertext->len));


    /* Set up key and output buffer */
    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);
    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));
    output_buffer_size = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg,
                                                        plaintext->len);
    ASSERT_ALLOC(output, output_buffer_size);

    /* set_iv() is not allowed */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    TEST_EQUAL(psa_cipher_set_iv(&operation, iv, sizeof(iv)),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_cipher_decrypt_setup(&operation, key, alg));
    TEST_EQUAL(psa_cipher_set_iv(&operation, iv, sizeof(iv)),
               PSA_ERROR_BAD_STATE);

    /* generate_iv() is not allowed */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    TEST_EQUAL(psa_cipher_generate_iv(&operation, iv, sizeof(iv),
                                      &length),
               PSA_ERROR_BAD_STATE);
    PSA_ASSERT(psa_cipher_decrypt_setup(&operation, key, alg));
    TEST_EQUAL(psa_cipher_generate_iv(&operation, iv, sizeof(iv),
                                      &length),
               PSA_ERROR_BAD_STATE);

    /* Multipart encryption */
    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    output_length = 0;
    length = ~0;
    PSA_ASSERT(psa_cipher_update(&operation,
                                 plaintext->x, plaintext->len,
                                 output, output_buffer_size,
                                 &length));
    TEST_LE_U(length, output_buffer_size);
    output_length += length;
    PSA_ASSERT(psa_cipher_finish(&operation,
                                 mbedtls_buffer_offset(output, output_length),
                                 output_buffer_size - output_length,
                                 &length));
    output_length += length;
    ASSERT_COMPARE(ciphertext->x, ciphertext->len,
                   output, output_length);

    /* Multipart encryption */
    PSA_ASSERT(psa_cipher_decrypt_setup(&operation, key, alg));
    output_length = 0;
    length = ~0;
    PSA_ASSERT(psa_cipher_update(&operation,
                                 ciphertext->x, ciphertext->len,
                                 output, output_buffer_size,
                                 &length));
    TEST_LE_U(length, output_buffer_size);
    output_length += length;
    PSA_ASSERT(psa_cipher_finish(&operation,
                                 mbedtls_buffer_offset(output, output_length),
                                 output_buffer_size - output_length,
                                 &length));
    output_length += length;
    ASSERT_COMPARE(plaintext->x, plaintext->len,
                   output, output_length);

    /* One-shot encryption */
    output_length = ~0;
    PSA_ASSERT(psa_cipher_encrypt(key, alg, plaintext->x, plaintext->len,
                                  output, output_buffer_size,
                                  &output_length));
    ASSERT_COMPARE(ciphertext->x, ciphertext->len,
                   output, output_length);

    /* One-shot decryption */
    output_length = ~0;
    PSA_ASSERT(psa_cipher_decrypt(key, alg, ciphertext->x, ciphertext->len,
                                  output, output_buffer_size,
                                  &output_length));
    ASSERT_COMPARE(plaintext->x, plaintext->len,
                   output, output_length);

exit:
    mbedtls_free(output);
    psa_cipher_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_alg_without_iv_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_cipher_alg_without_iv( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4, &data6 );
}
#line 2746 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_bad_key(int alg_arg, int key_type_arg, data_t *key_data)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg = alg_arg;
    psa_key_type_t key_type = key_type_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    psa_status_t status;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    /* Usage of either of these two size macros would cause divide by zero
     * with incorrect key types previously. Input length should be irrelevant
     * here. */
    TEST_EQUAL(PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, 16),
               0);
    TEST_EQUAL(PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, 16), 0);


    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    /* Should fail due to invalid alg type (to support invalid key type).
     * Encrypt or decrypt will end up in the same place. */
    status = psa_cipher_encrypt_setup(&operation, key, alg);

    TEST_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);

exit:
    psa_cipher_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_bad_key_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};

    test_cipher_bad_key( *( (int *) params[0] ), *( (int *) params[1] ), &data2 );
}
#line 2786 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_encrypt_validation(int alg_arg,
                               int key_type_arg,
                               data_t *key_data,
                               data_t *input)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t iv_size = PSA_CIPHER_IV_LENGTH(key_type, alg);
    unsigned char *output1 = NULL;
    size_t output1_buffer_size = 0;
    size_t output1_length = 0;
    unsigned char *output2 = NULL;
    size_t output2_buffer_size = 0;
    size_t output2_length = 0;
    size_t function_output_length = 0;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    output1_buffer_size = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, input->len);
    output2_buffer_size = PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, input->len) +
                          PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg);
    ASSERT_ALLOC(output1, output1_buffer_size);
    ASSERT_ALLOC(output2, output2_buffer_size);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    /* The one-shot cipher encryption uses generated iv so validating
       the output is not possible. Validating with multipart encryption. */
    PSA_ASSERT(psa_cipher_encrypt(key, alg, input->x, input->len, output1,
                                  output1_buffer_size, &output1_length));
    TEST_LE_U(output1_length,
              PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, input->len));
    TEST_LE_U(output1_length,
              PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input->len));

    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));
    PSA_ASSERT(psa_cipher_set_iv(&operation, output1, iv_size));

    PSA_ASSERT(psa_cipher_update(&operation,
                                 input->x, input->len,
                                 output2, output2_buffer_size,
                                 &function_output_length));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, input->len));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(input->len));
    output2_length += function_output_length;

    PSA_ASSERT(psa_cipher_finish(&operation,
                                 output2 + output2_length,
                                 output2_buffer_size - output2_length,
                                 &function_output_length));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE);
    output2_length += function_output_length;

    PSA_ASSERT(psa_cipher_abort(&operation));
    ASSERT_COMPARE(output1 + iv_size, output1_length - iv_size,
                   output2, output2_length);

exit:
    psa_cipher_abort(&operation);
    mbedtls_free(output1);
    mbedtls_free(output2);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_encrypt_validation_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_cipher_encrypt_validation( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4 );
}
#line 2866 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_encrypt_multipart(int alg_arg, int key_type_arg,
                              data_t *key_data, data_t *iv,
                              data_t *input,
                              int first_part_size_arg,
                              int output1_length_arg, int output2_length_arg,
                              data_t *expected_output,
                              int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t status;
    psa_status_t expected_status = expected_status_arg;
    size_t first_part_size = first_part_size_arg;
    size_t output1_length = output1_length_arg;
    size_t output2_length = output2_length_arg;
    unsigned char *output = NULL;
    size_t output_buffer_size = 0;
    size_t function_output_length = 0;
    size_t total_output_length = 0;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    PSA_ASSERT(psa_cipher_encrypt_setup(&operation, key, alg));

    if (iv->len > 0) {
        PSA_ASSERT(psa_cipher_set_iv(&operation, iv->x, iv->len));
    }

    output_buffer_size = PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, input->len) +
                         PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg);
    ASSERT_ALLOC(output, output_buffer_size);

    TEST_LE_U(first_part_size, input->len);
    PSA_ASSERT(psa_cipher_update(&operation, input->x, first_part_size,
                                 output, output_buffer_size,
                                 &function_output_length));
    TEST_ASSERT(function_output_length == output1_length);
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, first_part_size));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(first_part_size));
    total_output_length += function_output_length;

    if (first_part_size < input->len) {
        PSA_ASSERT(psa_cipher_update(&operation,
                                     input->x + first_part_size,
                                     input->len - first_part_size,
                                     (output_buffer_size == 0 ? NULL :
                                      output + total_output_length),
                                     output_buffer_size - total_output_length,
                                     &function_output_length));
        TEST_ASSERT(function_output_length == output2_length);
        TEST_LE_U(function_output_length,
                  PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type,
                                                alg,
                                                input->len - first_part_size));
        TEST_LE_U(function_output_length,
                  PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(input->len));
        total_output_length += function_output_length;
    }

    status = psa_cipher_finish(&operation,
                               (output_buffer_size == 0 ? NULL :
                                output + total_output_length),
                               output_buffer_size - total_output_length,
                               &function_output_length);
    TEST_LE_U(function_output_length,
              PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE);
    total_output_length += function_output_length;
    TEST_EQUAL(status, expected_status);

    if (expected_status == PSA_SUCCESS) {
        PSA_ASSERT(psa_cipher_abort(&operation));

        ASSERT_COMPARE(expected_output->x, expected_output->len,
                       output, total_output_length);
    }

exit:
    psa_cipher_abort(&operation);
    mbedtls_free(output);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_encrypt_multipart_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data11 = {(uint8_t *) params[11], *( (uint32_t *) params[12] )};

    test_cipher_encrypt_multipart( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4, &data6, *( (int *) params[8] ), *( (int *) params[9] ), *( (int *) params[10] ), &data11, *( (int *) params[13] ) );
}
#line 2965 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_decrypt_multipart(int alg_arg, int key_type_arg,
                              data_t *key_data, data_t *iv,
                              data_t *input,
                              int first_part_size_arg,
                              int output1_length_arg, int output2_length_arg,
                              data_t *expected_output,
                              int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t status;
    psa_status_t expected_status = expected_status_arg;
    size_t first_part_size = first_part_size_arg;
    size_t output1_length = output1_length_arg;
    size_t output2_length = output2_length_arg;
    unsigned char *output = NULL;
    size_t output_buffer_size = 0;
    size_t function_output_length = 0;
    size_t total_output_length = 0;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    PSA_ASSERT(psa_cipher_decrypt_setup(&operation, key, alg));

    if (iv->len > 0) {
        PSA_ASSERT(psa_cipher_set_iv(&operation, iv->x, iv->len));
    }

    output_buffer_size = PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, input->len) +
                         PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg);
    ASSERT_ALLOC(output, output_buffer_size);

    TEST_LE_U(first_part_size, input->len);
    PSA_ASSERT(psa_cipher_update(&operation,
                                 input->x, first_part_size,
                                 output, output_buffer_size,
                                 &function_output_length));
    TEST_ASSERT(function_output_length == output1_length);
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, first_part_size));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(first_part_size));
    total_output_length += function_output_length;

    if (first_part_size < input->len) {
        PSA_ASSERT(psa_cipher_update(&operation,
                                     input->x + first_part_size,
                                     input->len - first_part_size,
                                     (output_buffer_size == 0 ? NULL :
                                      output + total_output_length),
                                     output_buffer_size - total_output_length,
                                     &function_output_length));
        TEST_ASSERT(function_output_length == output2_length);
        TEST_LE_U(function_output_length,
                  PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type,
                                                alg,
                                                input->len - first_part_size));
        TEST_LE_U(function_output_length,
                  PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(input->len));
        total_output_length += function_output_length;
    }

    status = psa_cipher_finish(&operation,
                               (output_buffer_size == 0 ? NULL :
                                output + total_output_length),
                               output_buffer_size - total_output_length,
                               &function_output_length);
    TEST_LE_U(function_output_length,
              PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE);
    total_output_length += function_output_length;
    TEST_EQUAL(status, expected_status);

    if (expected_status == PSA_SUCCESS) {
        PSA_ASSERT(psa_cipher_abort(&operation));

        ASSERT_COMPARE(expected_output->x, expected_output->len,
                       output, total_output_length);
    }

exit:
    psa_cipher_abort(&operation);
    mbedtls_free(output);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_decrypt_multipart_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data11 = {(uint8_t *) params[11], *( (uint32_t *) params[12] )};

    test_cipher_decrypt_multipart( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4, &data6, *( (int *) params[8] ), *( (int *) params[9] ), *( (int *) params[10] ), &data11, *( (int *) params[13] ) );
}
#line 3065 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_decrypt_fail(int alg_arg,
                         int key_type_arg,
                         data_t *key_data,
                         data_t *iv,
                         data_t *input_arg,
                         int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_status = expected_status_arg;
    unsigned char *input = NULL;
    size_t input_buffer_size = 0;
    unsigned char *output = NULL;
    size_t output_buffer_size = 0;
    size_t output_length = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    if (PSA_ERROR_BAD_STATE != expected_status) {
        PSA_ASSERT(psa_crypto_init());

        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_type(&attributes, key_type);

        PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                                  &key));
    }

    /* Allocate input buffer and copy the iv and the plaintext */
    input_buffer_size = ((size_t) input_arg->len + (size_t) iv->len);
    if (input_buffer_size > 0) {
        ASSERT_ALLOC(input, input_buffer_size);
        memcpy(input, iv->x, iv->len);
        memcpy(input + iv->len, input_arg->x, input_arg->len);
    }

    output_buffer_size = PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_buffer_size);
    ASSERT_ALLOC(output, output_buffer_size);

    status = psa_cipher_decrypt(key, alg, input, input_buffer_size, output,
                                output_buffer_size, &output_length);
    TEST_EQUAL(status, expected_status);

exit:
    mbedtls_free(input);
    mbedtls_free(output);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_decrypt_fail_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_cipher_decrypt_fail( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4, &data6, *( (int *) params[8] ) );
}
#line 3119 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_decrypt(int alg_arg,
                    int key_type_arg,
                    data_t *key_data,
                    data_t *iv,
                    data_t *input_arg,
                    data_t *expected_output)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    unsigned char *input = NULL;
    size_t input_buffer_size = 0;
    unsigned char *output = NULL;
    size_t output_buffer_size = 0;
    size_t output_length = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    /* Allocate input buffer and copy the iv and the plaintext */
    input_buffer_size = ((size_t) input_arg->len + (size_t) iv->len);
    if (input_buffer_size > 0) {
        ASSERT_ALLOC(input, input_buffer_size);
        memcpy(input, iv->x, iv->len);
        memcpy(input + iv->len, input_arg->x, input_arg->len);
    }

    output_buffer_size = PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_buffer_size);
    ASSERT_ALLOC(output, output_buffer_size);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    PSA_ASSERT(psa_cipher_decrypt(key, alg, input, input_buffer_size, output,
                                  output_buffer_size, &output_length));
    TEST_LE_U(output_length,
              PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_buffer_size));
    TEST_LE_U(output_length,
              PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE(input_buffer_size));

    ASSERT_COMPARE(expected_output->x, expected_output->len,
                   output, output_length);
exit:
    mbedtls_free(input);
    mbedtls_free(output);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_decrypt_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};

    test_cipher_decrypt( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4, &data6, &data8 );
}
#line 3174 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_verify_output(int alg_arg,
                          int key_type_arg,
                          data_t *key_data,
                          data_t *input)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    unsigned char *output1 = NULL;
    size_t output1_size = 0;
    size_t output1_length = 0;
    unsigned char *output2 = NULL;
    size_t output2_size = 0;
    size_t output2_length = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));
    output1_size = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, input->len);
    ASSERT_ALLOC(output1, output1_size);

    PSA_ASSERT(psa_cipher_encrypt(key, alg, input->x, input->len,
                                  output1, output1_size,
                                  &output1_length));
    TEST_LE_U(output1_length,
              PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, input->len));
    TEST_LE_U(output1_length,
              PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input->len));

    output2_size = output1_length;
    ASSERT_ALLOC(output2, output2_size);

    PSA_ASSERT(psa_cipher_decrypt(key, alg, output1, output1_length,
                                  output2, output2_size,
                                  &output2_length));
    TEST_LE_U(output2_length,
              PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, output1_length));
    TEST_LE_U(output2_length,
              PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE(output1_length));

    ASSERT_COMPARE(input->x, input->len, output2, output2_length);

exit:
    mbedtls_free(output1);
    mbedtls_free(output2);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_verify_output_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_cipher_verify_output( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4 );
}
#line 3231 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_cipher_verify_output_multipart(int alg_arg,
                                    int key_type_arg,
                                    data_t *key_data,
                                    data_t *input,
                                    int first_part_size_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t first_part_size = first_part_size_arg;
    unsigned char iv[16] = { 0 };
    size_t iv_size = 16;
    size_t iv_length = 0;
    unsigned char *output1 = NULL;
    size_t output1_buffer_size = 0;
    size_t output1_length = 0;
    unsigned char *output2 = NULL;
    size_t output2_buffer_size = 0;
    size_t output2_length = 0;
    size_t function_output_length;
    psa_cipher_operation_t operation1 = PSA_CIPHER_OPERATION_INIT;
    psa_cipher_operation_t operation2 = PSA_CIPHER_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    PSA_ASSERT(psa_cipher_encrypt_setup(&operation1, key, alg));
    PSA_ASSERT(psa_cipher_decrypt_setup(&operation2, key, alg));

    if (alg != PSA_ALG_ECB_NO_PADDING) {
        PSA_ASSERT(psa_cipher_generate_iv(&operation1,
                                          iv, iv_size,
                                          &iv_length));
    }

    output1_buffer_size = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, input->len);
    TEST_LE_U(output1_buffer_size,
              PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input->len));
    ASSERT_ALLOC(output1, output1_buffer_size);

    TEST_LE_U(first_part_size, input->len);

    PSA_ASSERT(psa_cipher_update(&operation1, input->x, first_part_size,
                                 output1, output1_buffer_size,
                                 &function_output_length));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, first_part_size));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(first_part_size));
    output1_length += function_output_length;

    PSA_ASSERT(psa_cipher_update(&operation1,
                                 input->x + first_part_size,
                                 input->len - first_part_size,
                                 output1, output1_buffer_size,
                                 &function_output_length));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type,
                                            alg,
                                            input->len - first_part_size));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(input->len - first_part_size));
    output1_length += function_output_length;

    PSA_ASSERT(psa_cipher_finish(&operation1,
                                 output1 + output1_length,
                                 output1_buffer_size - output1_length,
                                 &function_output_length));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE);
    output1_length += function_output_length;

    PSA_ASSERT(psa_cipher_abort(&operation1));

    output2_buffer_size = output1_length;
    TEST_LE_U(output2_buffer_size,
              PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, output1_length));
    TEST_LE_U(output2_buffer_size,
              PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE(output1_length));
    ASSERT_ALLOC(output2, output2_buffer_size);

    if (iv_length > 0) {
        PSA_ASSERT(psa_cipher_set_iv(&operation2,
                                     iv, iv_length));
    }

    PSA_ASSERT(psa_cipher_update(&operation2, output1, first_part_size,
                                 output2, output2_buffer_size,
                                 &function_output_length));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, first_part_size));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(first_part_size));
    output2_length += function_output_length;

    PSA_ASSERT(psa_cipher_update(&operation2,
                                 output1 + first_part_size,
                                 output1_length - first_part_size,
                                 output2, output2_buffer_size,
                                 &function_output_length));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type,
                                            alg,
                                            output1_length - first_part_size));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(output1_length - first_part_size));
    output2_length += function_output_length;

    PSA_ASSERT(psa_cipher_finish(&operation2,
                                 output2 + output2_length,
                                 output2_buffer_size - output2_length,
                                 &function_output_length));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg));
    TEST_LE_U(function_output_length,
              PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE);
    output2_length += function_output_length;

    PSA_ASSERT(psa_cipher_abort(&operation2));

    ASSERT_COMPARE(input->x, input->len, output2, output2_length);

exit:
    psa_cipher_abort(&operation1);
    psa_cipher_abort(&operation2);
    mbedtls_free(output1);
    mbedtls_free(output2);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_cipher_verify_output_multipart_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_cipher_verify_output_multipart( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4, *( (int *) params[6] ) );
}
#line 3373 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_aead_encrypt_decrypt(int key_type_arg, data_t *key_data,
                          int alg_arg,
                          data_t *nonce,
                          data_t *additional_data,
                          data_t *input_data,
                          int expected_result_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t key_bits;
    unsigned char *output_data = NULL;
    size_t output_size = 0;
    size_t output_length = 0;
    unsigned char *output_data2 = NULL;
    size_t output_length2 = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_status_t expected_result = expected_result_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    output_size = input_data->len + PSA_AEAD_TAG_LENGTH(key_type, key_bits,
                                                        alg);
    /* For all currently defined algorithms, PSA_AEAD_ENCRYPT_OUTPUT_SIZE
     * should be exact. */
    if (expected_result != PSA_ERROR_INVALID_ARGUMENT &&
        expected_result != PSA_ERROR_NOT_SUPPORTED) {
        TEST_EQUAL(output_size,
                   PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg, input_data->len));
        TEST_ASSERT(output_size <=
                    PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(input_data->len));
    }
    ASSERT_ALLOC(output_data, output_size);

    status = psa_aead_encrypt(key, alg,
                              nonce->x, nonce->len,
                              additional_data->x,
                              additional_data->len,
                              input_data->x, input_data->len,
                              output_data, output_size,
                              &output_length);

    /* If the operation is not supported, just skip and not fail in case the
     * encryption involves a common limitation of cryptography hardwares and
     * an alternative implementation. */
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        MBEDTLS_TEST_PSA_SKIP_IF_ALT_AES_192(key_type, key_data->len * 8);
        MBEDTLS_TEST_PSA_SKIP_IF_ALT_GCM_NOT_12BYTES_NONCE(alg, nonce->len);
    }

    TEST_EQUAL(status, expected_result);

    if (PSA_SUCCESS == expected_result) {
        ASSERT_ALLOC(output_data2, output_length);

        /* For all currently defined algorithms, PSA_AEAD_DECRYPT_OUTPUT_SIZE
         * should be exact. */
        TEST_EQUAL(input_data->len,
                   PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg, output_length));

        TEST_ASSERT(input_data->len <=
                    PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(output_length));

        TEST_EQUAL(psa_aead_decrypt(key, alg,
                                    nonce->x, nonce->len,
                                    additional_data->x,
                                    additional_data->len,
                                    output_data, output_length,
                                    output_data2, output_length,
                                    &output_length2),
                   expected_result);

        ASSERT_COMPARE(input_data->x, input_data->len,
                       output_data2, output_length2);
    }

exit:
    psa_destroy_key(key);
    mbedtls_free(output_data);
    mbedtls_free(output_data2);
    PSA_DONE();
}

void test_aead_encrypt_decrypt_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};

    test_aead_encrypt_decrypt( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6, &data8, *( (int *) params[10] ) );
}
#line 3468 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_aead_encrypt(int key_type_arg, data_t *key_data,
                  int alg_arg,
                  data_t *nonce,
                  data_t *additional_data,
                  data_t *input_data,
                  data_t *expected_result)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t key_bits;
    unsigned char *output_data = NULL;
    size_t output_size = 0;
    size_t output_length = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    output_size = input_data->len + PSA_AEAD_TAG_LENGTH(key_type, key_bits,
                                                        alg);
    /* For all currently defined algorithms, PSA_AEAD_ENCRYPT_OUTPUT_SIZE
     * should be exact. */
    TEST_EQUAL(output_size,
               PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg, input_data->len));
    TEST_ASSERT(output_size <=
                PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(input_data->len));
    ASSERT_ALLOC(output_data, output_size);

    status = psa_aead_encrypt(key, alg,
                              nonce->x, nonce->len,
                              additional_data->x, additional_data->len,
                              input_data->x, input_data->len,
                              output_data, output_size,
                              &output_length);

    /* If the operation is not supported, just skip and not fail in case the
     * encryption involves a common limitation of cryptography hardwares and
     * an alternative implementation. */
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        MBEDTLS_TEST_PSA_SKIP_IF_ALT_AES_192(key_type, key_data->len * 8);
        MBEDTLS_TEST_PSA_SKIP_IF_ALT_GCM_NOT_12BYTES_NONCE(alg, nonce->len);
    }

    PSA_ASSERT(status);
    ASSERT_COMPARE(expected_result->x, expected_result->len,
                   output_data, output_length);

exit:
    psa_destroy_key(key);
    mbedtls_free(output_data);
    PSA_DONE();
}

void test_aead_encrypt_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};
    data_t data10 = {(uint8_t *) params[10], *( (uint32_t *) params[11] )};

    test_aead_encrypt( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6, &data8, &data10 );
}
#line 3533 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_aead_decrypt(int key_type_arg, data_t *key_data,
                  int alg_arg,
                  data_t *nonce,
                  data_t *additional_data,
                  data_t *input_data,
                  data_t *expected_data,
                  int expected_result_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t key_bits;
    unsigned char *output_data = NULL;
    size_t output_size = 0;
    size_t output_length = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t expected_result = expected_result_arg;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    output_size = input_data->len - PSA_AEAD_TAG_LENGTH(key_type, key_bits,
                                                        alg);
    if (expected_result != PSA_ERROR_INVALID_ARGUMENT &&
        expected_result != PSA_ERROR_NOT_SUPPORTED) {
        /* For all currently defined algorithms, PSA_AEAD_DECRYPT_OUTPUT_SIZE
         * should be exact. */
        TEST_EQUAL(output_size,
                   PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg, input_data->len));
        TEST_ASSERT(output_size <=
                    PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(input_data->len));
    }
    ASSERT_ALLOC(output_data, output_size);

    status = psa_aead_decrypt(key, alg,
                              nonce->x, nonce->len,
                              additional_data->x,
                              additional_data->len,
                              input_data->x, input_data->len,
                              output_data, output_size,
                              &output_length);

    /* If the operation is not supported, just skip and not fail in case the
     * decryption involves a common limitation of cryptography hardwares and
     * an alternative implementation. */
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        MBEDTLS_TEST_PSA_SKIP_IF_ALT_AES_192(key_type, key_data->len * 8);
        MBEDTLS_TEST_PSA_SKIP_IF_ALT_GCM_NOT_12BYTES_NONCE(alg, nonce->len);
    }

    TEST_EQUAL(status, expected_result);

    if (expected_result == PSA_SUCCESS) {
        ASSERT_COMPARE(expected_data->x, expected_data->len,
                       output_data, output_length);
    }

exit:
    psa_destroy_key(key);
    mbedtls_free(output_data);
    PSA_DONE();
}

void test_aead_decrypt_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};
    data_t data10 = {(uint8_t *) params[10], *( (uint32_t *) params[11] )};

    test_aead_decrypt( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6, &data8, &data10, *( (int *) params[12] ) );
}
#line 3607 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_signature_size(int type_arg,
                    int bits,
                    int alg_arg,
                    int expected_size_arg)
{
    psa_key_type_t type = type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t actual_size = PSA_SIGN_OUTPUT_SIZE(type, bits, alg);

    TEST_EQUAL(actual_size, (size_t) expected_size_arg);
#if defined(MBEDTLS_TEST_DEPRECATED)
    TEST_EQUAL(actual_size,
               PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(type, bits, alg));
#endif /* MBEDTLS_TEST_DEPRECATED */

exit:
    ;
}

void test_signature_size_wrapper( void ** params )
{

    test_signature_size( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ) );
}
#line 3628 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_sign_hash_deterministic(int key_type_arg, data_t *key_data,
                             int alg_arg, data_t *input_data,
                             data_t *output_data)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t key_bits;
    unsigned char *signature = NULL;
    size_t signature_size;
    size_t signature_length = 0xdeadbeef;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    /* Allocate a buffer which has the size advertised by the
     * library. */
    signature_size = PSA_SIGN_OUTPUT_SIZE(key_type,
                                          key_bits, alg);
    TEST_ASSERT(signature_size != 0);
    TEST_LE_U(signature_size, PSA_SIGNATURE_MAX_SIZE);
    ASSERT_ALLOC(signature, signature_size);

    /* Perform the signature. */
    PSA_ASSERT(psa_sign_hash(key, alg,
                             input_data->x, input_data->len,
                             signature, signature_size,
                             &signature_length));
    /* Verify that the signature is what is expected. */
    ASSERT_COMPARE(output_data->x, output_data->len,
                   signature, signature_length);

#if defined(MBEDTLS_TEST_DEPRECATED)
    memset(signature, 0, signature_size);
    signature_length = INVALID_EXPORT_LENGTH;
    PSA_ASSERT(psa_asymmetric_sign(key, alg,
                                   input_data->x, input_data->len,
                                   signature, signature_size,
                                   &signature_length));
    ASSERT_COMPARE(output_data->x, output_data->len,
                   signature, signature_length);
#endif /* MBEDTLS_TEST_DEPRECATED */

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    psa_destroy_key(key);
    mbedtls_free(signature);
    PSA_DONE();
}

void test_sign_hash_deterministic_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_sign_hash_deterministic( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6 );
}
#line 3694 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_sign_hash_fail(int key_type_arg, data_t *key_data,
                    int alg_arg, data_t *input_data,
                    int signature_size_arg, int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t signature_size = signature_size_arg;
    psa_status_t actual_status;
    psa_status_t expected_status = expected_status_arg;
    unsigned char *signature = NULL;
    size_t signature_length = 0xdeadbeef;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    ASSERT_ALLOC(signature, signature_size);

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    actual_status = psa_sign_hash(key, alg,
                                  input_data->x, input_data->len,
                                  signature, signature_size,
                                  &signature_length);
    TEST_EQUAL(actual_status, expected_status);
    /* The value of *signature_length is unspecified on error, but
     * whatever it is, it should be less than signature_size, so that
     * if the caller tries to read *signature_length bytes without
     * checking the error code then they don't overflow a buffer. */
    TEST_LE_U(signature_length, signature_size);

#if defined(MBEDTLS_TEST_DEPRECATED)
    signature_length = INVALID_EXPORT_LENGTH;
    TEST_EQUAL(psa_asymmetric_sign(key, alg,
                                   input_data->x, input_data->len,
                                   signature, signature_size,
                                   &signature_length),
               expected_status);
    TEST_LE_U(signature_length, signature_size);
#endif /* MBEDTLS_TEST_DEPRECATED */

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key);
    mbedtls_free(signature);
    PSA_DONE();
}

void test_sign_hash_fail_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_sign_hash_fail( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, *( (int *) params[6] ), *( (int *) params[7] ) );
}
#line 3749 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_sign_verify_hash(int key_type_arg, data_t *key_data,
                      int alg_arg, data_t *input_data)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t key_bits;
    unsigned char *signature = NULL;
    size_t signature_size;
    size_t signature_length = 0xdeadbeef;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    /* Allocate a buffer which has the size advertised by the
     * library. */
    signature_size = PSA_SIGN_OUTPUT_SIZE(key_type,
                                          key_bits, alg);
    TEST_ASSERT(signature_size != 0);
    TEST_LE_U(signature_size, PSA_SIGNATURE_MAX_SIZE);
    ASSERT_ALLOC(signature, signature_size);

    /* Perform the signature. */
    PSA_ASSERT(psa_sign_hash(key, alg,
                             input_data->x, input_data->len,
                             signature, signature_size,
                             &signature_length));
    /* Check that the signature length looks sensible. */
    TEST_LE_U(signature_length, signature_size);
    TEST_ASSERT(signature_length > 0);

    /* Use the library to verify that the signature is correct. */
    PSA_ASSERT(psa_verify_hash(key, alg,
                               input_data->x, input_data->len,
                               signature, signature_length));

    if (input_data->len != 0) {
        /* Flip a bit in the input and verify that the signature is now
         * detected as invalid. Flip a bit at the beginning, not at the end,
         * because ECDSA may ignore the last few bits of the input. */
        input_data->x[0] ^= 1;
        TEST_EQUAL(psa_verify_hash(key, alg,
                                   input_data->x, input_data->len,
                                   signature, signature_length),
                   PSA_ERROR_INVALID_SIGNATURE);
    }

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    psa_destroy_key(key);
    mbedtls_free(signature);
    PSA_DONE();
}

void test_sign_verify_hash_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_sign_verify_hash( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4 );
}
#line 3819 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_verify_hash(int key_type_arg, data_t *key_data,
                 int alg_arg, data_t *hash_data,
                 data_t *signature_data)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    TEST_LE_U(signature_data->len, PSA_SIGNATURE_MAX_SIZE);

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    PSA_ASSERT(psa_verify_hash(key, alg,
                               hash_data->x, hash_data->len,
                               signature_data->x, signature_data->len));

#if defined(MBEDTLS_TEST_DEPRECATED)
    PSA_ASSERT(psa_asymmetric_verify(key, alg,
                                     hash_data->x, hash_data->len,
                                     signature_data->x,
                                     signature_data->len));

#endif /* MBEDTLS_TEST_DEPRECATED */

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_verify_hash_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_verify_hash( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6 );
}
#line 3859 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_verify_hash_fail(int key_type_arg, data_t *key_data,
                      int alg_arg, data_t *hash_data,
                      data_t *signature_data,
                      int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t actual_status;
    psa_status_t expected_status = expected_status_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    actual_status = psa_verify_hash(key, alg,
                                    hash_data->x, hash_data->len,
                                    signature_data->x, signature_data->len);
    TEST_EQUAL(actual_status, expected_status);

#if defined(MBEDTLS_TEST_DEPRECATED)
    TEST_EQUAL(psa_asymmetric_verify(key, alg,
                                     hash_data->x, hash_data->len,
                                     signature_data->x, signature_data->len),
               expected_status);
#endif /* MBEDTLS_TEST_DEPRECATED */

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_verify_hash_fail_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_verify_hash_fail( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6, *( (int *) params[8] ) );
}
#line 3900 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_sign_message_deterministic(int key_type_arg,
                                data_t *key_data,
                                int alg_arg,
                                data_t *input_data,
                                data_t *output_data)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t key_bits;
    unsigned char *signature = NULL;
    size_t signature_size;
    size_t signature_length = 0xdeadbeef;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    signature_size = PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg);
    TEST_ASSERT(signature_size != 0);
    TEST_LE_U(signature_size, PSA_SIGNATURE_MAX_SIZE);
    ASSERT_ALLOC(signature, signature_size);

    PSA_ASSERT(psa_sign_message(key, alg,
                                input_data->x, input_data->len,
                                signature, signature_size,
                                &signature_length));

    ASSERT_COMPARE(output_data->x, output_data->len,
                   signature, signature_length);

exit:
    psa_reset_key_attributes(&attributes);

    psa_destroy_key(key);
    mbedtls_free(signature);
    PSA_DONE();

}

void test_sign_message_deterministic_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_sign_message_deterministic( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6 );
}
#line 3950 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_sign_message_fail(int key_type_arg,
                       data_t *key_data,
                       int alg_arg,
                       data_t *input_data,
                       int signature_size_arg,
                       int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t signature_size = signature_size_arg;
    psa_status_t actual_status;
    psa_status_t expected_status = expected_status_arg;
    unsigned char *signature = NULL;
    size_t signature_length = 0xdeadbeef;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    ASSERT_ALLOC(signature, signature_size);

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    actual_status = psa_sign_message(key, alg,
                                     input_data->x, input_data->len,
                                     signature, signature_size,
                                     &signature_length);
    TEST_EQUAL(actual_status, expected_status);
    /* The value of *signature_length is unspecified on error, but
     * whatever it is, it should be less than signature_size, so that
     * if the caller tries to read *signature_length bytes without
     * checking the error code then they don't overflow a buffer. */
    TEST_LE_U(signature_length, signature_size);

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key);
    mbedtls_free(signature);
    PSA_DONE();
}

void test_sign_message_fail_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_sign_message_fail( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, *( (int *) params[6] ), *( (int *) params[7] ) );
}
#line 3998 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_sign_verify_message(int key_type_arg,
                         data_t *key_data,
                         int alg_arg,
                         data_t *input_data)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t key_bits;
    unsigned char *signature = NULL;
    size_t signature_size;
    size_t signature_length = 0xdeadbeef;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    signature_size = PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg);
    TEST_ASSERT(signature_size != 0);
    TEST_LE_U(signature_size, PSA_SIGNATURE_MAX_SIZE);
    ASSERT_ALLOC(signature, signature_size);

    PSA_ASSERT(psa_sign_message(key, alg,
                                input_data->x, input_data->len,
                                signature, signature_size,
                                &signature_length));
    TEST_LE_U(signature_length, signature_size);
    TEST_ASSERT(signature_length > 0);

    PSA_ASSERT(psa_verify_message(key, alg,
                                  input_data->x, input_data->len,
                                  signature, signature_length));

    if (input_data->len != 0) {
        /* Flip a bit in the input and verify that the signature is now
         * detected as invalid. Flip a bit at the beginning, not at the end,
         * because ECDSA may ignore the last few bits of the input. */
        input_data->x[0] ^= 1;
        TEST_EQUAL(psa_verify_message(key, alg,
                                      input_data->x, input_data->len,
                                      signature, signature_length),
                   PSA_ERROR_INVALID_SIGNATURE);
    }

exit:
    psa_reset_key_attributes(&attributes);

    psa_destroy_key(key);
    mbedtls_free(signature);
    PSA_DONE();
}

void test_sign_verify_message_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_sign_verify_message( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4 );
}
#line 4061 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_verify_message(int key_type_arg,
                    data_t *key_data,
                    int alg_arg,
                    data_t *input_data,
                    data_t *signature_data)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    TEST_LE_U(signature_data->len, PSA_SIGNATURE_MAX_SIZE);

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    PSA_ASSERT(psa_verify_message(key, alg,
                                  input_data->x, input_data->len,
                                  signature_data->x, signature_data->len));

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_verify_message_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_verify_message( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6 );
}
#line 4095 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_verify_message_fail(int key_type_arg,
                         data_t *key_data,
                         int alg_arg,
                         data_t *hash_data,
                         data_t *signature_data,
                         int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t actual_status;
    psa_status_t expected_status = expected_status_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    actual_status = psa_verify_message(key, alg,
                                       hash_data->x, hash_data->len,
                                       signature_data->x,
                                       signature_data->len);
    TEST_EQUAL(actual_status, expected_status);

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_verify_message_fail_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_verify_message_fail( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6, *( (int *) params[8] ) );
}
#line 4132 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_asymmetric_encrypt(int key_type_arg,
                        data_t *key_data,
                        int alg_arg,
                        data_t *input_data,
                        data_t *label,
                        int expected_output_length_arg,
                        int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t expected_output_length = expected_output_length_arg;
    size_t key_bits;
    unsigned char *output = NULL;
    size_t output_size;
    size_t output_length = ~0;
    psa_status_t actual_status;
    psa_status_t expected_status = expected_status_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    /* Import the key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);
    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    /* Determine the maximum output length */
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    output_size = PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg);
    TEST_LE_U(output_size, PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE);
    ASSERT_ALLOC(output, output_size);

    /* Encrypt the input */
    actual_status = psa_asymmetric_encrypt(key, alg,
                                           input_data->x, input_data->len,
                                           label->x, label->len,
                                           output, output_size,
                                           &output_length);
    TEST_EQUAL(actual_status, expected_status);
    if (actual_status == PSA_SUCCESS) {
        TEST_EQUAL(output_length, expected_output_length);
    } else {
        TEST_LE_U(output_length, output_size);
    }

    /* If the label is empty, the test framework puts a non-null pointer
     * in label->x. Test that a null pointer works as well. */
    if (label->len == 0) {
        output_length = ~0;
        if (output_size != 0) {
            memset(output, 0, output_size);
        }
        actual_status = psa_asymmetric_encrypt(key, alg,
                                               input_data->x, input_data->len,
                                               NULL, label->len,
                                               output, output_size,
                                               &output_length);
        TEST_EQUAL(actual_status, expected_status);
        if (actual_status == PSA_SUCCESS) {
            TEST_EQUAL(output_length, expected_output_length);
        } else {
            TEST_LE_U(output_length, output_size);
        }
    }

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    psa_destroy_key(key);
    mbedtls_free(output);
    PSA_DONE();
}

void test_asymmetric_encrypt_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_asymmetric_encrypt( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6, *( (int *) params[8] ), *( (int *) params[9] ) );
}
#line 4216 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_asymmetric_encrypt_decrypt(int key_type_arg,
                                data_t *key_data,
                                int alg_arg,
                                data_t *input_data,
                                data_t *label)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t key_bits;
    unsigned char *output = NULL;
    size_t output_size;
    size_t output_length = ~0;
    unsigned char *output2 = NULL;
    size_t output2_size;
    size_t output2_length = ~0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    /* Determine the maximum ciphertext length */
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    output_size = PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg);
    TEST_LE_U(output_size, PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE);
    ASSERT_ALLOC(output, output_size);

    output2_size = input_data->len;
    TEST_LE_U(output2_size,
              PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg));
    TEST_LE_U(output2_size, PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE);
    ASSERT_ALLOC(output2, output2_size);

    /* We test encryption by checking that encrypt-then-decrypt gives back
     * the original plaintext because of the non-optional random
     * part of encryption process which prevents using fixed vectors. */
    PSA_ASSERT(psa_asymmetric_encrypt(key, alg,
                                      input_data->x, input_data->len,
                                      label->x, label->len,
                                      output, output_size,
                                      &output_length));
    /* We don't know what ciphertext length to expect, but check that
     * it looks sensible. */
    TEST_LE_U(output_length, output_size);

    PSA_ASSERT(psa_asymmetric_decrypt(key, alg,
                                      output, output_length,
                                      label->x, label->len,
                                      output2, output2_size,
                                      &output2_length));
    ASSERT_COMPARE(input_data->x, input_data->len,
                   output2, output2_length);

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    psa_destroy_key(key);
    mbedtls_free(output);
    mbedtls_free(output2);
    PSA_DONE();
}

void test_asymmetric_encrypt_decrypt_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_asymmetric_encrypt_decrypt( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6 );
}
#line 4292 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_asymmetric_decrypt(int key_type_arg,
                        data_t *key_data,
                        int alg_arg,
                        data_t *input_data,
                        data_t *label,
                        data_t *expected_data)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    size_t key_bits;
    unsigned char *output = NULL;
    size_t output_size = 0;
    size_t output_length = ~0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    /* Determine the maximum ciphertext length */
    output_size = PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg);
    TEST_LE_U(output_size, PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE);
    ASSERT_ALLOC(output, output_size);

    PSA_ASSERT(psa_asymmetric_decrypt(key, alg,
                                      input_data->x, input_data->len,
                                      label->x, label->len,
                                      output,
                                      output_size,
                                      &output_length));
    ASSERT_COMPARE(expected_data->x, expected_data->len,
                   output, output_length);

    /* If the label is empty, the test framework puts a non-null pointer
     * in label->x. Test that a null pointer works as well. */
    if (label->len == 0) {
        output_length = ~0;
        if (output_size != 0) {
            memset(output, 0, output_size);
        }
        PSA_ASSERT(psa_asymmetric_decrypt(key, alg,
                                          input_data->x, input_data->len,
                                          NULL, label->len,
                                          output,
                                          output_size,
                                          &output_length));
        ASSERT_COMPARE(expected_data->x, expected_data->len,
                       output, output_length);
    }

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key);
    mbedtls_free(output);
    PSA_DONE();
}

void test_asymmetric_decrypt_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};

    test_asymmetric_decrypt( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6, &data8 );
}
#line 4360 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_asymmetric_decrypt_fail(int key_type_arg,
                             data_t *key_data,
                             int alg_arg,
                             data_t *input_data,
                             data_t *label,
                             int output_size_arg,
                             int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t key_type = key_type_arg;
    psa_algorithm_t alg = alg_arg;
    unsigned char *output = NULL;
    size_t output_size = output_size_arg;
    size_t output_length = ~0;
    psa_status_t actual_status;
    psa_status_t expected_status = expected_status_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    ASSERT_ALLOC(output, output_size);

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    actual_status = psa_asymmetric_decrypt(key, alg,
                                           input_data->x, input_data->len,
                                           label->x, label->len,
                                           output, output_size,
                                           &output_length);
    TEST_EQUAL(actual_status, expected_status);
    TEST_LE_U(output_length, output_size);

    /* If the label is empty, the test framework puts a non-null pointer
     * in label->x. Test that a null pointer works as well. */
    if (label->len == 0) {
        output_length = ~0;
        if (output_size != 0) {
            memset(output, 0, output_size);
        }
        actual_status = psa_asymmetric_decrypt(key, alg,
                                               input_data->x, input_data->len,
                                               NULL, label->len,
                                               output, output_size,
                                               &output_length);
        TEST_EQUAL(actual_status, expected_status);
        TEST_LE_U(output_length, output_size);
    }

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(key);
    mbedtls_free(output);
    PSA_DONE();
}

void test_asymmetric_decrypt_fail_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_asymmetric_decrypt_fail( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, &data6, *( (int *) params[8] ), *( (int *) params[9] ) );
}
#line 4422 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_key_derivation_init()
{
    /* Test each valid way of initializing the object, except for `= {0}`, as
     * Clang 5 complains when `-Wmissing-field-initializers` is used, even
     * though it's OK by the C standard. We could test for this, but we'd need
     * to suppress the Clang warning for the test. */
    size_t capacity;
    psa_key_derivation_operation_t func = psa_key_derivation_operation_init();
    psa_key_derivation_operation_t init = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_derivation_operation_t zero;

    memset(&zero, 0, sizeof(zero));

    /* A default operation should not be able to report its capacity. */
    TEST_EQUAL(psa_key_derivation_get_capacity(&func, &capacity),
               PSA_ERROR_BAD_STATE);
    TEST_EQUAL(psa_key_derivation_get_capacity(&init, &capacity),
               PSA_ERROR_BAD_STATE);
    TEST_EQUAL(psa_key_derivation_get_capacity(&zero, &capacity),
               PSA_ERROR_BAD_STATE);

    /* A default operation should be abortable without error. */
    PSA_ASSERT(psa_key_derivation_abort(&func));
    PSA_ASSERT(psa_key_derivation_abort(&init));
    PSA_ASSERT(psa_key_derivation_abort(&zero));
exit:
    ;
}

void test_key_derivation_init_wrapper( void ** params )
{
    (void)params;

    test_key_derivation_init(  );
}
#line 4451 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_setup(int alg_arg, int expected_status_arg)
{
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;

    PSA_ASSERT(psa_crypto_init());

    TEST_EQUAL(psa_key_derivation_setup(&operation, alg),
               expected_status);

exit:
    psa_key_derivation_abort(&operation);
    PSA_DONE();
}

void test_derive_setup_wrapper( void ** params )
{

    test_derive_setup( *( (int *) params[0] ), *( (int *) params[1] ) );
}
#line 4469 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_set_capacity(int alg_arg, int capacity_arg,
                         int expected_status_arg)
{
    psa_algorithm_t alg = alg_arg;
    size_t capacity = capacity_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;

    PSA_ASSERT(psa_crypto_init());

    PSA_ASSERT(psa_key_derivation_setup(&operation, alg));

    TEST_EQUAL(psa_key_derivation_set_capacity(&operation, capacity),
               expected_status);

exit:
    psa_key_derivation_abort(&operation);
    PSA_DONE();
}

void test_derive_set_capacity_wrapper( void ** params )
{

    test_derive_set_capacity( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#line 4491 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_input(int alg_arg,
                  int step_arg1, int key_type_arg1, data_t *input1,
                  int expected_status_arg1,
                  int step_arg2, int key_type_arg2, data_t *input2,
                  int expected_status_arg2,
                  int step_arg3, int key_type_arg3, data_t *input3,
                  int expected_status_arg3,
                  int output_key_type_arg, int expected_output_status_arg)
{
    psa_algorithm_t alg = alg_arg;
    psa_key_derivation_step_t steps[] = { step_arg1, step_arg2, step_arg3 };
    psa_key_type_t key_types[] = { key_type_arg1, key_type_arg2, key_type_arg3 };
    psa_status_t expected_statuses[] = { expected_status_arg1,
                                         expected_status_arg2,
                                         expected_status_arg3 };
    data_t *inputs[] = { input1, input2, input3 };
    mbedtls_svc_key_id_t keys[] = { MBEDTLS_SVC_KEY_ID_INIT,
                                    MBEDTLS_SVC_KEY_ID_INIT,
                                    MBEDTLS_SVC_KEY_ID_INIT };
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t i;
    psa_key_type_t output_key_type = output_key_type_arg;
    mbedtls_svc_key_id_t output_key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t expected_output_status = expected_output_status_arg;
    psa_status_t actual_output_status;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);

    PSA_ASSERT(psa_key_derivation_setup(&operation, alg));

    for (i = 0; i < ARRAY_LENGTH(steps); i++) {
        mbedtls_test_set_step(i);
        if (steps[i] == 0) {
            /* Skip this step */
        } else if (key_types[i] != PSA_KEY_TYPE_NONE) {
            psa_set_key_type(&attributes, key_types[i]);
            PSA_ASSERT(psa_import_key(&attributes,
                                      inputs[i]->x, inputs[i]->len,
                                      &keys[i]));
            if (PSA_KEY_TYPE_IS_KEY_PAIR(key_types[i]) &&
                steps[i] == PSA_KEY_DERIVATION_INPUT_SECRET) {
                // When taking a private key as secret input, use key agreement
                // to add the shared secret to the derivation
                TEST_EQUAL(mbedtls_test_psa_key_agreement_with_self(
                               &operation, keys[i]),
                           expected_statuses[i]);
            } else {
                TEST_EQUAL(psa_key_derivation_input_key(&operation, steps[i],
                                                        keys[i]),
                           expected_statuses[i]);
            }
        } else {
            TEST_EQUAL(psa_key_derivation_input_bytes(
                           &operation, steps[i],
                           inputs[i]->x, inputs[i]->len),
                       expected_statuses[i]);
        }
    }

    if (output_key_type != PSA_KEY_TYPE_NONE) {
        psa_reset_key_attributes(&attributes);
        psa_set_key_type(&attributes, output_key_type);
        psa_set_key_bits(&attributes, 8);
        actual_output_status =
            psa_key_derivation_output_key(&attributes, &operation,
                                          &output_key);
    } else {
        uint8_t buffer[1];
        actual_output_status =
            psa_key_derivation_output_bytes(&operation,
                                            buffer, sizeof(buffer));
    }
    TEST_EQUAL(actual_output_status, expected_output_status);

exit:
    psa_key_derivation_abort(&operation);
    for (i = 0; i < ARRAY_LENGTH(keys); i++) {
        psa_destroy_key(keys[i]);
    }
    psa_destroy_key(output_key);
    PSA_DONE();
}

void test_derive_input_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};
    data_t data13 = {(uint8_t *) params[13], *( (uint32_t *) params[14] )};

    test_derive_input( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, *( (int *) params[5] ), *( (int *) params[6] ), *( (int *) params[7] ), &data8, *( (int *) params[10] ), *( (int *) params[11] ), *( (int *) params[12] ), &data13, *( (int *) params[15] ), *( (int *) params[16] ), *( (int *) params[17] ) );
}
#line 4580 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_over_capacity(int alg_arg)
{
    psa_algorithm_t alg = alg_arg;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    size_t key_type = PSA_KEY_TYPE_DERIVE;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    unsigned char input1[] = "Input 1";
    size_t input1_length = sizeof(input1);
    unsigned char input2[] = "Input 2";
    size_t input2_length = sizeof(input2);
    uint8_t buffer[42];
    size_t capacity = sizeof(buffer);
    const uint8_t key_data[22] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                   0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);

    PSA_ASSERT(psa_import_key(&attributes,
                              key_data, sizeof(key_data),
                              &key));

    /* valid key derivation */
    if (!mbedtls_test_psa_setup_key_derivation_wrap(&operation, key, alg,
                                                    input1, input1_length,
                                                    input2, input2_length,
                                                    capacity)) {
        goto exit;
    }

    /* state of operation shouldn't allow additional generation */
    TEST_EQUAL(psa_key_derivation_setup(&operation, alg),
               PSA_ERROR_BAD_STATE);

    PSA_ASSERT(psa_key_derivation_output_bytes(&operation, buffer, capacity));

    TEST_EQUAL(psa_key_derivation_output_bytes(&operation, buffer, capacity),
               PSA_ERROR_INSUFFICIENT_DATA);

exit:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_derive_over_capacity_wrapper( void ** params )
{

    test_derive_over_capacity( *( (int *) params[0] ) );
}
#line 4632 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_actions_without_setup()
{
    uint8_t output_buffer[16];
    size_t buffer_size = 16;
    size_t capacity = 0;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;

    TEST_ASSERT(psa_key_derivation_output_bytes(&operation,
                                                output_buffer, buffer_size)
                == PSA_ERROR_BAD_STATE);

    TEST_ASSERT(psa_key_derivation_get_capacity(&operation, &capacity)
                == PSA_ERROR_BAD_STATE);

    PSA_ASSERT(psa_key_derivation_abort(&operation));

    TEST_ASSERT(psa_key_derivation_output_bytes(&operation,
                                                output_buffer, buffer_size)
                == PSA_ERROR_BAD_STATE);

    TEST_ASSERT(psa_key_derivation_get_capacity(&operation, &capacity)
                == PSA_ERROR_BAD_STATE);

exit:
    psa_key_derivation_abort(&operation);
}

void test_derive_actions_without_setup_wrapper( void ** params )
{
    (void)params;

    test_derive_actions_without_setup(  );
}
#line 4661 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_output(int alg_arg,
                   int step1_arg, data_t *input1,
                   int step2_arg, data_t *input2,
                   int step3_arg, data_t *input3,
                   int requested_capacity_arg,
                   data_t *expected_output1,
                   data_t *expected_output2)
{
    psa_algorithm_t alg = alg_arg;
    psa_key_derivation_step_t steps[] = { step1_arg, step2_arg, step3_arg };
    data_t *inputs[] = { input1, input2, input3 };
    mbedtls_svc_key_id_t keys[] = { MBEDTLS_SVC_KEY_ID_INIT,
                                    MBEDTLS_SVC_KEY_ID_INIT,
                                    MBEDTLS_SVC_KEY_ID_INIT };
    size_t requested_capacity = requested_capacity_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t *expected_outputs[2] =
    { expected_output1->x, expected_output2->x };
    size_t output_sizes[2] =
    { expected_output1->len, expected_output2->len };
    size_t output_buffer_size = 0;
    uint8_t *output_buffer = NULL;
    size_t expected_capacity;
    size_t current_capacity;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    size_t i;

    for (i = 0; i < ARRAY_LENGTH(expected_outputs); i++) {
        if (output_sizes[i] > output_buffer_size) {
            output_buffer_size = output_sizes[i];
        }
        if (output_sizes[i] == 0) {
            expected_outputs[i] = NULL;
        }
    }
    ASSERT_ALLOC(output_buffer, output_buffer_size);
    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);

    /* Extraction phase. */
    PSA_ASSERT(psa_key_derivation_setup(&operation, alg));
    PSA_ASSERT(psa_key_derivation_set_capacity(&operation,
                                               requested_capacity));
    for (i = 0; i < ARRAY_LENGTH(steps); i++) {
        switch (steps[i]) {
            case 0:
                break;
            case PSA_KEY_DERIVATION_INPUT_SECRET:
                PSA_ASSERT(psa_import_key(&attributes,
                                          inputs[i]->x, inputs[i]->len,
                                          &keys[i]));

                if (PSA_ALG_IS_TLS12_PSK_TO_MS(alg)) {
                    PSA_ASSERT(psa_get_key_attributes(keys[i], &attributes));
                    TEST_ASSERT(PSA_BITS_TO_BYTES(psa_get_key_bits(&attributes)) <=
                                PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE);
                }

                PSA_ASSERT(psa_key_derivation_input_key(
                               &operation, steps[i], keys[i]));
                break;
            default:
                PSA_ASSERT(psa_key_derivation_input_bytes(
                               &operation, steps[i],
                               inputs[i]->x, inputs[i]->len));
                break;
        }
    }

    PSA_ASSERT(psa_key_derivation_get_capacity(&operation,
                                               &current_capacity));
    TEST_EQUAL(current_capacity, requested_capacity);
    expected_capacity = requested_capacity;

    /* Expansion phase. */
    for (i = 0; i < ARRAY_LENGTH(expected_outputs); i++) {
        /* Read some bytes. */
        status = psa_key_derivation_output_bytes(&operation,
                                                 output_buffer, output_sizes[i]);
        if (expected_capacity == 0 && output_sizes[i] == 0) {
            /* Reading 0 bytes when 0 bytes are available can go either way. */
            TEST_ASSERT(status == PSA_SUCCESS ||
                        status == PSA_ERROR_INSUFFICIENT_DATA);
            continue;
        } else if (expected_capacity == 0 ||
                   output_sizes[i] > expected_capacity) {
            /* Capacity exceeded. */
            TEST_EQUAL(status, PSA_ERROR_INSUFFICIENT_DATA);
            expected_capacity = 0;
            continue;
        }
        /* Success. Check the read data. */
        PSA_ASSERT(status);
        if (output_sizes[i] != 0) {
            ASSERT_COMPARE(output_buffer, output_sizes[i],
                           expected_outputs[i], output_sizes[i]);
        }
        /* Check the operation status. */
        expected_capacity -= output_sizes[i];
        PSA_ASSERT(psa_key_derivation_get_capacity(&operation,
                                                   &current_capacity));
        TEST_EQUAL(expected_capacity, current_capacity);
    }
    PSA_ASSERT(psa_key_derivation_abort(&operation));

exit:
    mbedtls_free(output_buffer);
    psa_key_derivation_abort(&operation);
    for (i = 0; i < ARRAY_LENGTH(keys); i++) {
        psa_destroy_key(keys[i]);
    }
    PSA_DONE();
}

void test_derive_output_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};
    data_t data11 = {(uint8_t *) params[11], *( (uint32_t *) params[12] )};
    data_t data13 = {(uint8_t *) params[13], *( (uint32_t *) params[14] )};

    test_derive_output( *( (int *) params[0] ), *( (int *) params[1] ), &data2, *( (int *) params[4] ), &data5, *( (int *) params[7] ), &data8, *( (int *) params[10] ), &data11, &data13 );
}
#line 4781 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_full(int alg_arg,
                 data_t *key_data,
                 data_t *input1,
                 data_t *input2,
                 int requested_capacity_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg = alg_arg;
    size_t requested_capacity = requested_capacity_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    unsigned char output_buffer[16];
    size_t expected_capacity = requested_capacity;
    size_t current_capacity;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);

    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &key));

    if (!mbedtls_test_psa_setup_key_derivation_wrap(&operation, key, alg,
                                                    input1->x, input1->len,
                                                    input2->x, input2->len,
                                                    requested_capacity)) {
        goto exit;
    }

    PSA_ASSERT(psa_key_derivation_get_capacity(&operation,
                                               &current_capacity));
    TEST_EQUAL(current_capacity, expected_capacity);

    /* Expansion phase. */
    while (current_capacity > 0) {
        size_t read_size = sizeof(output_buffer);
        if (read_size > current_capacity) {
            read_size = current_capacity;
        }
        PSA_ASSERT(psa_key_derivation_output_bytes(&operation,
                                                   output_buffer,
                                                   read_size));
        expected_capacity -= read_size;
        PSA_ASSERT(psa_key_derivation_get_capacity(&operation,
                                                   &current_capacity));
        TEST_EQUAL(current_capacity, expected_capacity);
    }

    /* Check that the operation refuses to go over capacity. */
    TEST_EQUAL(psa_key_derivation_output_bytes(&operation, output_buffer, 1),
               PSA_ERROR_INSUFFICIENT_DATA);

    PSA_ASSERT(psa_key_derivation_abort(&operation));

exit:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_derive_full_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};

    test_derive_full( *( (int *) params[0] ), &data1, &data3, &data5, *( (int *) params[7] ) );
}
#line 4845 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_key_exercise(int alg_arg,
                         data_t *key_data,
                         data_t *input1,
                         data_t *input2,
                         int derived_type_arg,
                         int derived_bits_arg,
                         int derived_usage_arg,
                         int derived_alg_arg)
{
    mbedtls_svc_key_id_t base_key = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_svc_key_id_t derived_key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg = alg_arg;
    psa_key_type_t derived_type = derived_type_arg;
    size_t derived_bits = derived_bits_arg;
    psa_key_usage_t derived_usage = derived_usage_arg;
    psa_algorithm_t derived_alg = derived_alg_arg;
    size_t capacity = PSA_BITS_TO_BYTES(derived_bits);
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t got_attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
    PSA_ASSERT(psa_import_key(&attributes, key_data->x, key_data->len,
                              &base_key));

    /* Derive a key. */
    if (!mbedtls_test_psa_setup_key_derivation_wrap(&operation, base_key, alg,
                                                    input1->x, input1->len,
                                                    input2->x, input2->len,
                                                    capacity)) {
        goto exit;
    }

    psa_set_key_usage_flags(&attributes, derived_usage);
    psa_set_key_algorithm(&attributes, derived_alg);
    psa_set_key_type(&attributes, derived_type);
    psa_set_key_bits(&attributes, derived_bits);
    PSA_ASSERT(psa_key_derivation_output_key(&attributes, &operation,
                                             &derived_key));

    /* Test the key information */
    PSA_ASSERT(psa_get_key_attributes(derived_key, &got_attributes));
    TEST_EQUAL(psa_get_key_type(&got_attributes), derived_type);
    TEST_EQUAL(psa_get_key_bits(&got_attributes), derived_bits);

    /* Exercise the derived key. */
    if (!mbedtls_test_psa_exercise_key(derived_key, derived_usage, derived_alg)) {
        goto exit;
    }

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&got_attributes);

    psa_key_derivation_abort(&operation);
    psa_destroy_key(base_key);
    psa_destroy_key(derived_key);
    PSA_DONE();
}

void test_derive_key_exercise_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};

    test_derive_key_exercise( *( (int *) params[0] ), &data1, &data3, &data5, *( (int *) params[7] ), *( (int *) params[8] ), *( (int *) params[9] ), *( (int *) params[10] ) );
}
#line 4914 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_key_export(int alg_arg,
                       data_t *key_data,
                       data_t *input1,
                       data_t *input2,
                       int bytes1_arg,
                       int bytes2_arg)
{
    mbedtls_svc_key_id_t base_key = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_svc_key_id_t derived_key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg = alg_arg;
    size_t bytes1 = bytes1_arg;
    size_t bytes2 = bytes2_arg;
    size_t capacity = bytes1 + bytes2;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t *output_buffer = NULL;
    uint8_t *export_buffer = NULL;
    psa_key_attributes_t base_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t derived_attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t length;

    ASSERT_ALLOC(output_buffer, capacity);
    ASSERT_ALLOC(export_buffer, capacity);
    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&base_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&base_attributes, alg);
    psa_set_key_type(&base_attributes, PSA_KEY_TYPE_DERIVE);
    PSA_ASSERT(psa_import_key(&base_attributes, key_data->x, key_data->len,
                              &base_key));

    /* Derive some material and output it. */
    if (!mbedtls_test_psa_setup_key_derivation_wrap(&operation, base_key, alg,
                                                    input1->x, input1->len,
                                                    input2->x, input2->len,
                                                    capacity)) {
        goto exit;
    }

    PSA_ASSERT(psa_key_derivation_output_bytes(&operation,
                                               output_buffer,
                                               capacity));
    PSA_ASSERT(psa_key_derivation_abort(&operation));

    /* Derive the same output again, but this time store it in key objects. */
    if (!mbedtls_test_psa_setup_key_derivation_wrap(&operation, base_key, alg,
                                                    input1->x, input1->len,
                                                    input2->x, input2->len,
                                                    capacity)) {
        goto exit;
    }

    psa_set_key_usage_flags(&derived_attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&derived_attributes, 0);
    psa_set_key_type(&derived_attributes, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_bits(&derived_attributes, PSA_BYTES_TO_BITS(bytes1));
    PSA_ASSERT(psa_key_derivation_output_key(&derived_attributes, &operation,
                                             &derived_key));
    PSA_ASSERT(psa_export_key(derived_key,
                              export_buffer, bytes1,
                              &length));
    TEST_EQUAL(length, bytes1);
    PSA_ASSERT(psa_destroy_key(derived_key));
    psa_set_key_bits(&derived_attributes, PSA_BYTES_TO_BITS(bytes2));
    PSA_ASSERT(psa_key_derivation_output_key(&derived_attributes, &operation,
                                             &derived_key));
    PSA_ASSERT(psa_export_key(derived_key,
                              export_buffer + bytes1, bytes2,
                              &length));
    TEST_EQUAL(length, bytes2);

    /* Compare the outputs from the two runs. */
    ASSERT_COMPARE(output_buffer, bytes1 + bytes2,
                   export_buffer, capacity);

exit:
    mbedtls_free(output_buffer);
    mbedtls_free(export_buffer);
    psa_key_derivation_abort(&operation);
    psa_destroy_key(base_key);
    psa_destroy_key(derived_key);
    PSA_DONE();
}

void test_derive_key_export_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};

    test_derive_key_export( *( (int *) params[0] ), &data1, &data3, &data5, *( (int *) params[7] ), *( (int *) params[8] ) );
}
#line 4999 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_derive_key(int alg_arg,
                data_t *key_data, data_t *input1, data_t *input2,
                int type_arg, int bits_arg,
                int expected_status_arg,
                int is_large_output)
{
    mbedtls_svc_key_id_t base_key = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_svc_key_id_t derived_key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg = alg_arg;
    psa_key_type_t type = type_arg;
    size_t bits = bits_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t base_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t derived_attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&base_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&base_attributes, alg);
    psa_set_key_type(&base_attributes, PSA_KEY_TYPE_DERIVE);
    PSA_ASSERT(psa_import_key(&base_attributes, key_data->x, key_data->len,
                              &base_key));

    if (!mbedtls_test_psa_setup_key_derivation_wrap(&operation, base_key, alg,
                                                    input1->x, input1->len,
                                                    input2->x, input2->len,
                                                    SIZE_MAX)) {
        goto exit;
    }

    psa_set_key_usage_flags(&derived_attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&derived_attributes, 0);
    psa_set_key_type(&derived_attributes, type);
    psa_set_key_bits(&derived_attributes, bits);

    psa_status_t status =
        psa_key_derivation_output_key(&derived_attributes,
                                      &operation,
                                      &derived_key);
    if (is_large_output > 0) {
        TEST_ASSUME(status != PSA_ERROR_INSUFFICIENT_MEMORY);
    }
    TEST_EQUAL(status, expected_status);

exit:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(base_key);
    psa_destroy_key(derived_key);
    PSA_DONE();
}

void test_derive_key_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};

    test_derive_key( *( (int *) params[0] ), &data1, &data3, &data5, *( (int *) params[7] ), *( (int *) params[8] ), *( (int *) params[9] ), *( (int *) params[10] ) );
}
#line 5053 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_key_agreement_setup(int alg_arg,
                         int our_key_type_arg, int our_key_alg_arg,
                         data_t *our_key_data, data_t *peer_key_data,
                         int expected_status_arg)
{
    mbedtls_svc_key_id_t our_key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg = alg_arg;
    psa_algorithm_t our_key_alg = our_key_alg_arg;
    psa_key_type_t our_key_type = our_key_type_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t expected_status = expected_status_arg;
    psa_status_t status;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, our_key_alg);
    psa_set_key_type(&attributes, our_key_type);
    PSA_ASSERT(psa_import_key(&attributes,
                              our_key_data->x, our_key_data->len,
                              &our_key));

    /* The tests currently include inputs that should fail at either step.
     * Test cases that fail at the setup step should be changed to call
     * key_derivation_setup instead, and this function should be renamed
     * to key_agreement_fail. */
    status = psa_key_derivation_setup(&operation, alg);
    if (status == PSA_SUCCESS) {
        TEST_EQUAL(psa_key_derivation_key_agreement(
                       &operation, PSA_KEY_DERIVATION_INPUT_SECRET,
                       our_key,
                       peer_key_data->x, peer_key_data->len),
                   expected_status);
    } else {
        TEST_ASSERT(status == expected_status);
    }

exit:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(our_key);
    PSA_DONE();
}

void test_key_agreement_setup_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};

    test_key_agreement_setup( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), &data3, &data5, *( (int *) params[7] ) );
}
#line 5099 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_raw_key_agreement(int alg_arg,
                       int our_key_type_arg, data_t *our_key_data,
                       data_t *peer_key_data,
                       data_t *expected_output)
{
    mbedtls_svc_key_id_t our_key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg = alg_arg;
    psa_key_type_t our_key_type = our_key_type_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    unsigned char *output = NULL;
    size_t output_length = ~0;
    size_t key_bits;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, our_key_type);
    PSA_ASSERT(psa_import_key(&attributes,
                              our_key_data->x, our_key_data->len,
                              &our_key));

    PSA_ASSERT(psa_get_key_attributes(our_key, &attributes));
    key_bits = psa_get_key_bits(&attributes);

    /* Validate size macros */
    TEST_LE_U(expected_output->len,
              PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(our_key_type, key_bits));
    TEST_LE_U(PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(our_key_type, key_bits),
              PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE);

    /* Good case with exact output size */
    ASSERT_ALLOC(output, expected_output->len);
    PSA_ASSERT(psa_raw_key_agreement(alg, our_key,
                                     peer_key_data->x, peer_key_data->len,
                                     output, expected_output->len,
                                     &output_length));
    ASSERT_COMPARE(output, output_length,
                   expected_output->x, expected_output->len);
    mbedtls_free(output);
    output = NULL;
    output_length = ~0;

    /* Larger buffer */
    ASSERT_ALLOC(output, expected_output->len + 1);
    PSA_ASSERT(psa_raw_key_agreement(alg, our_key,
                                     peer_key_data->x, peer_key_data->len,
                                     output, expected_output->len + 1,
                                     &output_length));
    ASSERT_COMPARE(output, output_length,
                   expected_output->x, expected_output->len);
    mbedtls_free(output);
    output = NULL;
    output_length = ~0;

    /* Buffer too small */
    ASSERT_ALLOC(output, expected_output->len - 1);
    TEST_EQUAL(psa_raw_key_agreement(alg, our_key,
                                     peer_key_data->x, peer_key_data->len,
                                     output, expected_output->len - 1,
                                     &output_length),
               PSA_ERROR_BUFFER_TOO_SMALL);
    /* Not required by the spec, but good robustness */
    TEST_LE_U(output_length, expected_output->len - 1);
    mbedtls_free(output);
    output = NULL;

exit:
    mbedtls_free(output);
    psa_destroy_key(our_key);
    PSA_DONE();
}

void test_raw_key_agreement_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_raw_key_agreement( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4, &data6 );
}
#line 5174 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_key_agreement_capacity(int alg_arg,
                            int our_key_type_arg, data_t *our_key_data,
                            data_t *peer_key_data,
                            int expected_capacity_arg)
{
    mbedtls_svc_key_id_t our_key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg = alg_arg;
    psa_key_type_t our_key_type = our_key_type_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t actual_capacity;
    unsigned char output[16];

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, our_key_type);
    PSA_ASSERT(psa_import_key(&attributes,
                              our_key_data->x, our_key_data->len,
                              &our_key));

    PSA_ASSERT(psa_key_derivation_setup(&operation, alg));
    PSA_ASSERT(psa_key_derivation_key_agreement(
                   &operation,
                   PSA_KEY_DERIVATION_INPUT_SECRET, our_key,
                   peer_key_data->x, peer_key_data->len));
    if (PSA_ALG_IS_HKDF(PSA_ALG_KEY_AGREEMENT_GET_KDF(alg))) {
        /* The test data is for info="" */
        PSA_ASSERT(psa_key_derivation_input_bytes(&operation,
                                                  PSA_KEY_DERIVATION_INPUT_INFO,
                                                  NULL, 0));
    }

    /* Test the advertised capacity. */
    PSA_ASSERT(psa_key_derivation_get_capacity(
                   &operation, &actual_capacity));
    TEST_EQUAL(actual_capacity, (size_t) expected_capacity_arg);

    /* Test the actual capacity by reading the output. */
    while (actual_capacity > sizeof(output)) {
        PSA_ASSERT(psa_key_derivation_output_bytes(&operation,
                                                   output, sizeof(output)));
        actual_capacity -= sizeof(output);
    }
    PSA_ASSERT(psa_key_derivation_output_bytes(&operation,
                                               output, actual_capacity));
    TEST_EQUAL(psa_key_derivation_output_bytes(&operation, output, 1),
               PSA_ERROR_INSUFFICIENT_DATA);

exit:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(our_key);
    PSA_DONE();
}

void test_key_agreement_capacity_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};

    test_key_agreement_capacity( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4, *( (int *) params[6] ) );
}
#line 5232 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_key_agreement_output(int alg_arg,
                          int our_key_type_arg, data_t *our_key_data,
                          data_t *peer_key_data,
                          data_t *expected_output1, data_t *expected_output2)
{
    mbedtls_svc_key_id_t our_key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t alg = alg_arg;
    psa_key_type_t our_key_type = our_key_type_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t *actual_output = NULL;

    ASSERT_ALLOC(actual_output, MAX(expected_output1->len,
                                    expected_output2->len));

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, our_key_type);
    PSA_ASSERT(psa_import_key(&attributes,
                              our_key_data->x, our_key_data->len,
                              &our_key));

    PSA_ASSERT(psa_key_derivation_setup(&operation, alg));
    PSA_ASSERT(psa_key_derivation_key_agreement(
                   &operation,
                   PSA_KEY_DERIVATION_INPUT_SECRET, our_key,
                   peer_key_data->x, peer_key_data->len));
    if (PSA_ALG_IS_HKDF(PSA_ALG_KEY_AGREEMENT_GET_KDF(alg))) {
        /* The test data is for info="" */
        PSA_ASSERT(psa_key_derivation_input_bytes(&operation,
                                                  PSA_KEY_DERIVATION_INPUT_INFO,
                                                  NULL, 0));
    }

    PSA_ASSERT(psa_key_derivation_output_bytes(&operation,
                                               actual_output,
                                               expected_output1->len));
    ASSERT_COMPARE(actual_output, expected_output1->len,
                   expected_output1->x, expected_output1->len);
    if (expected_output2->len != 0) {
        PSA_ASSERT(psa_key_derivation_output_bytes(&operation,
                                                   actual_output,
                                                   expected_output2->len));
        ASSERT_COMPARE(actual_output, expected_output2->len,
                       expected_output2->x, expected_output2->len);
    }

exit:
    psa_key_derivation_abort(&operation);
    psa_destroy_key(our_key);
    PSA_DONE();
    mbedtls_free(actual_output);
}

void test_key_agreement_output_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};

    test_key_agreement_output( *( (int *) params[0] ), *( (int *) params[1] ), &data2, &data4, &data6, &data8 );
}
#line 5290 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_generate_random(int bytes_arg)
{
    size_t bytes = bytes_arg;
    unsigned char *output = NULL;
    unsigned char *changed = NULL;
    size_t i;
    unsigned run;

    TEST_ASSERT(bytes_arg >= 0);

    ASSERT_ALLOC(output, bytes);
    ASSERT_ALLOC(changed, bytes);

    PSA_ASSERT(psa_crypto_init());

    /* Run several times, to ensure that every output byte will be
     * nonzero at least once with overwhelming probability
     * (2^(-8*number_of_runs)). */
    for (run = 0; run < 10; run++) {
        if (bytes != 0) {
            memset(output, 0, bytes);
        }
        PSA_ASSERT(psa_generate_random(output, bytes));

        for (i = 0; i < bytes; i++) {
            if (output[i] != 0) {
                ++changed[i];
            }
        }
    }

    /* Check that every byte was changed to nonzero at least once. This
     * validates that psa_generate_random is overwriting every byte of
     * the output buffer. */
    for (i = 0; i < bytes; i++) {
        TEST_ASSERT(changed[i] != 0);
    }

exit:
    PSA_DONE();
    mbedtls_free(output);
    mbedtls_free(changed);
}

void test_generate_random_wrapper( void ** params )
{

    test_generate_random( *( (int *) params[0] ) );
}
#line 5336 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_generate_key(int type_arg,
                  int bits_arg,
                  int usage_arg,
                  int alg_arg,
                  int expected_status_arg,
                  int is_large_key)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t type = type_arg;
    psa_key_usage_t usage = usage_arg;
    size_t bits = bits_arg;
    psa_algorithm_t alg = alg_arg;
    psa_status_t expected_status = expected_status_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t got_attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, type);
    psa_set_key_bits(&attributes, bits);

    /* Generate a key */
    psa_status_t status = psa_generate_key(&attributes, &key);

    if (is_large_key > 0) {
        TEST_ASSUME(status != PSA_ERROR_INSUFFICIENT_MEMORY);
    }
    TEST_EQUAL(status, expected_status);
    if (expected_status != PSA_SUCCESS) {
        goto exit;
    }

    /* Test the key information */
    PSA_ASSERT(psa_get_key_attributes(key, &got_attributes));
    TEST_EQUAL(psa_get_key_type(&got_attributes), type);
    TEST_EQUAL(psa_get_key_bits(&got_attributes), bits);

    /* Do something with the key according to its type and permitted usage. */
    if (!mbedtls_test_psa_exercise_key(key, usage, alg)) {
        goto exit;
    }

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&got_attributes);

    psa_destroy_key(key);
    PSA_DONE();
}

void test_generate_key_wrapper( void ** params )
{

    test_generate_key( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ) );
}
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT)
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#if defined(MBEDTLS_GENPRIME)
#line 5393 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_generate_key_rsa(int bits_arg,
                      data_t *e_arg,
                      int expected_status_arg)
{
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t type = PSA_KEY_TYPE_RSA_KEY_PAIR;
    size_t bits = bits_arg;
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT;
    psa_algorithm_t alg = PSA_ALG_RSA_PKCS1V15_SIGN_RAW;
    psa_status_t expected_status = expected_status_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t *exported = NULL;
    size_t exported_size =
        PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_PUBLIC_KEY, bits);
    size_t exported_length = SIZE_MAX;
    uint8_t *e_read_buffer = NULL;
    int is_default_public_exponent = 0;
    size_t e_read_size = PSA_KEY_DOMAIN_PARAMETERS_SIZE(type, bits);
    size_t e_read_length = SIZE_MAX;

    if (e_arg->len == 0 ||
        (e_arg->len == 3 &&
         e_arg->x[0] == 1 && e_arg->x[1] == 0 && e_arg->x[2] == 1)) {
        is_default_public_exponent = 1;
        e_read_size = 0;
    }
    ASSERT_ALLOC(e_read_buffer, e_read_size);
    ASSERT_ALLOC(exported, exported_size);

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, alg);
    PSA_ASSERT(psa_set_key_domain_parameters(&attributes, type,
                                             e_arg->x, e_arg->len));
    psa_set_key_bits(&attributes, bits);

    /* Generate a key */
    TEST_EQUAL(psa_generate_key(&attributes, &key), expected_status);
    if (expected_status != PSA_SUCCESS) {
        goto exit;
    }

    /* Test the key information */
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    TEST_EQUAL(psa_get_key_type(&attributes), type);
    TEST_EQUAL(psa_get_key_bits(&attributes), bits);
    PSA_ASSERT(psa_get_key_domain_parameters(&attributes,
                                             e_read_buffer, e_read_size,
                                             &e_read_length));
    if (is_default_public_exponent) {
        TEST_EQUAL(e_read_length, 0);
    } else {
        ASSERT_COMPARE(e_read_buffer, e_read_length, e_arg->x, e_arg->len);
    }

    /* Do something with the key according to its type and permitted usage. */
    if (!mbedtls_test_psa_exercise_key(key, usage, alg)) {
        goto exit;
    }

    /* Export the key and check the public exponent. */
    PSA_ASSERT(psa_export_public_key(key,
                                     exported, exported_size,
                                     &exported_length));
    {
        uint8_t *p = exported;
        uint8_t *end = exported + exported_length;
        size_t len;
        /*   RSAPublicKey ::= SEQUENCE {
         *      modulus            INTEGER,    -- n
         *      publicExponent     INTEGER  }  -- e
         */
        TEST_EQUAL(0, mbedtls_asn1_get_tag(&p, end, &len,
                                           MBEDTLS_ASN1_SEQUENCE |
                                           MBEDTLS_ASN1_CONSTRUCTED));
        TEST_ASSERT(mbedtls_test_asn1_skip_integer(&p, end, bits, bits, 1));
        TEST_EQUAL(0, mbedtls_asn1_get_tag(&p, end, &len,
                                           MBEDTLS_ASN1_INTEGER));
        if (len >= 1 && p[0] == 0) {
            ++p;
            --len;
        }
        if (e_arg->len == 0) {
            TEST_EQUAL(len, 3);
            TEST_EQUAL(p[0], 1);
            TEST_EQUAL(p[1], 0);
            TEST_EQUAL(p[2], 1);
        } else {
            ASSERT_COMPARE(p, len, e_arg->x, e_arg->len);
        }
    }

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes() or
     * set by psa_set_key_domain_parameters() thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    psa_destroy_key(key);
    PSA_DONE();
    mbedtls_free(e_read_buffer);
    mbedtls_free(exported);
}

void test_generate_key_rsa_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_generate_key_rsa( *( (int *) params[0] ), &data1, *( (int *) params[3] ) );
}
#endif /* MBEDTLS_GENPRIME */
#endif /* PSA_WANT_ALG_RSA_PKCS1V15_SIGN */
#endif /* PSA_WANT_ALG_RSA_PKCS1V15_CRYPT */
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR */
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
#line 5501 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_psa_crypto.function"
void test_persistent_key_load_key_from_storage(data_t *data,
                                          int type_arg, int bits_arg,
                                          int usage_flags_arg, int alg_arg,
                                          int generation_method)
{
    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(1, 1);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_svc_key_id_t base_key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t type = type_arg;
    size_t bits = bits_arg;
    psa_key_usage_t usage_flags = usage_flags_arg;
    psa_algorithm_t alg = alg_arg;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    unsigned char *first_export = NULL;
    unsigned char *second_export = NULL;
    size_t export_size = PSA_EXPORT_KEY_OUTPUT_SIZE(type, bits);
    size_t first_exported_length;
    size_t second_exported_length;

    if (usage_flags & PSA_KEY_USAGE_EXPORT) {
        ASSERT_ALLOC(first_export, export_size);
        ASSERT_ALLOC(second_export, export_size);
    }

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_id(&attributes, key_id);
    psa_set_key_usage_flags(&attributes, usage_flags);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, type);
    psa_set_key_bits(&attributes, bits);

    switch (generation_method) {
        case IMPORT_KEY:
            /* Import the key */
            PSA_ASSERT(psa_import_key(&attributes, data->x, data->len,
                                      &key));
            break;

        case GENERATE_KEY:
            /* Generate a key */
            PSA_ASSERT(psa_generate_key(&attributes, &key));
            break;

        case DERIVE_KEY:
#if defined(PSA_WANT_ALG_HKDF) && defined(PSA_WANT_ALG_SHA_256)
        {
            /* Create base key */
            psa_algorithm_t derive_alg = PSA_ALG_HKDF(PSA_ALG_SHA_256);
            psa_key_attributes_t base_attributes = PSA_KEY_ATTRIBUTES_INIT;
            psa_set_key_usage_flags(&base_attributes,
                                    PSA_KEY_USAGE_DERIVE);
            psa_set_key_algorithm(&base_attributes, derive_alg);
            psa_set_key_type(&base_attributes, PSA_KEY_TYPE_DERIVE);
            PSA_ASSERT(psa_import_key(&base_attributes,
                                      data->x, data->len,
                                      &base_key));
            /* Derive a key. */
            PSA_ASSERT(psa_key_derivation_setup(&operation, derive_alg));
            PSA_ASSERT(psa_key_derivation_input_key(
                           &operation,
                           PSA_KEY_DERIVATION_INPUT_SECRET, base_key));
            PSA_ASSERT(psa_key_derivation_input_bytes(
                           &operation, PSA_KEY_DERIVATION_INPUT_INFO,
                           NULL, 0));
            PSA_ASSERT(psa_key_derivation_output_key(&attributes,
                                                     &operation,
                                                     &key));
            PSA_ASSERT(psa_key_derivation_abort(&operation));
            PSA_ASSERT(psa_destroy_key(base_key));
            base_key = MBEDTLS_SVC_KEY_ID_INIT;
        }
#else
            TEST_ASSUME(!"KDF not supported in this configuration");
#endif
            break;

        default:
            TEST_ASSERT(!"generation_method not implemented in test");
            break;
    }
    psa_reset_key_attributes(&attributes);

    /* Export the key if permitted by the key policy. */
    if (usage_flags & PSA_KEY_USAGE_EXPORT) {
        PSA_ASSERT(psa_export_key(key,
                                  first_export, export_size,
                                  &first_exported_length));
        if (generation_method == IMPORT_KEY) {
            ASSERT_COMPARE(data->x, data->len,
                           first_export, first_exported_length);
        }
    }

    /* Shutdown and restart */
    PSA_ASSERT(psa_purge_key(key));
    PSA_DONE();
    PSA_ASSERT(psa_crypto_init());

    /* Check key slot still contains key data */
    PSA_ASSERT(psa_get_key_attributes(key, &attributes));
    TEST_ASSERT(mbedtls_svc_key_id_equal(
                    psa_get_key_id(&attributes), key_id));
    TEST_EQUAL(psa_get_key_lifetime(&attributes),
               PSA_KEY_LIFETIME_PERSISTENT);
    TEST_EQUAL(psa_get_key_type(&attributes), type);
    TEST_EQUAL(psa_get_key_bits(&attributes), bits);
    TEST_EQUAL(psa_get_key_usage_flags(&attributes),
               mbedtls_test_update_key_usage_flags(usage_flags));
    TEST_EQUAL(psa_get_key_algorithm(&attributes), alg);

    /* Export the key again if permitted by the key policy. */
    if (usage_flags & PSA_KEY_USAGE_EXPORT) {
        PSA_ASSERT(psa_export_key(key,
                                  second_export, export_size,
                                  &second_exported_length));
        ASSERT_COMPARE(first_export, first_exported_length,
                       second_export, second_exported_length);
    }

    /* Do something with the key according to its type and permitted usage. */
    if (!mbedtls_test_psa_exercise_key(key, usage_flags, alg)) {
        goto exit;
    }

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    mbedtls_free(first_export);
    mbedtls_free(second_export);
    psa_key_derivation_abort(&operation);
    psa_destroy_key(base_key);
    psa_destroy_key(key);
    PSA_DONE();
}

void test_persistent_key_load_key_from_storage_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};

    test_persistent_key_load_key_from_storage( &data0, *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ), *( (int *) params[6] ) );
}
#endif /* MBEDTLS_PSA_CRYPTO_STORAGE_C */
#endif /* MBEDTLS_PSA_CRYPTO_C */


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
    
#if defined(MBEDTLS_PSA_CRYPTO_C)

        case 0:
            {
                *out_value = PSA_KEY_TYPE_RAW_DATA;
            }
            break;
        case 1:
            {
                *out_value = PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 2:
            {
                *out_value = PSA_SUCCESS;
            }
            break;
        case 3:
            {
                *out_value = -1;
            }
            break;
        case 4:
            {
                *out_value = PSA_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        case 5:
            {
                *out_value = PSA_KEY_TYPE_AES;
            }
            break;
        case 6:
            {
                *out_value = PSA_ALG_CTR;
            }
            break;
        case 7:
            {
                *out_value = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case 8:
            {
                *out_value = PSA_KEY_TYPE_RSA_PUBLIC_KEY;
            }
            break;
        case 9:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN_RAW;
            }
            break;
        case 10:
            {
                *out_value = PSA_KEY_TYPE_RSA_KEY_PAIR;
            }
            break;
        case 11:
            {
                *out_value = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case 12:
            {
                *out_value = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            }
            break;
        case 13:
            {
                *out_value = PSA_ALG_ECDSA_ANY;
            }
            break;
        case 14:
            {
                *out_value = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1);
            }
            break;
        case 15:
            {
                *out_value = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
            }
            break;
        case 16:
            {
                *out_value = PSA_ALG_ECDH;
            }
            break;
        case 17:
            {
                *out_value = PSA_ALG_CBC_NO_PADDING;
            }
            break;
        case 18:
            {
                *out_value = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
            }
            break;
        case 19:
            {
                *out_value = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_BRAINPOOL_P_R1);
            }
            break;
        case 20:
            {
                *out_value = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_MONTGOMERY);
            }
            break;
        case 21:
            {
                *out_value = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT;
            }
            break;
        case 22:
            {
                *out_value = PSA_ERROR_NOT_PERMITTED;
            }
            break;
        case 23:
            {
                *out_value = PSA_KEY_TYPE_HMAC;
            }
            break;
        case 24:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
            }
            break;
        case 25:
            {
                *out_value = PSA_ALG_HMAC(PSA_ALG_SHA_256);
            }
            break;
        case 26:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_CRYPT;
            }
            break;
        case 27:
            {
                *out_value = PSA_VENDOR_RSA_MAX_KEY_BITS+8;
            }
            break;
        case 28:
            {
                *out_value = PSA_KEY_USAGE_ENCRYPT;
            }
            break;
        case 29:
            {
                *out_value = PSA_ALG_ECB_NO_PADDING;
            }
            break;
        case 30:
            {
                *out_value = PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 );
            }
            break;
        case 31:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH;
            }
            break;
        case 32:
            {
                *out_value = PSA_KEY_USAGE_VERIFY_HASH;
            }
            break;
        case 33:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 34:
            {
                *out_value = PSA_KEY_USAGE_SIGN_MESSAGE;
            }
            break;
        case 35:
            {
                *out_value = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
            }
            break;
        case 36:
            {
                *out_value = PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 37:
            {
                *out_value = PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 38:
            {
                *out_value = PSA_ALG_HMAC(PSA_ALG_SHA_224);
            }
            break;
        case 39:
            {
                *out_value = PSA_ALG_HMAC(PSA_ALG_ANY_HASH);
            }
            break;
        case 40:
            {
                *out_value = PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 20);
            }
            break;
        case 41:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 30);
            }
            break;
        case 42:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 20);
            }
            break;
        case 43:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 10);
            }
            break;
        case 44:
            {
                *out_value = PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_CMAC, 10);
            }
            break;
        case 45:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_CMAC, 16);
            }
            break;
        case 46:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_CMAC, 10);
            }
            break;
        case 47:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_CMAC, 8);
            }
            break;
        case 48:
            {
                *out_value = PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 31);
            }
            break;
        case 49:
            {
                *out_value = PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 32);
            }
            break;
        case 50:
            {
                *out_value = PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 33);
            }
            break;
        case 51:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_CMAC, 20);
            }
            break;
        case 52:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_224), 20);
            }
            break;
        case 53:
            {
                *out_value = PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 10);
            }
            break;
        case 54:
            {
                *out_value = PSA_ALG_CMAC;
            }
            break;
        case 55:
            {
                *out_value = PSA_KEY_USAGE_DECRYPT;
            }
            break;
        case 56:
            {
                *out_value = PSA_ALG_CCM;
            }
            break;
        case 57:
            {
                *out_value = PSA_ALG_GCM;
            }
            break;
        case 58:
            {
                *out_value = PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_CCM, 4);
            }
            break;
        case 59:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8);
            }
            break;
        case 60:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 4);
            }
            break;
        case 61:
            {
                *out_value = PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_CCM, 8);
            }
            break;
        case 62:
            {
                *out_value = PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_GCM, 4);
            }
            break;
        case 63:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 8);
            }
            break;
        case 64:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 4);
            }
            break;
        case 65:
            {
                *out_value = PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_GCM, 8);
            }
            break;
        case 66:
            {
                *out_value = PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_CCM, 16);
            }
            break;
        case 67:
            {
                *out_value = PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_CCM, 17);
            }
            break;
        case 68:
            {
                *out_value = PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256);
            }
            break;
        case 69:
            {
                *out_value = PSA_ALG_RSA_OAEP(PSA_ALG_SHA_224);
            }
            break;
        case 70:
            {
                *out_value = PSA_ALG_RSA_OAEP(PSA_ALG_ANY_HASH);
            }
            break;
        case 71:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
            }
            break;
        case 72:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE;
            }
            break;
        case 73:
            {
                *out_value = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 74:
            {
                *out_value = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
            }
            break;
        case 75:
            {
                *out_value = PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_SHA_256);
            }
            break;
        case 76:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH);
            }
            break;
        case 77:
            {
                *out_value = PSA_ALG_ECDSA(PSA_ALG_ANY_HASH);
            }
            break;
        case 78:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_384);
            }
            break;
        case 79:
            {
                *out_value = PSA_KEY_USAGE_DERIVE;
            }
            break;
        case 80:
            {
                *out_value = PSA_ALG_HKDF(PSA_ALG_SHA_256);
            }
            break;
        case 81:
            {
                *out_value = PSA_KEY_TYPE_DERIVE;
            }
            break;
        case 82:
            {
                *out_value = PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256);
            }
            break;
        case 83:
            {
                *out_value = PSA_ALG_HKDF(PSA_ALG_SHA_224);
            }
            break;
        case 84:
            {
                *out_value = PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256));
            }
            break;
        case 85:
            {
                *out_value = PSA_ALG_KEY_AGREEMENT(PSA_ALG_FFDH, PSA_ALG_HKDF(PSA_ALG_SHA_256));
            }
            break;
        case 86:
            {
                *out_value = PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_224));
            }
            break;
        case 87:
            {
                *out_value = PSA_ALG_FFDH;
            }
            break;
        case 88:
            {
                *out_value = PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
            }
            break;
        case 89:
            {
                *out_value = PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 90:
            {
                *out_value = PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 91:
            {
                *out_value = PSA_KEY_USAGE_COPY;
            }
            break;
        case 92:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 93:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_ENCRYPT;
            }
            break;
        case 94:
            {
                *out_value = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 95:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT;
            }
            break;
        case 96:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 97:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 98:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 99:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 100:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE;
            }
            break;
        case 101:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 102:
            {
                *out_value = PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 103:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE;
            }
            break;
        case 104:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 105:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_DERIVE;
            }
            break;
        case 106:
            {
                *out_value = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 107:
            {
                *out_value = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_DERIVE;
            }
            break;
        case 108:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_DERIVE;
            }
            break;
        case 109:
            {
                *out_value = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 110:
            {
                *out_value = PSA_KEY_LIFETIME_VOLATILE;
            }
            break;
        case 111:
            {
                *out_value = PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 112:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 113:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 114:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 115:
            {
                *out_value = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 116:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 24);
            }
            break;
        case 117:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 16);
            }
            break;
        case 118:
            {
                *out_value = PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 24);
            }
            break;
        case 119:
            {
                *out_value = PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 16);
            }
            break;
        case 120:
            {
                *out_value = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 121:
            {
                *out_value = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 122:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 12);
            }
            break;
        case 123:
            {
                *out_value = PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH);
            }
            break;
        case 124:
            {
                *out_value = PSA_ALG_ECDSA(PSA_ALG_SHA_224);
            }
            break;
        case 125:
            {
                *out_value = PSA_KEY_LIFETIME_PERSISTENT;
            }
            break;
        case 126:
            {
                *out_value = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_PERSISTENT, 11);
            }
            break;
        case 127:
            {
                *out_value = PSA_ALG_SHA_1;
            }
            break;
        case 128:
            {
                *out_value = PSA_ALG_SHA_224;
            }
            break;
        case 129:
            {
                *out_value = PSA_ALG_SHA_256;
            }
            break;
        case 130:
            {
                *out_value = PSA_ALG_SHA_384;
            }
            break;
        case 131:
            {
                *out_value = PSA_ALG_SHA_512;
            }
            break;
        case 132:
            {
                *out_value = PSA_ALG_MD2;
            }
            break;
        case 133:
            {
                *out_value = PSA_ALG_MD4;
            }
            break;
        case 134:
            {
                *out_value = PSA_ALG_MD5;
            }
            break;
        case 135:
            {
                *out_value = PSA_ALG_RIPEMD160;
            }
            break;
        case 136:
            {
                *out_value = PSA_ALG_CATEGORY_HASH;
            }
            break;
        case 137:
            {
                *out_value = PSA_ALG_ANY_HASH;
            }
            break;
        case 138:
            {
                *out_value = PSA_ERROR_INVALID_SIGNATURE;
            }
            break;
        case 139:
            {
                *out_value = PSA_ALG_HMAC(0);
            }
            break;
        case 140:
            {
                *out_value = PSA_ALG_HMAC(PSA_ALG_MD2);
            }
            break;
        case 141:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC( PSA_ALG_HMAC( PSA_ALG_SHA_256 ), 1 );
            }
            break;
        case 142:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC( PSA_ALG_HMAC( PSA_ALG_SHA_256 ), 33 );
            }
            break;
        case 143:
            {
                *out_value = PSA_ALG_HMAC(PSA_ALG_MD5);
            }
            break;
        case 144:
            {
                *out_value = PSA_ALG_HMAC(PSA_ALG_SHA_384);
            }
            break;
        case 145:
            {
                *out_value = PSA_ALG_HMAC(PSA_ALG_SHA_512);
            }
            break;
        case 146:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_224), 28);
            }
            break;
        case 147:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_512), 64);
            }
            break;
        case 148:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_224), 27);
            }
            break;
        case 149:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_512), 63);
            }
            break;
        case 150:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_224), 4);
            }
            break;
        case 151:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_512), 4);
            }
            break;
        case 152:
            {
                *out_value = PSA_KEY_TYPE_DES;
            }
            break;
        case 153:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_CMAC, 15);
            }
            break;
        case 154:
            {
                *out_value = PSA_ALG_TRUNCATED_MAC(PSA_ALG_CMAC, 4);
            }
            break;
        case 155:
            {
                *out_value = PSA_ALG_CATEGORY_CIPHER;
            }
            break;
        case 156:
            {
                *out_value = PSA_KEY_TYPE_ARC4;
            }
            break;
        case 157:
            {
                *out_value = PSA_ERROR_BAD_STATE;
            }
            break;
        case 158:
            {
                *out_value = PSA_ALG_STREAM_CIPHER;
            }
            break;
        case 159:
            {
                *out_value = PSA_ALG_CBC_PKCS7;
            }
            break;
        case 160:
            {
                *out_value = PSA_KEY_TYPE_CHACHA20;
            }
            break;
        case 161:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 4 );
            }
            break;
        case 162:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 6 );
            }
            break;
        case 163:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 8 );
            }
            break;
        case 164:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 10 );
            }
            break;
        case 165:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 12 );
            }
            break;
        case 166:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 14 );
            }
            break;
        case 167:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 16 );
            }
            break;
        case 168:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 );
            }
            break;
        case 169:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 2 );
            }
            break;
        case 170:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 15 );
            }
            break;
        case 171:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 18 );
            }
            break;
        case 172:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 4 );
            }
            break;
        case 173:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 15 );
            }
            break;
        case 174:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 16 );
            }
            break;
        case 175:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 8 );
            }
            break;
        case 176:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 14 );
            }
            break;
        case 177:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 13 );
            }
            break;
        case 178:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 12 );
            }
            break;
        case 179:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 );
            }
            break;
        case 180:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 2 );
            }
            break;
        case 181:
            {
                *out_value = PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 18 );
            }
            break;
        case 182:
            {
                *out_value = PSA_ALG_CHACHA20_POLY1305;
            }
            break;
        case 183:
            {
                *out_value = PSA_ALG_RSA_PSS( PSA_ALG_SHA_256 );
            }
            break;
        case 184:
            {
                *out_value = PSA_ALG_RSA_PSS_ANY_SALT( PSA_ALG_SHA_256 );
            }
            break;
        case 185:
            {
                *out_value = PSA_ALG_DETERMINISTIC_ECDSA( PSA_ALG_SHA_256 );
            }
            break;
        case 186:
            {
                *out_value = PSA_ALG_DETERMINISTIC_ECDSA( PSA_ALG_SHA_384 );
            }
            break;
        case 187:
            {
                *out_value = PSA_ALG_DETERMINISTIC_ECDSA( 0 );
            }
            break;
        case 188:
            {
                *out_value = PSA_ALG_DETERMINISTIC_ECDSA( PSA_ALG_ANY_HASH );
            }
            break;
        case 189:
            {
                *out_value = PSA_ALG_ECDSA( PSA_ALG_SHA_256 );
            }
            break;
        case 190:
            {
                *out_value = PSA_ALG_ECDSA( PSA_ALG_SHA_384 );
            }
            break;
        case 191:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_1);
            }
            break;
        case 192:
            {
                *out_value = PSA_ALG_RSA_PSS(PSA_ALG_SHA_512);
            }
            break;
        case 193:
            {
                *out_value = PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_SHA_512);
            }
            break;
        case 194:
            {
                *out_value = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
            }
            break;
        case 195:
            {
                *out_value = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384);
            }
            break;
        case 196:
            {
                *out_value = PSA_ALG_RSA_PKCS1V15_SIGN(0);
            }
            break;
        case 197:
            {
                *out_value = PSA_ALG_ECDSA(0);
            }
            break;
        case 198:
            {
                *out_value = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
            }
            break;
        case 199:
            {
                *out_value = PSA_ALG_RSA_OAEP(PSA_ALG_SHA_384);
            }
            break;
        case 200:
            {
                *out_value = PSA_ERROR_INVALID_PADDING;
            }
            break;
        case 201:
            {
                *out_value = PSA_ALG_HKDF(PSA_ALG_SHA_512);
            }
            break;
        case 202:
            {
                *out_value = PSA_ALG_HKDF(PSA_ALG_CATEGORY_HASH);
            }
            break;
        case 203:
            {
                *out_value = PSA_ALG_CATEGORY_KEY_DERIVATION;
            }
            break;
        case 204:
            {
                *out_value = PSA_KEY_DERIVATION_INPUT_SALT;
            }
            break;
        case 205:
            {
                *out_value = PSA_KEY_TYPE_NONE;
            }
            break;
        case 206:
            {
                *out_value = PSA_KEY_DERIVATION_INPUT_SECRET;
            }
            break;
        case 207:
            {
                *out_value = PSA_KEY_DERIVATION_INPUT_INFO;
            }
            break;
        case 208:
            {
                *out_value = UNUSED;
            }
            break;
        case 209:
            {
                *out_value = PSA_KEY_DERIVATION_INPUT_LABEL;
            }
            break;
        case 210:
            {
                *out_value = PSA_KEY_DERIVATION_INPUT_SEED;
            }
            break;
        case 211:
            {
                *out_value = PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256));
            }
            break;
        case 212:
            {
                *out_value = PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256);
            }
            break;
        case 213:
            {
                *out_value = PSA_ALG_HKDF(PSA_ALG_SHA_1);
            }
            break;
        case 214:
            {
                *out_value = PSA_ALG_TLS12_PRF(PSA_ALG_SHA_384);
            }
            break;
        case 215:
            {
                *out_value = PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_384);
            }
            break;
        case 216:
            {
                *out_value = 255 * PSA_HASH_LENGTH(PSA_ALG_SHA_256);
            }
            break;
        case 217:
            {
                *out_value = 255 * PSA_HASH_LENGTH(PSA_ALG_SHA_1);
            }
            break;
        case 218:
            {
                *out_value = 255 * PSA_HASH_LENGTH(PSA_ALG_SHA_256) + 1;
            }
            break;
        case 219:
            {
                *out_value = 255 * PSA_HASH_LENGTH(PSA_ALG_SHA_1) + 1;
            }
            break;
        case 220:
            {
                *out_value = 255 * PSA_HASH_LENGTH(PSA_ALG_SHA_256) - 1;
            }
            break;
        case 221:
            {
                *out_value = PSA_KEY_TYPE_CATEGORY_MASK;
            }
            break;
        case 222:
            {
                *out_value = PSA_MAX_KEY_BITS;
            }
            break;
        case 223:
            {
                *out_value = PSA_MAX_KEY_BITS + 1;
            }
            break;
        case 224:
            {
                *out_value = PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_512));
            }
            break;
        case 225:
            {
                *out_value = PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(0));
            }
            break;
        case 226:
            {
                *out_value = PSA_ALG_KEY_AGREEMENT(0, PSA_ALG_HKDF(PSA_ALG_SHA_256));
            }
            break;
        case 227:
            {
                *out_value = MBEDTLS_CTR_DRBG_MAX_REQUEST;
            }
            break;
        case 228:
            {
                *out_value = MBEDTLS_CTR_DRBG_MAX_REQUEST + 1;
            }
            break;
        case 229:
            {
                *out_value = 2 * MBEDTLS_CTR_DRBG_MAX_REQUEST + 1;
            }
            break;
        case 230:
            {
                *out_value = (MBEDTLS_CTR_DRBG_MAX_REQUEST + 1) * 8;
            }
            break;
        case 231:
            {
                *out_value = (2 * MBEDTLS_CTR_DRBG_MAX_REQUEST + 1) * 8;
            }
            break;
        case 232:
            {
                *out_value = PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT;
            }
            break;
        case 233:
            {
                *out_value = PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
            }
            break;
        case 234:
            {
                *out_value = PSA_VENDOR_RSA_MAX_KEY_BITS+1;
            }
            break;
        case 235:
            {
                *out_value = PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE;
            }
            break;
        case 236:
            {
                *out_value = IMPORT_KEY;
            }
            break;
        case 237:
            {
                *out_value = GENERATE_KEY;
            }
            break;
        case 238:
            {
                *out_value = DERIVE_KEY;
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
    
#if defined(MBEDTLS_PSA_CRYPTO_C)

        case 0:
            {
#if defined(PSA_WANT_ALG_CTR)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(PSA_WANT_KEY_TYPE_AES)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(MBEDTLS_PK_PARSE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if defined(MBEDTLS_PK_WRITE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 7:
            {
#if defined(MBEDTLS_RSA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 8:
            {
#if defined(PSA_WANT_ALG_ECDSA)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 9:
            {
#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 10:
            {
#if defined(PSA_WANT_ECC_SECP_R1_224)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 11:
            {
#if defined(PSA_WANT_ECC_SECP_R1_256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 12:
            {
#if defined(PSA_WANT_ECC_SECP_R1_384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 13:
            {
#if defined(PSA_WANT_ECC_SECP_R1_521)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 14:
            {
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 15:
            {
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 16:
            {
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 17:
            {
#if defined(PSA_WANT_ALG_ECDH)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 18:
            {
#if defined(PSA_WANT_ECC_MONTGOMERY_255)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 19:
            {
#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 20:
            {
#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 21:
            {
#if defined(PSA_WANT_ALG_HMAC)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 22:
            {
#if defined(PSA_WANT_ALG_SHA_256)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 23:
            {
#if defined(PSA_WANT_KEY_TYPE_HMAC)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 24:
            {
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 25:
            {
#if defined(MBEDTLS_MD_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 26:
            {
#if defined(MBEDTLS_PEM_PARSE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 27:
            {
#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 28:
            {
#if defined(PSA_WANT_ALG_SHA_224)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 29:
            {
#if defined(PSA_WANT_ALG_CMAC)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 30:
            {
#if defined(PSA_WANT_ALG_CCM)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 31:
            {
#if defined(PSA_WANT_ALG_GCM)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 32:
            {
#if defined(PSA_WANT_ALG_RSA_OAEP)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 33:
            {
#if defined(PSA_WANT_ALG_RSA_PSS)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 34:
            {
#if defined(PSA_WANT_ALG_SHA_384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 35:
            {
#if defined(PSA_WANT_ALG_HKDF)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 36:
            {
#if defined(PSA_WANT_ALG_TLS12_PRF)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 37:
            {
#if defined(PSA_WANT_ALG_FFDH)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 38:
            {
#if defined(MBEDTLS_ECP_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 39:
            {
#if defined(MBEDTLS_ECDH_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 40:
            {
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 41:
            {
#if defined(PSA_WANT_ALG_SHA_1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 42:
            {
#if defined(PSA_WANT_ALG_SHA_512)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 43:
            {
#if defined(PSA_WANT_ALG_MD2)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 44:
            {
#if defined(PSA_WANT_ALG_MD4)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 45:
            {
#if defined(PSA_WANT_ALG_MD5)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 46:
            {
#if defined(PSA_WANT_ALG_RIPEMD160)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 47:
            {
#if defined(MBEDTLS_SHA256_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 48:
            {
#if !defined(PSA_WANT_ALG_MD2)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 49:
            {
#if !defined(PSA_WANT_ALG_MD5)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 50:
            {
#if defined(PSA_WANT_KEY_TYPE_DES)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 51:
            {
#if defined(MBEDTLS_AES_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 52:
            {
#if defined(MBEDTLS_CIPHER_MODE_CTR)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 53:
            {
#if defined(MBEDTLS_ARC4_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 54:
            {
#if defined(PSA_WANT_KEY_TYPE_ARC4)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 55:
            {
#if defined(PSA_WANT_ALG_STREAM_CIPHER)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 56:
            {
#if defined(PSA_WANT_ALG_CBC_PKCS7)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 57:
            {
#if defined(PSA_WANT_KEY_TYPE_CHACHA20)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 58:
            {
#if defined(MBEDTLS_DES_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 59:
            {
#if defined(MBEDTLS_CCM_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 60:
            {
#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 61:
            {
#if defined(MBEDTLS_GCM_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 62:
            {
#if defined(MBEDTLS_CHACHA20_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 63:
            {
#if defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 64:
            {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 65:
            {
#if !defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 66:
            {
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 67:
            {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 68:
            {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_512)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 69:
            {
#if defined(PSA_WANT_ALG_TLS12_PSK_TO_MS)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 70:
            {
#if defined(MBEDTLS_GENPRIME)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 71:
            {
#if defined(MBEDTLS_PK_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
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

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_static_checks_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_import_with_policy_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_import_with_data_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_import_large_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_ASN1_WRITE_C)
    test_import_rsa_made_up_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_import_export_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_import_export_public_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_import_and_exercise_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_effective_key_attributes_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_check_key_policy_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_key_attributes_init_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_mac_key_policy_wrapper,
#else
    NULL,
#endif
/* Function Id: 12 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_key_policy_wrapper,
#else
    NULL,
#endif
/* Function Id: 13 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_aead_key_policy_wrapper,
#else
    NULL,
#endif
/* Function Id: 14 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_asymmetric_encryption_key_policy_wrapper,
#else
    NULL,
#endif
/* Function Id: 15 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_asymmetric_signature_key_policy_wrapper,
#else
    NULL,
#endif
/* Function Id: 16 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_key_policy_wrapper,
#else
    NULL,
#endif
/* Function Id: 17 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_agreement_key_policy_wrapper,
#else
    NULL,
#endif
/* Function Id: 18 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_key_policy_alg2_wrapper,
#else
    NULL,
#endif
/* Function Id: 19 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_raw_agreement_key_policy_wrapper,
#else
    NULL,
#endif
/* Function Id: 20 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_copy_success_wrapper,
#else
    NULL,
#endif
/* Function Id: 21 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_copy_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 22 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_hash_operation_init_wrapper,
#else
    NULL,
#endif
/* Function Id: 23 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_hash_setup_wrapper,
#else
    NULL,
#endif
/* Function Id: 24 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_hash_compute_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 25 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_hash_compare_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 26 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_hash_compute_compare_wrapper,
#else
    NULL,
#endif
/* Function Id: 27 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_256)
    test_hash_bad_order_wrapper,
#else
    NULL,
#endif
/* Function Id: 28 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_256)
    test_hash_verify_bad_args_wrapper,
#else
    NULL,
#endif
/* Function Id: 29 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_256)
    test_hash_finish_bad_args_wrapper,
#else
    NULL,
#endif
/* Function Id: 30 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_256)
    test_hash_clone_source_state_wrapper,
#else
    NULL,
#endif
/* Function Id: 31 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_256)
    test_hash_clone_target_state_wrapper,
#else
    NULL,
#endif
/* Function Id: 32 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_mac_operation_init_wrapper,
#else
    NULL,
#endif
/* Function Id: 33 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_mac_setup_wrapper,
#else
    NULL,
#endif
/* Function Id: 34 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_KEY_TYPE_HMAC) && defined(PSA_WANT_ALG_HMAC) && defined(PSA_WANT_ALG_SHA_256)
    test_mac_bad_order_wrapper,
#else
    NULL,
#endif
/* Function Id: 35 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_mac_sign_wrapper,
#else
    NULL,
#endif
/* Function Id: 36 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_mac_verify_wrapper,
#else
    NULL,
#endif
/* Function Id: 37 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_operation_init_wrapper,
#else
    NULL,
#endif
/* Function Id: 38 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_setup_wrapper,
#else
    NULL,
#endif
/* Function Id: 39 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_KEY_TYPE_AES) && defined(PSA_WANT_ALG_CBC_PKCS7)
    test_cipher_bad_order_wrapper,
#else
    NULL,
#endif
/* Function Id: 40 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_encrypt_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 41 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_alg_without_iv_wrapper,
#else
    NULL,
#endif
/* Function Id: 42 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_bad_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 43 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_encrypt_validation_wrapper,
#else
    NULL,
#endif
/* Function Id: 44 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_encrypt_multipart_wrapper,
#else
    NULL,
#endif
/* Function Id: 45 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_decrypt_multipart_wrapper,
#else
    NULL,
#endif
/* Function Id: 46 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_decrypt_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 47 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_decrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 48 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_verify_output_wrapper,
#else
    NULL,
#endif
/* Function Id: 49 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_cipher_verify_output_multipart_wrapper,
#else
    NULL,
#endif
/* Function Id: 50 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_aead_encrypt_decrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 51 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_aead_encrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 52 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_aead_decrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 53 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_signature_size_wrapper,
#else
    NULL,
#endif
/* Function Id: 54 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_sign_hash_deterministic_wrapper,
#else
    NULL,
#endif
/* Function Id: 55 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_sign_hash_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 56 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_sign_verify_hash_wrapper,
#else
    NULL,
#endif
/* Function Id: 57 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_verify_hash_wrapper,
#else
    NULL,
#endif
/* Function Id: 58 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_verify_hash_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 59 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_sign_message_deterministic_wrapper,
#else
    NULL,
#endif
/* Function Id: 60 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_sign_message_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 61 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_sign_verify_message_wrapper,
#else
    NULL,
#endif
/* Function Id: 62 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_verify_message_wrapper,
#else
    NULL,
#endif
/* Function Id: 63 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_verify_message_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 64 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_asymmetric_encrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 65 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_asymmetric_encrypt_decrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 66 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_asymmetric_decrypt_wrapper,
#else
    NULL,
#endif
/* Function Id: 67 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_asymmetric_decrypt_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 68 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_key_derivation_init_wrapper,
#else
    NULL,
#endif
/* Function Id: 69 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_setup_wrapper,
#else
    NULL,
#endif
/* Function Id: 70 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_set_capacity_wrapper,
#else
    NULL,
#endif
/* Function Id: 71 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_input_wrapper,
#else
    NULL,
#endif
/* Function Id: 72 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_over_capacity_wrapper,
#else
    NULL,
#endif
/* Function Id: 73 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_actions_without_setup_wrapper,
#else
    NULL,
#endif
/* Function Id: 74 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_output_wrapper,
#else
    NULL,
#endif
/* Function Id: 75 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_full_wrapper,
#else
    NULL,
#endif
/* Function Id: 76 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_key_exercise_wrapper,
#else
    NULL,
#endif
/* Function Id: 77 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_key_export_wrapper,
#else
    NULL,
#endif
/* Function Id: 78 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_derive_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 79 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_key_agreement_setup_wrapper,
#else
    NULL,
#endif
/* Function Id: 80 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_raw_key_agreement_wrapper,
#else
    NULL,
#endif
/* Function Id: 81 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_key_agreement_capacity_wrapper,
#else
    NULL,
#endif
/* Function Id: 82 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_key_agreement_output_wrapper,
#else
    NULL,
#endif
/* Function Id: 83 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_generate_random_wrapper,
#else
    NULL,
#endif
/* Function Id: 84 */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    test_generate_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 85 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR) && defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT) && defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN) && defined(MBEDTLS_GENPRIME)
    test_generate_key_rsa_wrapper,
#else
    NULL,
#endif
/* Function Id: 86 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_persistent_key_load_key_from_storage_wrapper,
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
    const char *default_filename = "./test_suite_psa_crypto.datax";
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
