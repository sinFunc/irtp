#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_ssl.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/main_test.function
 *      Platform code file  : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/host_test.function
 *      Helper file         : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/helpers.function
 *      Test suite file     : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function
 *      Test suite data     : /home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.data
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

#if defined(MBEDTLS_SSL_TLS_C)
#line 2 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
#include <test/ssl_helpers.h>

#include <constant_time_internal.h>

#include <test/constant_flow.h>

#line 16 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_test_callback_buffer_sanity()
{
    enum { MSGLEN = 10 };
    mbedtls_test_ssl_buffer buf;
    unsigned char input[MSGLEN];
    unsigned char output[MSGLEN];

    memset(input, 0, sizeof(input));

    /* Make sure calling put and get on NULL buffer results in error. */
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(NULL, input, sizeof(input))
                == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(NULL, output, sizeof(output))
                == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(NULL, NULL, sizeof(input))
                == -1);

    TEST_ASSERT(mbedtls_test_ssl_buffer_put(NULL, NULL, 0) == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(NULL, NULL, 0) == -1);

    /* Make sure calling put and get on a buffer that hasn't been set up results
     * in error. */
    mbedtls_test_ssl_buffer_init(&buf);

    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, input, sizeof(input))
                == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(&buf, output, sizeof(output))
                == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, NULL, sizeof(input))
                == -1);

    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, NULL, 0) == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(&buf, NULL, 0) == -1);

    /* Make sure calling put and get on NULL input only results in
     * error if the length is not zero, and that a NULL output is valid for data
     * dropping.
     */

    TEST_ASSERT(mbedtls_test_ssl_buffer_setup(&buf, sizeof(input)) == 0);

    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, NULL, sizeof(input))
                == -1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(&buf, NULL, sizeof(output))
                == 0);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, NULL, 0) == 0);
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(&buf, NULL, 0) == 0);

    /* Make sure calling put several times in the row is safe */

    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, input, sizeof(input))
                == sizeof(input));
    TEST_ASSERT(mbedtls_test_ssl_buffer_get(&buf, output, 2) == 2);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, input, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, input, 2) == 1);
    TEST_ASSERT(mbedtls_test_ssl_buffer_put(&buf, input, 2) == 0);


exit:

    mbedtls_test_ssl_buffer_free(&buf);
}

void test_test_callback_buffer_sanity_wrapper( void ** params )
{
    (void)params;

    test_test_callback_buffer_sanity(  );
}
#line 94 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_test_callback_buffer(int size, int put1, int put1_ret,
                          int get1, int get1_ret, int put2, int put2_ret,
                          int get2, int get2_ret)
{
    enum { ROUNDS = 2 };
    size_t put[ROUNDS];
    int put_ret[ROUNDS];
    size_t get[ROUNDS];
    int get_ret[ROUNDS];
    mbedtls_test_ssl_buffer buf;
    unsigned char *input = NULL;
    size_t input_len;
    unsigned char *output = NULL;
    size_t output_len;
    size_t i, j, written, read;

    mbedtls_test_ssl_buffer_init(&buf);
    TEST_ASSERT(mbedtls_test_ssl_buffer_setup(&buf, size) == 0);

    /* Check the sanity of input parameters and initialise local variables. That
     * is, ensure that the amount of data is not negative and that we are not
     * expecting more to put or get than we actually asked for. */
    TEST_ASSERT(put1 >= 0);
    put[0] = put1;
    put_ret[0] = put1_ret;
    TEST_ASSERT(put1_ret <= put1);
    TEST_ASSERT(put2 >= 0);
    put[1] = put2;
    put_ret[1] = put2_ret;
    TEST_ASSERT(put2_ret <= put2);

    TEST_ASSERT(get1 >= 0);
    get[0] = get1;
    get_ret[0] = get1_ret;
    TEST_ASSERT(get1_ret <= get1);
    TEST_ASSERT(get2 >= 0);
    get[1] = get2;
    get_ret[1] = get2_ret;
    TEST_ASSERT(get2_ret <= get2);

    input_len = 0;
    /* Calculate actual input and output lengths */
    for (j = 0; j < ROUNDS; j++) {
        if (put_ret[j] > 0) {
            input_len += put_ret[j];
        }
    }
    /* In order to always have a valid pointer we always allocate at least 1
     * byte. */
    if (input_len == 0) {
        input_len = 1;
    }
    ASSERT_ALLOC(input, input_len);

    output_len = 0;
    for (j = 0; j < ROUNDS; j++) {
        if (get_ret[j] > 0) {
            output_len += get_ret[j];
        }
    }
    TEST_ASSERT(output_len <= input_len);
    /* In order to always have a valid pointer we always allocate at least 1
     * byte. */
    if (output_len == 0) {
        output_len = 1;
    }
    ASSERT_ALLOC(output, output_len);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < input_len; i++) {
        input[i] = i & 0xFF;
    }

    written = read = 0;
    for (j = 0; j < ROUNDS; j++) {
        TEST_ASSERT(put_ret[j] == mbedtls_test_ssl_buffer_put(&buf,
                                                              input + written, put[j]));
        written += put_ret[j];
        TEST_ASSERT(get_ret[j] == mbedtls_test_ssl_buffer_get(&buf,
                                                              output + read, get[j]));
        read += get_ret[j];
        TEST_ASSERT(read <= written);
        if (get_ret[j] > 0) {
            TEST_ASSERT(memcmp(output + read - get_ret[j],
                               input + read - get_ret[j], get_ret[j])
                        == 0);
        }
    }

exit:

    mbedtls_free(input);
    mbedtls_free(output);
    mbedtls_test_ssl_buffer_free(&buf);
}

void test_test_callback_buffer_wrapper( void ** params )
{

    test_test_callback_buffer( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ), *( (int *) params[6] ), *( (int *) params[7] ), *( (int *) params[8] ) );
}
#line 198 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_mock_sanity()
{
    enum { MSGLEN = 105 };
    unsigned char message[MSGLEN] = { 0 };
    unsigned char received[MSGLEN] = { 0 };
    mbedtls_test_mock_socket socket;

    mbedtls_mock_socket_init(&socket);
    TEST_ASSERT(mbedtls_test_mock_tcp_send_b(&socket, message, MSGLEN) < 0);
    mbedtls_test_mock_socket_close(&socket);
    mbedtls_mock_socket_init(&socket);
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_b(&socket, received, MSGLEN) < 0);
    mbedtls_test_mock_socket_close(&socket);

    mbedtls_mock_socket_init(&socket);
    TEST_ASSERT(mbedtls_test_mock_tcp_send_nb(&socket, message, MSGLEN) < 0);
    mbedtls_test_mock_socket_close(&socket);
    mbedtls_mock_socket_init(&socket);
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_nb(&socket, received, MSGLEN) < 0);
    mbedtls_test_mock_socket_close(&socket);

exit:

    mbedtls_test_mock_socket_close(&socket);
}

void test_ssl_mock_sanity_wrapper( void ** params )
{
    (void)params;

    test_ssl_mock_sanity(  );
}
#line 231 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_mock_tcp(int blocking)
{
    enum { MSGLEN = 105 };
    enum { BUFLEN = MSGLEN / 5 };
    unsigned char message[MSGLEN];
    unsigned char received[MSGLEN];
    mbedtls_test_mock_socket client;
    mbedtls_test_mock_socket server;
    size_t written, read;
    int send_ret, recv_ret;
    mbedtls_ssl_send_t *send;
    mbedtls_ssl_recv_t *recv;
    unsigned i;

    if (blocking == 0) {
        send = mbedtls_test_mock_tcp_send_nb;
        recv = mbedtls_test_mock_tcp_recv_nb;
    } else {
        send = mbedtls_test_mock_tcp_send_b;
        recv = mbedtls_test_mock_tcp_recv_b;
    }

    mbedtls_mock_socket_init(&client);
    mbedtls_mock_socket_init(&server);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }

    /* Make sure that sending a message takes a few  iterations. */
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server, BUFLEN));

    /* Send the message to the server */
    send_ret = recv_ret = 1;
    written = read = 0;
    while (send_ret != 0 || recv_ret != 0) {
        send_ret = send(&client, message + written, MSGLEN - written);

        TEST_ASSERT(send_ret >= 0);
        TEST_ASSERT(send_ret <= BUFLEN);
        written += send_ret;

        /* If the buffer is full we can test blocking and non-blocking send */
        if (send_ret == BUFLEN) {
            int blocking_ret = send(&client, message, 1);
            if (blocking) {
                TEST_ASSERT(blocking_ret == 0);
            } else {
                TEST_ASSERT(blocking_ret == MBEDTLS_ERR_SSL_WANT_WRITE);
            }
        }

        recv_ret = recv(&server, received + read, MSGLEN - read);

        /* The result depends on whether any data was sent */
        if (send_ret > 0) {
            TEST_ASSERT(recv_ret > 0);
            TEST_ASSERT(recv_ret <= BUFLEN);
            read += recv_ret;
        } else if (blocking) {
            TEST_ASSERT(recv_ret == 0);
        } else {
            TEST_ASSERT(recv_ret == MBEDTLS_ERR_SSL_WANT_READ);
            recv_ret = 0;
        }

        /* If the buffer is empty we can test blocking and non-blocking read */
        if (recv_ret == BUFLEN) {
            int blocking_ret = recv(&server, received, 1);
            if (blocking) {
                TEST_ASSERT(blocking_ret == 0);
            } else {
                TEST_ASSERT(blocking_ret == MBEDTLS_ERR_SSL_WANT_READ);
            }
        }
    }
    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

exit:

    mbedtls_test_mock_socket_close(&client);
    mbedtls_test_mock_socket_close(&server);
}

void test_ssl_mock_tcp_wrapper( void ** params )
{

    test_ssl_mock_tcp( *( (int *) params[0] ) );
}
#line 325 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_mock_tcp_interleaving(int blocking)
{
    enum { ROUNDS = 2 };
    enum { MSGLEN = 105 };
    enum { BUFLEN = MSGLEN / 5 };
    unsigned char message[ROUNDS][MSGLEN];
    unsigned char received[ROUNDS][MSGLEN];
    mbedtls_test_mock_socket client;
    mbedtls_test_mock_socket server;
    size_t written[ROUNDS];
    size_t read[ROUNDS];
    int send_ret[ROUNDS];
    int recv_ret[ROUNDS];
    unsigned i, j, progress;
    mbedtls_ssl_send_t *send;
    mbedtls_ssl_recv_t *recv;

    if (blocking == 0) {
        send = mbedtls_test_mock_tcp_send_nb;
        recv = mbedtls_test_mock_tcp_recv_nb;
    } else {
        send = mbedtls_test_mock_tcp_send_b;
        recv = mbedtls_test_mock_tcp_recv_b;
    }

    mbedtls_mock_socket_init(&client);
    mbedtls_mock_socket_init(&server);

    /* Fill up the buffers with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < ROUNDS; i++) {
        for (j = 0; j < MSGLEN; j++) {
            message[i][j] = (i * MSGLEN + j) & 0xFF;
        }
    }

    /* Make sure that sending a message takes a few  iterations. */
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      BUFLEN));

    /* Send the message from both sides, interleaving. */
    progress = 1;
    for (i = 0; i < ROUNDS; i++) {
        written[i] = 0;
        read[i] = 0;
    }
    /* This loop does not stop as long as there was a successful write or read
     * of at least one byte on either side. */
    while (progress != 0) {
        mbedtls_test_mock_socket *socket;

        for (i = 0; i < ROUNDS; i++) {
            /* First sending is from the client */
            socket = (i % 2 == 0) ? (&client) : (&server);

            send_ret[i] = send(socket, message[i] + written[i],
                               MSGLEN - written[i]);
            TEST_ASSERT(send_ret[i] >= 0);
            TEST_ASSERT(send_ret[i] <= BUFLEN);
            written[i] += send_ret[i];

            /* If the buffer is full we can test blocking and non-blocking
             * send */
            if (send_ret[i] == BUFLEN) {
                int blocking_ret = send(socket, message[i], 1);
                if (blocking) {
                    TEST_ASSERT(blocking_ret == 0);
                } else {
                    TEST_ASSERT(blocking_ret == MBEDTLS_ERR_SSL_WANT_WRITE);
                }
            }
        }

        for (i = 0; i < ROUNDS; i++) {
            /* First receiving is from the server */
            socket = (i % 2 == 0) ? (&server) : (&client);

            recv_ret[i] = recv(socket, received[i] + read[i],
                               MSGLEN - read[i]);

            /* The result depends on whether any data was sent */
            if (send_ret[i] > 0) {
                TEST_ASSERT(recv_ret[i] > 0);
                TEST_ASSERT(recv_ret[i] <= BUFLEN);
                read[i] += recv_ret[i];
            } else if (blocking) {
                TEST_ASSERT(recv_ret[i] == 0);
            } else {
                TEST_ASSERT(recv_ret[i] == MBEDTLS_ERR_SSL_WANT_READ);
                recv_ret[i] = 0;
            }

            /* If the buffer is empty we can test blocking and non-blocking
             * read */
            if (recv_ret[i] == BUFLEN) {
                int blocking_ret = recv(socket, received[i], 1);
                if (blocking) {
                    TEST_ASSERT(blocking_ret == 0);
                } else {
                    TEST_ASSERT(blocking_ret == MBEDTLS_ERR_SSL_WANT_READ);
                }
            }
        }

        progress = 0;
        for (i = 0; i < ROUNDS; i++) {
            progress += send_ret[i] + recv_ret[i];
        }
    }

    for (i = 0; i < ROUNDS; i++) {
        TEST_ASSERT(memcmp(message[i], received[i], MSGLEN) == 0);
    }

exit:

    mbedtls_test_mock_socket_close(&client);
    mbedtls_test_mock_socket_close(&server);
}

void test_ssl_mock_tcp_interleaving_wrapper( void ** params )
{

    test_ssl_mock_tcp_interleaving( *( (int *) params[0] ) );
}
#line 447 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_queue_sanity()
{
    mbedtls_test_ssl_message_queue queue;

    /* Trying to push/pull to an empty queue */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(NULL, 1)
                == MBEDTLS_TEST_ERROR_ARG_NULL);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(NULL, 1)
                == MBEDTLS_TEST_ERROR_ARG_NULL);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_setup(&queue, 3) == 0);
    TEST_ASSERT(queue.capacity == 3);
    TEST_ASSERT(queue.num == 0);

exit:
    mbedtls_test_ssl_message_queue_free(&queue);
}

void test_ssl_message_queue_sanity_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_queue_sanity(  );
}
#line 467 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_queue_basic()
{
    mbedtls_test_ssl_message_queue queue;

    TEST_ASSERT(mbedtls_test_ssl_message_queue_setup(&queue, 3) == 0);

    /* Sanity test - 3 pushes and 3 pops with sufficient space */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);
    TEST_ASSERT(queue.capacity == 3);
    TEST_ASSERT(queue.num == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);
    TEST_ASSERT(queue.capacity == 3);
    TEST_ASSERT(queue.num == 2);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 2) == 2);
    TEST_ASSERT(queue.capacity == 3);
    TEST_ASSERT(queue.num == 3);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 2) == 2);

exit:
    mbedtls_test_ssl_message_queue_free(&queue);
}

void test_ssl_message_queue_basic_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_queue_basic(  );
}
#line 494 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_queue_overflow_underflow()
{
    mbedtls_test_ssl_message_queue queue;

    TEST_ASSERT(mbedtls_test_ssl_message_queue_setup(&queue, 3) == 0);

    /* 4 pushes (last one with an error), 4 pops (last one with an error) */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 2) == 2);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 3)
                == MBEDTLS_ERR_SSL_WANT_WRITE);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 2) == 2);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1)
                == MBEDTLS_ERR_SSL_WANT_READ);

exit:
    mbedtls_test_ssl_message_queue_free(&queue);
}

void test_ssl_message_queue_overflow_underflow_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_queue_overflow_underflow(  );
}
#line 520 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_queue_interleaved()
{
    mbedtls_test_ssl_message_queue queue;

    TEST_ASSERT(mbedtls_test_ssl_message_queue_setup(&queue, 3) == 0);

    /* Interleaved test - [2 pushes, 1 pop] twice, and then two pops
     * (to wrap around the buffer) */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 1) == 1);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 2) == 2);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 3) == 3);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 1) == 1);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 2) == 2);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 5) == 5);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, 8) == 8);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 3) == 3);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 5) == 5);

    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, 8) == 8);

exit:
    mbedtls_test_ssl_message_queue_free(&queue);
}

void test_ssl_message_queue_interleaved_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_queue_interleaved(  );
}
#line 554 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_queue_insufficient_buffer()
{
    mbedtls_test_ssl_message_queue queue;
    size_t message_len = 10;
    size_t buffer_len = 5;

    TEST_ASSERT(mbedtls_test_ssl_message_queue_setup(&queue, 1) == 0);

    /* Popping without a sufficient buffer */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&queue, message_len)
                == (int) message_len);
    TEST_ASSERT(mbedtls_test_ssl_message_queue_pop_info(&queue, buffer_len)
                == (int) buffer_len);
exit:
    mbedtls_test_ssl_message_queue_free(&queue);
}

void test_ssl_message_queue_insufficient_buffer_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_queue_insufficient_buffer(  );
}
#line 573 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_uninitialized()
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN] = { 0 }, received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;
    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);

    /* Send with a NULL context */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(NULL, message, MSGLEN)
                == MBEDTLS_TEST_ERROR_CONTEXT_ERROR);

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(NULL, message, MSGLEN)
                == MBEDTLS_TEST_ERROR_CONTEXT_ERROR);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 1,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 1,
                                                  &client,
                                                  &client_context) == 0);

    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MBEDTLS_TEST_ERROR_SEND_FAILED);

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_READ);

    /* Push directly to a queue to later simulate a disconnected behavior */
    TEST_ASSERT(mbedtls_test_ssl_message_queue_push_info(&server_queue,
                                                         MSGLEN)
                == MSGLEN);

    /* Test if there's an error when trying to read from a disconnected
     * socket */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_TEST_ERROR_RECV_FAILED);
exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
}

void test_ssl_message_mock_uninitialized_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_uninitialized(  );
}
#line 625 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_basic()
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;
    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 1,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 1,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN));

    /* Send the message to the server */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MSGLEN);

    /* Read from the server */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);
    memset(received, 0, MSGLEN);

    /* Send the message to the client */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&server_context, message,
                                               MSGLEN) == MSGLEN);

    /* Read from the client */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&client_context, received,
                                               MSGLEN)
                == MSGLEN);
    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
}

void test_ssl_message_mock_basic_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_basic(  );
}
#line 684 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_queue_overflow_underflow()
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;
    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 2,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 2,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN*2));

    /* Send three message to the server, last one with an error */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN - 1)
                == MSGLEN - 1);

    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_WRITE);

    /* Read three messages from the server, last one with an error */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN - 1)
                == MSGLEN - 1);

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_READ);

exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
}

void test_ssl_message_mock_queue_overflow_underflow_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_queue_overflow_underflow(  );
}
#line 748 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_socket_overflow()
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;
    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 2,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 2,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN));

    /* Send two message to the server, second one with an error */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MBEDTLS_TEST_ERROR_SEND_FAILED);

    /* Read the only message from the server */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
}

void test_ssl_message_mock_socket_overflow_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_socket_overflow(  );
}
#line 800 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_truncated()
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;
    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 2,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 2,
                                                  &client,
                                                  &client_context) == 0);

    memset(received, 0, MSGLEN);
    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      2 * MSGLEN));

    /* Send two messages to the server, the second one small enough to fit in the
     * receiver's buffer. */
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MSGLEN);
    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN / 2)
                == MSGLEN / 2);
    /* Read a truncated message from the server */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN/2)
                == MSGLEN/2);

    /* Test that the first half of the message is valid, and second one isn't */
    TEST_ASSERT(memcmp(message, received, MSGLEN/2) == 0);
    TEST_ASSERT(memcmp(message + MSGLEN/2, received + MSGLEN/2, MSGLEN/2)
                != 0);
    memset(received, 0, MSGLEN);

    /* Read a full message from the server */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN/2)
                == MSGLEN / 2);

    /* Test that the first half of the message is valid */
    TEST_ASSERT(memcmp(message, received, MSGLEN/2) == 0);

exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
}

void test_ssl_message_mock_truncated_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_truncated(  );
}
#line 864 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_socket_read_error()
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;
    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 1,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 1,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN));

    TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                               MSGLEN)
                == MSGLEN);

    /* Force a read error by disconnecting the socket by hand */
    server.status = 0;
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_TEST_ERROR_RECV_FAILED);
    /* Return to a valid state */
    server.status = MBEDTLS_MOCK_SOCKET_CONNECTED;

    memset(received, 0, sizeof(received));

    /* Test that even though the server tried to read once disconnected, the
     * continuity is preserved */
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MSGLEN);

    TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
}

void test_ssl_message_mock_socket_read_error_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_socket_read_error(  );
}
#line 922 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_interleaved_one_way()
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;
    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 3,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 3,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN*3));

    /* Interleaved test - [2 sends, 1 read] twice, and then two reads
     * (to wrap around the buffer) */
    for (i = 0; i < 2; i++) {
        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                                   MSGLEN) == MSGLEN);
        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);
        memset(received, 0, sizeof(received));
    }

    for (i = 0; i < 2; i++) {
        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);
    }
    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_READ);
exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
}

void test_ssl_message_mock_interleaved_one_way_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_interleaved_one_way(  );
}
#line 982 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_message_mock_interleaved_two_ways()
{
    enum { MSGLEN = 10 };
    unsigned char message[MSGLEN], received[MSGLEN];
    mbedtls_test_mock_socket client, server;
    unsigned i;
    mbedtls_test_ssl_message_queue server_queue, client_queue;
    mbedtls_test_message_socket_context server_context, client_context;
    mbedtls_test_message_socket_init(&server_context);
    mbedtls_test_message_socket_init(&client_context);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&server_queue,
                                                  &client_queue, 3,
                                                  &server,
                                                  &server_context) == 0);

    TEST_ASSERT(mbedtls_test_message_socket_setup(&client_queue,
                                                  &server_queue, 3,
                                                  &client,
                                                  &client_context) == 0);

    /* Fill up the buffer with structured data so that unwanted changes
     * can be detected */
    for (i = 0; i < MSGLEN; i++) {
        message[i] = i & 0xFF;
    }
    TEST_ASSERT(0 == mbedtls_test_mock_socket_connect(&client, &server,
                                                      MSGLEN*3));

    /* Interleaved test - [2 sends, 1 read] twice, both ways, and then two reads
     * (to wrap around the buffer) both ways. */
    for (i = 0; i < 2; i++) {
        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&client_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&server_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_send_msg(&server_context, message,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

        memset(received, 0, sizeof(received));

        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&client_context, received,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);

        memset(received, 0, sizeof(received));
    }

    for (i = 0; i < 2; i++) {
        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);
        memset(received, 0, sizeof(received));

        TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&client_context, received,
                                                   MSGLEN) == MSGLEN);

        TEST_ASSERT(memcmp(message, received, MSGLEN) == 0);
        memset(received, 0, sizeof(received));
    }

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&server_context, received,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_READ);

    TEST_ASSERT(mbedtls_test_mock_tcp_recv_msg(&client_context, received,
                                               MSGLEN)
                == MBEDTLS_ERR_SSL_WANT_READ);
exit:
    mbedtls_test_message_socket_close(&server_context);
    mbedtls_test_message_socket_close(&client_context);
}

void test_ssl_message_mock_interleaved_two_ways_wrapper( void ** params )
{
    (void)params;

    test_ssl_message_mock_interleaved_two_ways(  );
}
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
#line 1069 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_dtls_replay(data_t *prevs, data_t *new, int ret)
{
    uint32_t len = 0;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    TEST_ASSERT(mbedtls_ssl_config_defaults(&conf,
                                            MBEDTLS_SSL_IS_CLIENT,
                                            MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT) == 0);
    TEST_ASSERT(mbedtls_ssl_setup(&ssl, &conf) == 0);

    /* Read previous record numbers */
    for (len = 0; len < prevs->len; len += 6) {
        memcpy(ssl.in_ctr + 2, prevs->x + len, 6);
        mbedtls_ssl_dtls_replay_update(&ssl);
    }

    /* Check new number */
    memcpy(ssl.in_ctr + 2, new->x, 6);
    TEST_ASSERT(mbedtls_ssl_dtls_replay_check(&ssl) == ret);

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
exit:
    ;
}

void test_ssl_dtls_replay_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};

    test_ssl_dtls_replay( &data0, &data2, *( (int *) params[4] ) );
}
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#line 1100 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_set_hostname_twice(char *hostname0, char *hostname1)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);

    TEST_ASSERT(mbedtls_ssl_set_hostname(&ssl, hostname0) == 0);
    TEST_ASSERT(mbedtls_ssl_set_hostname(&ssl, hostname1) == 0);

    mbedtls_ssl_free(&ssl);
exit:
    ;
}

void test_ssl_set_hostname_twice_wrapper( void ** params )
{

    test_ssl_set_hostname_twice( (char *) params[0], (char *) params[1] );
}
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#line 1113 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_crypt_record(int cipher_type, int hash_id,
                      int etm, int tag_mode, int ver,
                      int cid0_len, int cid1_len)
{
    /*
     * Test several record encryptions and decryptions
     * with plenty of space before and after the data
     * within the record buffer.
     */

    int ret;
    int num_records = 16;
    mbedtls_ssl_context ssl; /* ONLY for debugging */

    mbedtls_ssl_transform t0, t1;
    unsigned char *buf = NULL;
    size_t const buflen = 512;
    mbedtls_record rec, rec_backup;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_transform_init(&t0);
    mbedtls_ssl_transform_init(&t1);
    TEST_ASSERT(mbedtls_test_ssl_build_transforms(&t0, &t1, cipher_type, hash_id,
                                                  etm, tag_mode, ver,
                                                  (size_t) cid0_len,
                                                  (size_t) cid1_len) == 0);

    TEST_ASSERT((buf = mbedtls_calloc(1, buflen)) != NULL);

    while (num_records-- > 0) {
        mbedtls_ssl_transform *t_dec, *t_enc;
        /* Take turns in who's sending and who's receiving. */
        if (num_records % 3 == 0) {
            t_dec = &t0;
            t_enc = &t1;
        } else {
            t_dec = &t1;
            t_enc = &t0;
        }

        /*
         * The record header affects the transformation in two ways:
         * 1) It determines the AEAD additional data
         * 2) The record counter sometimes determines the IV.
         *
         * Apart from that, the fields don't have influence.
         * In particular, it is currently not the responsibility
         * of ssl_encrypt/decrypt_buf to check if the transform
         * version matches the record version, or that the
         * type is sensible.
         */

        memset(rec.ctr, num_records, sizeof(rec.ctr));
        rec.type    = 42;
        rec.ver[0]  = num_records;
        rec.ver[1]  = num_records;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        rec.cid_len = 0;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

        rec.buf     = buf;
        rec.buf_len = buflen;
        rec.data_offset = 16;
        /* Make sure to vary the length to exercise different
         * paddings. */
        rec.data_len = 1 + num_records;

        memset(rec.buf + rec.data_offset, 42, rec.data_len);

        /* Make a copy for later comparison */
        rec_backup = rec;

        /* Encrypt record */
        ret = mbedtls_ssl_encrypt_buf(&ssl, t_enc, &rec,
                                      mbedtls_test_rnd_std_rand, NULL);
        TEST_ASSERT(ret == 0 || ret == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
        if (ret != 0) {
            continue;
        }

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        if (rec.cid_len != 0) {
            /* DTLS 1.2 + CID hides the real content type and
             * uses a special CID content type in the protected
             * record. Double-check this. */
            TEST_ASSERT(rec.type == MBEDTLS_SSL_MSG_CID);
        }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
        if (t_enc->minor_ver == MBEDTLS_SSL_MINOR_VERSION_4) {
            /* TLS 1.3 hides the real content type and
             * always uses Application Data as the content type
             * for protected records. Double-check this. */
            TEST_ASSERT(rec.type == MBEDTLS_SSL_MSG_APPLICATION_DATA);
        }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

        /* Decrypt record with t_dec */
        ret = mbedtls_ssl_decrypt_buf(&ssl, t_dec, &rec);
        TEST_ASSERT(ret == 0);

        /* Compare results */
        TEST_ASSERT(rec.type == rec_backup.type);
        TEST_ASSERT(memcmp(rec.ctr, rec_backup.ctr, 8) == 0);
        TEST_ASSERT(rec.ver[0] == rec_backup.ver[0]);
        TEST_ASSERT(rec.ver[1] == rec_backup.ver[1]);
        TEST_ASSERT(rec.data_len == rec_backup.data_len);
        TEST_ASSERT(rec.data_offset == rec_backup.data_offset);
        TEST_ASSERT(memcmp(rec.buf + rec.data_offset,
                           rec_backup.buf + rec_backup.data_offset,
                           rec.data_len) == 0);
    }

exit:

    /* Cleanup */
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_transform_free(&t0);
    mbedtls_ssl_transform_free(&t1);

    mbedtls_free(buf);
}

void test_ssl_crypt_record_wrapper( void ** params )
{

    test_ssl_crypt_record( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ), *( (int *) params[6] ) );
}
#line 1239 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_crypt_record_small(int cipher_type, int hash_id,
                            int etm, int tag_mode, int ver,
                            int cid0_len, int cid1_len)
{
    /*
     * Test pairs of encryption and decryption with an increasing
     * amount of space in the record buffer - in more detail:
     * 1) Try to encrypt with 0, 1, 2, ... bytes available
     *    in front of the plaintext, and expect the encryption
     *    to succeed starting from some offset. Always keep
     *    enough space in the end of the buffer.
     * 2) Try to encrypt with 0, 1, 2, ... bytes available
     *    at the end of the plaintext, and expect the encryption
     *    to succeed starting from some offset. Always keep
     *    enough space at the beginning of the buffer.
     * 3) Try to encrypt with 0, 1, 2, ... bytes available
     *    both at the front and end of the plaintext,
     *    and expect the encryption to succeed starting from
     *    some offset.
     *
     * If encryption succeeds, check that decryption succeeds
     * and yields the original record.
     */

    mbedtls_ssl_context ssl; /* ONLY for debugging */

    mbedtls_ssl_transform t0, t1;
    unsigned char *buf = NULL;
    size_t const buflen = 256;
    mbedtls_record rec, rec_backup;

    int ret;
    int mode;              /* Mode 1, 2 or 3 as explained above     */
    size_t offset;         /* Available space at beginning/end/both */
    size_t threshold = 96; /* Maximum offset to test against        */

    size_t default_pre_padding  = 64;  /* Pre-padding to use in mode 2  */
    size_t default_post_padding = 128; /* Post-padding to use in mode 1 */

    int seen_success; /* Indicates if in the current mode we've
                       * already seen a successful test. */

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_transform_init(&t0);
    mbedtls_ssl_transform_init(&t1);
    TEST_ASSERT(mbedtls_test_ssl_build_transforms(&t0, &t1, cipher_type, hash_id,
                                                  etm, tag_mode, ver,
                                                  (size_t) cid0_len,
                                                  (size_t) cid1_len) == 0);

    TEST_ASSERT((buf = mbedtls_calloc(1, buflen)) != NULL);

    for (mode = 1; mode <= 3; mode++) {
        seen_success = 0;
        for (offset = 0; offset <= threshold; offset++) {
            mbedtls_ssl_transform *t_dec, *t_enc;
            t_dec = &t0;
            t_enc = &t1;

            memset(rec.ctr, offset, sizeof(rec.ctr));
            rec.type    = 42;
            rec.ver[0]  = offset;
            rec.ver[1]  = offset;
            rec.buf     = buf;
            rec.buf_len = buflen;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
            rec.cid_len = 0;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

            switch (mode) {
                case 1: /* Space in the beginning */
                    rec.data_offset = offset;
                    rec.data_len = buflen - offset - default_post_padding;
                    break;

                case 2: /* Space in the end */
                    rec.data_offset = default_pre_padding;
                    rec.data_len = buflen - default_pre_padding - offset;
                    break;

                case 3: /* Space in the beginning and end */
                    rec.data_offset = offset;
                    rec.data_len = buflen - 2 * offset;
                    break;

                default:
                    TEST_ASSERT(0);
                    break;
            }

            memset(rec.buf + rec.data_offset, 42, rec.data_len);

            /* Make a copy for later comparison */
            rec_backup = rec;

            /* Encrypt record */
            ret = mbedtls_ssl_encrypt_buf(&ssl, t_enc, &rec,
                                          mbedtls_test_rnd_std_rand, NULL);

            if ((mode == 1 || mode == 2) && seen_success) {
                TEST_ASSERT(ret == 0);
            } else {
                TEST_ASSERT(ret == 0 || ret == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
                if (ret == 0) {
                    seen_success = 1;
                }
            }

            if (ret != 0) {
                continue;
            }

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
            if (rec.cid_len != 0) {
                /* DTLS 1.2 + CID hides the real content type and
                 * uses a special CID content type in the protected
                 * record. Double-check this. */
                TEST_ASSERT(rec.type == MBEDTLS_SSL_MSG_CID);
            }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
            if (t_enc->minor_ver == MBEDTLS_SSL_MINOR_VERSION_4) {
                /* TLS 1.3 hides the real content type and
                 * always uses Application Data as the content type
                 * for protected records. Double-check this. */
                TEST_ASSERT(rec.type == MBEDTLS_SSL_MSG_APPLICATION_DATA);
            }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

            /* Decrypt record with t_dec */
            TEST_ASSERT(mbedtls_ssl_decrypt_buf(&ssl, t_dec, &rec) == 0);

            /* Compare results */
            TEST_ASSERT(rec.type == rec_backup.type);
            TEST_ASSERT(memcmp(rec.ctr, rec_backup.ctr, 8) == 0);
            TEST_ASSERT(rec.ver[0] == rec_backup.ver[0]);
            TEST_ASSERT(rec.ver[1] == rec_backup.ver[1]);
            TEST_ASSERT(rec.data_len == rec_backup.data_len);
            TEST_ASSERT(rec.data_offset == rec_backup.data_offset);
            TEST_ASSERT(memcmp(rec.buf + rec.data_offset,
                               rec_backup.buf + rec_backup.data_offset,
                               rec.data_len) == 0);
        }

        TEST_ASSERT(seen_success == 1);
    }

exit:

    /* Cleanup */
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_transform_free(&t0);
    mbedtls_ssl_transform_free(&t1);

    mbedtls_free(buf);
}

void test_ssl_crypt_record_small_wrapper( void ** params )
{

    test_ssl_crypt_record_small( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ), *( (int *) params[6] ) );
}
#if defined(MBEDTLS_CIPHER_MODE_CBC)
#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#line 1399 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_decrypt_non_etm_cbc(int cipher_type, int hash_id, int trunc_hmac,
                             int length_selector)
{
    /*
     * Test record decryption for CBC without EtM, focused on the verification
     * of padding and MAC.
     *
     * Actually depends on TLS >= 1.0 (SSL 3.0 computes the MAC differently),
     * and either AES, ARIA, Camellia or DES, but since the test framework
     * doesn't support alternation in dependency statements, just depend on
     * TLS 1.2 and AES.
     *
     * The length_selector argument is interpreted as follows:
     * - if it's -1, the plaintext length is 0 and minimal padding is applied
     * - if it's -2, the plaintext length is 0 and maximal padding is applied
     * - otherwise it must be in [0, 255] and is padding_length from RFC 5246:
     *   it's the length of the rest of the padding, that is, excluding the
     *   byte that encodes the length. The minimal non-zero plaintext length
     *   that gives this padding_length is automatically selected.
     */
    mbedtls_ssl_context ssl; /* ONLY for debugging */
    mbedtls_ssl_transform t0, t1;
    mbedtls_record rec, rec_save;
    unsigned char *buf = NULL, *buf_save = NULL;
    size_t buflen, olen = 0;
    size_t plaintext_len, block_size, i;
    unsigned char padlen; /* excluding the padding_length byte */
    unsigned char add_data[13];
    unsigned char mac[MBEDTLS_MD_MAX_SIZE];
    int exp_ret;
    const unsigned char pad_max_len = 255; /* Per the standard */

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_transform_init(&t0);
    mbedtls_ssl_transform_init(&t1);

    /* Set up transforms with dummy keys */
    TEST_ASSERT(mbedtls_test_ssl_build_transforms(&t0, &t1, cipher_type, hash_id,
                                                  0, trunc_hmac,
                                                  MBEDTLS_SSL_MINOR_VERSION_3,
                                                  0, 0) == 0);

    /* Determine padding/plaintext length */
    TEST_ASSERT(length_selector >= -2 && length_selector <= 255);
    block_size = t0.ivlen;
    if (length_selector < 0) {
        plaintext_len = 0;

        /* Minimal padding
         * The +1 is for the padding_length byte, not counted in padlen. */
        padlen = block_size - (t0.maclen + 1) % block_size;

        /* Maximal padding? */
        if (length_selector == -2) {
            padlen += block_size * ((pad_max_len - padlen) / block_size);
        }
    } else {
        padlen = length_selector;

        /* Minimal non-zero plaintext_length giving desired padding.
         * The +1 is for the padding_length byte, not counted in padlen. */
        plaintext_len = block_size - (padlen + t0.maclen + 1) % block_size;
    }

    /* Prepare a buffer for record data */
    buflen = block_size
             + plaintext_len
             + t0.maclen
             + padlen + 1;
    ASSERT_ALLOC(buf, buflen);
    ASSERT_ALLOC(buf_save, buflen);

    /* Prepare a dummy record header */
    memset(rec.ctr, 0, sizeof(rec.ctr));
    rec.type    = MBEDTLS_SSL_MSG_APPLICATION_DATA;
    rec.ver[0]  = MBEDTLS_SSL_MAJOR_VERSION_3;
    rec.ver[1]  = MBEDTLS_SSL_MINOR_VERSION_3;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    rec.cid_len = 0;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    /* Prepare dummy record content */
    rec.buf     = buf;
    rec.buf_len = buflen;
    rec.data_offset = block_size;
    rec.data_len = plaintext_len;
    memset(rec.buf + rec.data_offset, 42, rec.data_len);

    /* Serialized version of record header for MAC purposes */
    memcpy(add_data, rec.ctr, 8);
    add_data[8] = rec.type;
    add_data[9] = rec.ver[0];
    add_data[10] = rec.ver[1];
    add_data[11] = (rec.data_len >> 8) & 0xff;
    add_data[12] = (rec.data_len >> 0) & 0xff;

    /* Set dummy IV */
    memset(t0.iv_enc, 0x55, t0.ivlen);
    memcpy(rec.buf, t0.iv_enc, t0.ivlen);

    /*
     * Prepare a pre-encryption record (with MAC and padding), and save it.
     */

    /* MAC with additional data */
    TEST_EQUAL(0, mbedtls_md_hmac_update(&t0.md_ctx_enc, add_data, 13));
    TEST_EQUAL(0, mbedtls_md_hmac_update(&t0.md_ctx_enc,
                                         rec.buf + rec.data_offset,
                                         rec.data_len));
    TEST_EQUAL(0, mbedtls_md_hmac_finish(&t0.md_ctx_enc, mac));

    memcpy(rec.buf + rec.data_offset + rec.data_len, mac, t0.maclen);
    rec.data_len += t0.maclen;

    /* Pad */
    memset(rec.buf + rec.data_offset + rec.data_len, padlen, padlen + 1);
    rec.data_len += padlen + 1;

    /* Save correct pre-encryption record */
    rec_save = rec;
    rec_save.buf = buf_save;
    memcpy(buf_save, buf, buflen);

    /*
     * Encrypt and decrypt the correct record, expecting success
     */
    TEST_EQUAL(0, mbedtls_cipher_crypt(&t0.cipher_ctx_enc,
                                       t0.iv_enc, t0.ivlen,
                                       rec.buf + rec.data_offset, rec.data_len,
                                       rec.buf + rec.data_offset, &olen));
    rec.data_offset -= t0.ivlen;
    rec.data_len    += t0.ivlen;

    TEST_EQUAL(0, mbedtls_ssl_decrypt_buf(&ssl, &t1, &rec));

    /*
     * Modify each byte of the pre-encryption record before encrypting and
     * decrypting it, expecting failure every time.
     */
    for (i = block_size; i < buflen; i++) {
        mbedtls_test_set_step(i);

        /* Restore correct pre-encryption record */
        rec = rec_save;
        rec.buf = buf;
        memcpy(buf, buf_save, buflen);

        /* Corrupt one byte of the data (could be plaintext, MAC or padding) */
        rec.buf[i] ^= 0x01;

        /* Encrypt */
        TEST_EQUAL(0, mbedtls_cipher_crypt(&t0.cipher_ctx_enc,
                                           t0.iv_enc, t0.ivlen,
                                           rec.buf + rec.data_offset, rec.data_len,
                                           rec.buf + rec.data_offset, &olen));
        rec.data_offset -= t0.ivlen;
        rec.data_len    += t0.ivlen;

        /* Decrypt and expect failure */
        TEST_EQUAL(MBEDTLS_ERR_SSL_INVALID_MAC,
                   mbedtls_ssl_decrypt_buf(&ssl, &t1, &rec));
    }

    /*
     * Use larger values of the padding bytes - with small buffers, this tests
     * the case where the announced padlen would be larger than the buffer
     * (and before that, than the buffer minus the size of the MAC), to make
     * sure our padding checking code does not perform any out-of-bounds reads
     * in this case. (With larger buffers, ie when the plaintext is long or
     * maximal length padding is used, this is less relevant but still doesn't
     * hurt to test.)
     *
     * (Start the loop with correct padding, just to double-check that record
     * saving did work, and that we're overwriting the correct bytes.)
     */
    for (i = padlen; i <= pad_max_len; i++) {
        mbedtls_test_set_step(i);

        /* Restore correct pre-encryption record */
        rec = rec_save;
        rec.buf = buf;
        memcpy(buf, buf_save, buflen);

        /* Set padding bytes to new value */
        memset(buf + buflen - padlen - 1, i, padlen + 1);

        /* Encrypt */
        TEST_EQUAL(0, mbedtls_cipher_crypt(&t0.cipher_ctx_enc,
                                           t0.iv_enc, t0.ivlen,
                                           rec.buf + rec.data_offset, rec.data_len,
                                           rec.buf + rec.data_offset, &olen));
        rec.data_offset -= t0.ivlen;
        rec.data_len    += t0.ivlen;

        /* Decrypt and expect failure except the first time */
        exp_ret = (i == padlen) ? 0 : MBEDTLS_ERR_SSL_INVALID_MAC;
        TEST_EQUAL(exp_ret, mbedtls_ssl_decrypt_buf(&ssl, &t1, &rec));
    }

exit:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_transform_free(&t0);
    mbedtls_ssl_transform_free(&t1);
    mbedtls_free(buf);
    mbedtls_free(buf_save);
}

void test_ssl_decrypt_non_etm_cbc_wrapper( void ** params )
{

    test_ssl_decrypt_non_etm_cbc( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ) );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_AES_C */
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#line 1608 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_tls1_3_hkdf_expand_label(int hash_alg,
                                  data_t *secret,
                                  int label_idx,
                                  data_t *ctx,
                                  int desired_length,
                                  data_t *expected)
{
    unsigned char dst[100];

    unsigned char const *lbl = NULL;
    size_t lbl_len;
#define MBEDTLS_SSL_TLS1_3_LABEL(name, string)                        \
    if (label_idx == (int) tls1_3_label_ ## name)                      \
    {                                                                   \
        lbl = mbedtls_ssl_tls1_3_labels.name;                           \
        lbl_len = sizeof(mbedtls_ssl_tls1_3_labels.name);             \
    }
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
#undef MBEDTLS_SSL_TLS1_3_LABEL
    TEST_ASSERT(lbl != NULL);

    /* Check sanity of test parameters. */
    TEST_ASSERT((size_t) desired_length <= sizeof(dst));
    TEST_ASSERT((size_t) desired_length == expected->len);

    TEST_ASSERT(mbedtls_ssl_tls1_3_hkdf_expand_label(
                    (mbedtls_md_type_t) hash_alg,
                    secret->x, secret->len,
                    lbl, lbl_len,
                    ctx->x, ctx->len,
                    dst, desired_length) == 0);

    ASSERT_COMPARE(dst, (size_t) desired_length,
                   expected->x, (size_t) expected->len);
exit:
    ;
}

void test_ssl_tls1_3_hkdf_expand_label_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data7 = {(uint8_t *) params[7], *( (uint32_t *) params[8] )};

    test_ssl_tls1_3_hkdf_expand_label( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, *( (int *) params[6] ), &data7 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#line 1646 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_tls1_3_traffic_key_generation(int hash_alg,
                                       data_t *server_secret,
                                       data_t *client_secret,
                                       int desired_iv_len,
                                       int desired_key_len,
                                       data_t *expected_server_write_key,
                                       data_t *expected_server_write_iv,
                                       data_t *expected_client_write_key,
                                       data_t *expected_client_write_iv)
{
    mbedtls_ssl_key_set keys;

    /* Check sanity of test parameters. */
    TEST_ASSERT(client_secret->len == server_secret->len);
    TEST_ASSERT(
        expected_client_write_iv->len == expected_server_write_iv->len &&
        expected_client_write_iv->len == (size_t) desired_iv_len);
    TEST_ASSERT(
        expected_client_write_key->len == expected_server_write_key->len &&
        expected_client_write_key->len == (size_t) desired_key_len);

    TEST_ASSERT(mbedtls_ssl_tls1_3_make_traffic_keys(
                    (mbedtls_md_type_t) hash_alg,
                    client_secret->x,
                    server_secret->x,
                    client_secret->len /* == server_secret->len */,
                    desired_key_len, desired_iv_len,
                    &keys) == 0);

    ASSERT_COMPARE(keys.client_write_key,
                   keys.key_len,
                   expected_client_write_key->x,
                   (size_t) desired_key_len);
    ASSERT_COMPARE(keys.server_write_key,
                   keys.key_len,
                   expected_server_write_key->x,
                   (size_t) desired_key_len);
    ASSERT_COMPARE(keys.client_write_iv,
                   keys.iv_len,
                   expected_client_write_iv->x,
                   (size_t) desired_iv_len);
    ASSERT_COMPARE(keys.server_write_iv,
                   keys.iv_len,
                   expected_server_write_iv->x,
                   (size_t) desired_iv_len);
exit:
    ;
}

void test_ssl_tls1_3_traffic_key_generation_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data7 = {(uint8_t *) params[7], *( (uint32_t *) params[8] )};
    data_t data9 = {(uint8_t *) params[9], *( (uint32_t *) params[10] )};
    data_t data11 = {(uint8_t *) params[11], *( (uint32_t *) params[12] )};
    data_t data13 = {(uint8_t *) params[13], *( (uint32_t *) params[14] )};

    test_ssl_tls1_3_traffic_key_generation( *( (int *) params[0] ), &data1, &data3, *( (int *) params[5] ), *( (int *) params[6] ), &data7, &data9, &data11, &data13 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#line 1695 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_tls1_3_derive_secret(int hash_alg,
                              data_t *secret,
                              int label_idx,
                              data_t *ctx,
                              int desired_length,
                              int already_hashed,
                              data_t *expected)
{
    unsigned char dst[100];

    unsigned char const *lbl = NULL;
    size_t lbl_len;
#define MBEDTLS_SSL_TLS1_3_LABEL(name, string)                        \
    if (label_idx == (int) tls1_3_label_ ## name)                      \
    {                                                                   \
        lbl = mbedtls_ssl_tls1_3_labels.name;                           \
        lbl_len = sizeof(mbedtls_ssl_tls1_3_labels.name);             \
    }
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
#undef MBEDTLS_SSL_TLS1_3_LABEL
    TEST_ASSERT(lbl != NULL);

    /* Check sanity of test parameters. */
    TEST_ASSERT((size_t) desired_length <= sizeof(dst));
    TEST_ASSERT((size_t) desired_length == expected->len);

    TEST_ASSERT(mbedtls_ssl_tls1_3_derive_secret(
                    (mbedtls_md_type_t) hash_alg,
                    secret->x, secret->len,
                    lbl, lbl_len,
                    ctx->x, ctx->len,
                    already_hashed,
                    dst, desired_length) == 0);

    ASSERT_COMPARE(dst, desired_length,
                   expected->x, desired_length);
exit:
    ;
}

void test_ssl_tls1_3_derive_secret_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data4 = {(uint8_t *) params[4], *( (uint32_t *) params[5] )};
    data_t data8 = {(uint8_t *) params[8], *( (uint32_t *) params[9] )};

    test_ssl_tls1_3_derive_secret( *( (int *) params[0] ), &data1, *( (int *) params[3] ), &data4, *( (int *) params[6] ), *( (int *) params[7] ), &data8 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#line 1735 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_tls1_3_key_evolution(int hash_alg,
                              data_t *secret,
                              data_t *input,
                              data_t *expected)
{
    unsigned char secret_new[MBEDTLS_MD_MAX_SIZE];

    TEST_ASSERT(mbedtls_ssl_tls1_3_evolve_secret(
                    (mbedtls_md_type_t) hash_alg,
                    secret->len ? secret->x : NULL,
                    input->len ? input->x : NULL, input->len,
                    secret_new) == 0);

    ASSERT_COMPARE(secret_new, (size_t) expected->len,
                   expected->x, (size_t) expected->len);
exit:
    ;
}

void test_ssl_tls1_3_key_evolution_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};

    test_ssl_tls1_3_key_evolution( *( (int *) params[0] ), &data1, &data3, &data5 );
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
#line 1754 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_tls_prf(int type, data_t *secret, data_t *random,
                 char *label, data_t *result_str, int exp_ret)
{
    unsigned char *output;

    output = mbedtls_calloc(1, result_str->len);
    if (output == NULL) {
        goto exit;
    }

    USE_PSA_INIT();

    TEST_ASSERT(mbedtls_ssl_tls_prf(type, secret->x, secret->len,
                                    label, random->x, random->len,
                                    output, result_str->len) == exp_ret);

    if (exp_ret == 0) {
        TEST_ASSERT(mbedtls_test_hexcmp(output, result_str->x,
                                        result_str->len, result_str->len) == 0);
    }
exit:

    mbedtls_free(output);
    USE_PSA_DONE();
}

void test_ssl_tls_prf_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};
    data_t data3 = {(uint8_t *) params[3], *( (uint32_t *) params[4] )};
    data_t data6 = {(uint8_t *) params[6], *( (uint32_t *) params[7] )};

    test_ssl_tls_prf( *( (int *) params[0] ), &data1, &data3, (char *) params[5], &data6, *( (int *) params[8] ) );
}
#line 1782 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_serialize_session_save_load(int ticket_len, char *crt_file)
{
    mbedtls_ssl_session original, restored;
    unsigned char *buf = NULL;
    size_t len;

    /*
     * Test that a save-load pair is the identity
     */

    mbedtls_ssl_session_init(&original);
    mbedtls_ssl_session_init(&restored);

    /* Prepare a dummy session to work on */
    TEST_ASSERT(mbedtls_test_ssl_populate_session(
                    &original, ticket_len, crt_file) == 0);

    /* Serialize it */
    TEST_ASSERT(mbedtls_ssl_session_save(&original, NULL, 0, &len)
                == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
    TEST_ASSERT((buf = mbedtls_calloc(1, len)) != NULL);
    TEST_ASSERT(mbedtls_ssl_session_save(&original, buf, len, &len)
                == 0);

    /* Restore session from serialized data */
    TEST_ASSERT(mbedtls_ssl_session_load(&restored, buf, len) == 0);

    /*
     * Make sure both session structures are identical
     */
#if defined(MBEDTLS_HAVE_TIME)
    TEST_ASSERT(original.start == restored.start);
#endif
    TEST_ASSERT(original.ciphersuite == restored.ciphersuite);
    TEST_ASSERT(original.compression == restored.compression);
    TEST_ASSERT(original.id_len == restored.id_len);
    TEST_ASSERT(memcmp(original.id,
                       restored.id, sizeof(original.id)) == 0);
    TEST_ASSERT(memcmp(original.master,
                       restored.master, sizeof(original.master)) == 0);

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && \
    defined(MBEDTLS_CERTS_C)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    TEST_ASSERT((original.peer_cert == NULL) ==
                (restored.peer_cert == NULL));
    if (original.peer_cert != NULL) {
        TEST_ASSERT(original.peer_cert->raw.len ==
                    restored.peer_cert->raw.len);
        TEST_ASSERT(memcmp(original.peer_cert->raw.p,
                           restored.peer_cert->raw.p,
                           original.peer_cert->raw.len) == 0);
    }
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    TEST_ASSERT(original.peer_cert_digest_type ==
                restored.peer_cert_digest_type);
    TEST_ASSERT(original.peer_cert_digest_len ==
                restored.peer_cert_digest_len);
    TEST_ASSERT((original.peer_cert_digest == NULL) ==
                (restored.peer_cert_digest == NULL));
    if (original.peer_cert_digest != NULL) {
        TEST_ASSERT(memcmp(original.peer_cert_digest,
                           restored.peer_cert_digest,
                           original.peer_cert_digest_len) == 0);
    }
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_CERTS_C */
    TEST_ASSERT(original.verify_result == restored.verify_result);

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    TEST_ASSERT(original.ticket_len == restored.ticket_len);
    if (original.ticket_len != 0) {
        TEST_ASSERT(original.ticket != NULL);
        TEST_ASSERT(restored.ticket != NULL);
        TEST_ASSERT(memcmp(original.ticket,
                           restored.ticket, original.ticket_len) == 0);
    }
    TEST_ASSERT(original.ticket_lifetime == restored.ticket_lifetime);
#endif

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    TEST_ASSERT(original.mfl_code == restored.mfl_code);
#endif

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
    TEST_ASSERT(original.trunc_hmac == restored.trunc_hmac);
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    TEST_ASSERT(original.encrypt_then_mac == restored.encrypt_then_mac);
#endif

exit:
    mbedtls_ssl_session_free(&original);
    mbedtls_ssl_session_free(&restored);
    mbedtls_free(buf);
}

void test_ssl_serialize_session_save_load_wrapper( void ** params )
{

    test_ssl_serialize_session_save_load( *( (int *) params[0] ), (char *) params[1] );
}
#line 1882 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_serialize_session_load_save(int ticket_len, char *crt_file)
{
    mbedtls_ssl_session session;
    unsigned char *buf1 = NULL, *buf2 = NULL;
    size_t len0, len1, len2;

    /*
     * Test that a load-save pair is the identity
     */

    mbedtls_ssl_session_init(&session);

    /* Prepare a dummy session to work on */
    TEST_ASSERT(mbedtls_test_ssl_populate_session(
                    &session, ticket_len, crt_file) == 0);

    /* Get desired buffer size for serializing */
    TEST_ASSERT(mbedtls_ssl_session_save(&session, NULL, 0, &len0)
                == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);

    /* Allocate first buffer */
    buf1 = mbedtls_calloc(1, len0);
    TEST_ASSERT(buf1 != NULL);

    /* Serialize to buffer and free live session */
    TEST_ASSERT(mbedtls_ssl_session_save(&session, buf1, len0, &len1)
                == 0);
    TEST_ASSERT(len0 == len1);
    mbedtls_ssl_session_free(&session);

    /* Restore session from serialized data */
    TEST_ASSERT(mbedtls_ssl_session_load(&session, buf1, len1) == 0);

    /* Allocate second buffer and serialize to it */
    buf2 = mbedtls_calloc(1, len0);
    TEST_ASSERT(buf2 != NULL);
    TEST_ASSERT(mbedtls_ssl_session_save(&session, buf2, len0, &len2)
                == 0);

    /* Make sure both serialized versions are identical */
    TEST_ASSERT(len1 == len2);
    TEST_ASSERT(memcmp(buf1, buf2, len1) == 0);

exit:
    mbedtls_ssl_session_free(&session);
    mbedtls_free(buf1);
    mbedtls_free(buf2);
}

void test_ssl_serialize_session_load_save_wrapper( void ** params )
{

    test_ssl_serialize_session_load_save( *( (int *) params[0] ), (char *) params[1] );
}
#line 1933 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_serialize_session_save_buf_size(int ticket_len, char *crt_file)
{
    mbedtls_ssl_session session;
    unsigned char *buf = NULL;
    size_t good_len, bad_len, test_len;

    /*
     * Test that session_save() fails cleanly on small buffers
     */

    mbedtls_ssl_session_init(&session);

    /* Prepare dummy session and get serialized size */
    TEST_ASSERT(mbedtls_test_ssl_populate_session(
                    &session, ticket_len, crt_file) == 0);
    TEST_ASSERT(mbedtls_ssl_session_save(&session, NULL, 0, &good_len)
                == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);

    /* Try all possible bad lengths */
    for (bad_len = 1; bad_len < good_len; bad_len++) {
        /* Allocate exact size so that asan/valgrind can detect any overwrite */
        mbedtls_free(buf);
        TEST_ASSERT((buf = mbedtls_calloc(1, bad_len)) != NULL);
        TEST_ASSERT(mbedtls_ssl_session_save(&session, buf, bad_len,
                                             &test_len)
                    == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
        TEST_ASSERT(test_len == good_len);
    }

exit:
    mbedtls_ssl_session_free(&session);
    mbedtls_free(buf);
}

void test_ssl_serialize_session_save_buf_size_wrapper( void ** params )
{

    test_ssl_serialize_session_save_buf_size( *( (int *) params[0] ), (char *) params[1] );
}
#line 1969 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_serialize_session_load_buf_size(int ticket_len, char *crt_file)
{
    mbedtls_ssl_session session;
    unsigned char *good_buf = NULL, *bad_buf = NULL;
    size_t good_len, bad_len;

    /*
     * Test that session_load() fails cleanly on small buffers
     */

    mbedtls_ssl_session_init(&session);

    /* Prepare serialized session data */
    TEST_ASSERT(mbedtls_test_ssl_populate_session(
                    &session, ticket_len, crt_file) == 0);
    TEST_ASSERT(mbedtls_ssl_session_save(&session, NULL, 0, &good_len)
                == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
    TEST_ASSERT((good_buf = mbedtls_calloc(1, good_len)) != NULL);
    TEST_ASSERT(mbedtls_ssl_session_save(&session, good_buf, good_len,
                                         &good_len) == 0);
    mbedtls_ssl_session_free(&session);

    /* Try all possible bad lengths */
    for (bad_len = 0; bad_len < good_len; bad_len++) {
        /* Allocate exact size so that asan/valgrind can detect any overread */
        mbedtls_free(bad_buf);
        bad_buf = mbedtls_calloc(1, bad_len ? bad_len : 1);
        TEST_ASSERT(bad_buf != NULL);
        memcpy(bad_buf, good_buf, bad_len);

        TEST_ASSERT(mbedtls_ssl_session_load(&session, bad_buf, bad_len)
                    == MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }

exit:
    mbedtls_ssl_session_free(&session);
    mbedtls_free(good_buf);
    mbedtls_free(bad_buf);
}

void test_ssl_serialize_session_load_buf_size_wrapper( void ** params )
{

    test_ssl_serialize_session_load_buf_size( *( (int *) params[0] ), (char *) params[1] );
}
#line 2011 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_ssl_session_serialize_version_check(int corrupt_major,
                                         int corrupt_minor,
                                         int corrupt_patch,
                                         int corrupt_config)
{
    unsigned char serialized_session[2048];
    size_t serialized_session_len;
    unsigned cur_byte;
    mbedtls_ssl_session session;
    uint8_t should_corrupt_byte[] = { corrupt_major  == 1,
                                      corrupt_minor  == 1,
                                      corrupt_patch  == 1,
                                      corrupt_config == 1,
                                      corrupt_config == 1 };

    mbedtls_ssl_session_init(&session);

    /* Infer length of serialized session. */
    TEST_ASSERT(mbedtls_ssl_session_save(&session,
                                         serialized_session,
                                         sizeof(serialized_session),
                                         &serialized_session_len) == 0);

    mbedtls_ssl_session_free(&session);

    /* Without any modification, we should be able to successfully
     * de-serialize the session - double-check that. */
    TEST_ASSERT(mbedtls_ssl_session_load(&session,
                                         serialized_session,
                                         serialized_session_len) == 0);
    mbedtls_ssl_session_free(&session);

    /* Go through the bytes in the serialized session header and
     * corrupt them bit-by-bit. */
    for (cur_byte = 0; cur_byte < sizeof(should_corrupt_byte); cur_byte++) {
        int cur_bit;
        unsigned char * const byte = &serialized_session[cur_byte];

        if (should_corrupt_byte[cur_byte] == 0) {
            continue;
        }

        for (cur_bit = 0; cur_bit < CHAR_BIT; cur_bit++) {
            unsigned char const corrupted_bit = 0x1u << cur_bit;
            /* Modify a single bit in the serialized session. */
            *byte ^= corrupted_bit;

            /* Attempt to deserialize */
            TEST_ASSERT(mbedtls_ssl_session_load(&session,
                                                 serialized_session,
                                                 serialized_session_len) ==
                        MBEDTLS_ERR_SSL_VERSION_MISMATCH);

            /* Undo the change */
            *byte ^= corrupted_bit;
        }
    }

exit:
    ;
}

void test_ssl_session_serialize_version_check_wrapper( void ** params )
{

    test_ssl_session_serialize_version_check( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ) );
}
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#line 2073 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_mbedtls_endpoint_sanity(int endpoint_type)
{
    enum { BUFFSIZE = 1024 };
    mbedtls_test_ssl_endpoint ep;
    int ret = -1;

    ret = mbedtls_test_ssl_endpoint_init(NULL, endpoint_type, MBEDTLS_PK_RSA,
                                         NULL, NULL, NULL, NULL);
    TEST_ASSERT(MBEDTLS_ERR_SSL_BAD_INPUT_DATA == ret);

    ret = mbedtls_test_ssl_endpoint_certificate_init(NULL, MBEDTLS_PK_RSA);
    TEST_ASSERT(MBEDTLS_ERR_SSL_BAD_INPUT_DATA == ret);

    ret = mbedtls_test_ssl_endpoint_init(&ep, endpoint_type, MBEDTLS_PK_RSA,
                                         NULL, NULL, NULL, NULL);
    TEST_ASSERT(ret == 0);

exit:
    mbedtls_test_ssl_endpoint_free(&ep, NULL);
}

void test_mbedtls_endpoint_sanity_wrapper( void ** params )
{

    test_mbedtls_endpoint_sanity( *( (int *) params[0] ) );
}
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_SHA256_C)
#line 2096 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_move_handshake_to_state(int endpoint_type, int state, int need_pass)
{
    enum { BUFFSIZE = 1024 };
    mbedtls_test_ssl_endpoint base_ep, second_ep;
    int ret = -1;

    mbedtls_platform_zeroize(&base_ep, sizeof(base_ep));
    mbedtls_platform_zeroize(&second_ep, sizeof(second_ep));

    ret = mbedtls_test_ssl_endpoint_init(&base_ep, endpoint_type,
                                         MBEDTLS_PK_RSA,
                                         NULL, NULL, NULL, NULL);
    TEST_ASSERT(ret == 0);

    ret = mbedtls_test_ssl_endpoint_init(
        &second_ep,
        (endpoint_type == MBEDTLS_SSL_IS_SERVER) ?
        MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_PK_RSA, NULL, NULL, NULL, NULL);
    TEST_ASSERT(ret == 0);

    ret = mbedtls_test_mock_socket_connect(&(base_ep.socket),
                                           &(second_ep.socket),
                                           BUFFSIZE);
    TEST_ASSERT(ret == 0);

    ret = mbedtls_test_move_handshake_to_state(&(base_ep.ssl),
                                               &(second_ep.ssl),
                                               state);
    if (need_pass) {
        TEST_ASSERT(ret == 0);
        TEST_ASSERT(base_ep.ssl.state == state);
    } else {
        TEST_ASSERT(ret != 0);
        TEST_ASSERT(base_ep.ssl.state != state);
    }

exit:
    mbedtls_test_ssl_endpoint_free(&base_ep, NULL);
    mbedtls_test_ssl_endpoint_free(&second_ep, NULL);
}

void test_move_handshake_to_state_wrapper( void ** params )
{

    test_move_handshake_to_state( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_ECP_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2140 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_handshake_version(int dtls, int client_min_version, int client_max_version,
                       int server_min_version, int server_max_version,
                       int expected_negotiated_version)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.client_min_version = client_min_version;
    options.client_max_version = client_max_version;
    options.server_min_version = server_min_version;
    options.server_max_version = server_max_version;

    options.expected_negotiated_version = expected_negotiated_version;

    options.dtls = dtls;
    /* By default, SSLv3.0 and TLSv1.0 use 1/n-1 splitting when sending data, so
     * the number of fragments will be twice as big. */
    if (expected_negotiated_version == MBEDTLS_SSL_MINOR_VERSION_0 ||
        expected_negotiated_version == MBEDTLS_SSL_MINOR_VERSION_1) {
        options.expected_cli_fragments = 2;
        options.expected_srv_fragments = 2;
    }
    mbedtls_test_ssl_perform_handshake(&options);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_handshake_version_wrapper( void ** params )
{

    test_handshake_version( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ) );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_ECP_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#line 2170 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_handshake_psk_cipher(char *cipher, int pk_alg, data_t *psk_str, int dtls)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.cipher = cipher;
    options.dtls = dtls;
    options.psk_str = psk_str;
    options.pk_alg = pk_alg;

    mbedtls_test_ssl_perform_handshake(&options);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_handshake_psk_cipher_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};

    test_handshake_psk_cipher( (char *) params[0], *( (int *) params[1] ), &data2, *( (int *) params[4] ) );
}
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#line 2188 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_handshake_cipher(char *cipher, int pk_alg, int dtls)
{
    test_handshake_psk_cipher(cipher, pk_alg, NULL, dtls);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_handshake_cipher_wrapper( void ** params )
{

    test_handshake_cipher( (char *) params[0], *( (int *) params[1] ), *( (int *) params[2] ) );
}
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#line 2198 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_app_data(int mfl, int cli_msg_len, int srv_msg_len,
              int expected_cli_fragments,
              int expected_srv_fragments, int dtls)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.mfl = mfl;
    options.cli_msg_len = cli_msg_len;
    options.srv_msg_len = srv_msg_len;
    options.expected_cli_fragments = expected_cli_fragments;
    options.expected_srv_fragments = expected_srv_fragments;
    options.dtls = dtls;

    mbedtls_test_ssl_perform_handshake(&options);
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_app_data_wrapper( void ** params )
{

    test_app_data( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ) );
}
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2219 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_app_data_tls(int mfl, int cli_msg_len, int srv_msg_len,
                  int expected_cli_fragments,
                  int expected_srv_fragments)
{
    test_app_data(mfl, cli_msg_len, srv_msg_len, expected_cli_fragments,
                  expected_srv_fragments, 0);
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_app_data_tls_wrapper( void ** params )
{

    test_app_data_tls( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ) );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_ECP_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2231 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_app_data_dtls(int mfl, int cli_msg_len, int srv_msg_len,
                   int expected_cli_fragments,
                   int expected_srv_fragments)
{
    test_app_data(mfl, cli_msg_len, srv_msg_len, expected_cli_fragments,
                  expected_srv_fragments, 1);
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_app_data_dtls_wrapper( void ** params )
{

    test_app_data_dtls( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ) );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_SSL_RENEGOTIATION)
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2243 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_handshake_serialization()
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.serialize = 1;
    options.dtls = 1;
    mbedtls_test_ssl_perform_handshake(&options);
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_handshake_serialization_wrapper( void ** params )
{
    (void)params;

    test_handshake_serialization(  );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */
#endif /* MBEDTLS_SSL_RENEGOTIATION */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_DEBUG_C)
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
#if defined(MBEDTLS_CIPHER_MODE_CBC)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
#line 2257 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_handshake_fragmentation(int mfl,
                             int expected_srv_hs_fragmentation,
                             int expected_cli_hs_fragmentation)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_ssl_log_pattern srv_pattern, cli_pattern;

    srv_pattern.pattern = cli_pattern.pattern = "found fragmented DTLS handshake";
    srv_pattern.counter = 0;
    cli_pattern.counter = 0;

    mbedtls_test_init_handshake_options(&options);
    options.dtls = 1;
    options.mfl = mfl;
    /* Set cipher to one using CBC so that record splitting can be tested */
    options.cipher = "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256";
    options.srv_auth_mode = MBEDTLS_SSL_VERIFY_REQUIRED;
    options.srv_log_obj = &srv_pattern;
    options.cli_log_obj = &cli_pattern;
    options.srv_log_fun = mbedtls_test_ssl_log_analyzer;
    options.cli_log_fun = mbedtls_test_ssl_log_analyzer;

    mbedtls_test_ssl_perform_handshake(&options);

    /* Test if the server received a fragmented handshake */
    if (expected_srv_hs_fragmentation) {
        TEST_ASSERT(srv_pattern.counter >= 1);
    }
    /* Test if the client received a fragmented handshake */
    if (expected_cli_hs_fragmentation) {
        TEST_ASSERT(cli_pattern.counter >= 1);
    }
exit:
    ;
}

void test_handshake_fragmentation_wrapper( void ** params )
{

    test_handshake_fragmentation( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ) );
}
#endif /* MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED */
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */
#endif /* MBEDTLS_DEBUG_C */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_SSL_RENEGOTIATION)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2293 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_renegotiation(int legacy_renegotiation)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.renegotiate = 1;
    options.legacy_renegotiation = legacy_renegotiation;
    options.dtls = 1;

    mbedtls_test_ssl_perform_handshake(&options);
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_renegotiation_wrapper( void ** params )
{

    test_renegotiation( *( (int *) params[0] ) );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_SSL_RENEGOTIATION */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#line 2309 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_resize_buffers(int mfl, int renegotiation, int legacy_renegotiation,
                    int serialize, int dtls, char *cipher)
{
    mbedtls_test_handshake_test_options options;
    mbedtls_test_init_handshake_options(&options);

    options.mfl = mfl;
    options.cipher = cipher;
    options.renegotiate = renegotiation;
    options.legacy_renegotiation = legacy_renegotiation;
    options.serialize = serialize;
    options.dtls = dtls;
    options.resize_buffers = 1;

    mbedtls_test_ssl_perform_handshake(&options);
    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_resize_buffers_wrapper( void ** params )
{

    test_resize_buffers( *( (int *) params[0] ), *( (int *) params[1] ), *( (int *) params[2] ), *( (int *) params[3] ), *( (int *) params[4] ), (char *) params[5] );
}
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2330 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_resize_buffers_serialize_mfl(int mfl)
{
    test_resize_buffers(mfl, 0, MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION, 1, 1,
                        (char *) "");

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_resize_buffers_serialize_mfl_wrapper( void ** params )
{

    test_resize_buffers_serialize_mfl( *( (int *) params[0] ) );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */
#endif /* MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_SSL_RENEGOTIATION)
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
#line 2341 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_resize_buffers_renegotiate_mfl(int mfl, int legacy_renegotiation,
                                    char *cipher)
{
    test_resize_buffers(mfl, 1, legacy_renegotiation, 0, 1, cipher);

    /* The goto below is used to avoid an "unused label" warning.*/
    goto exit;
exit:
    ;
}

void test_resize_buffers_renegotiate_mfl_wrapper( void ** params )
{

    test_resize_buffers_renegotiate_mfl( *( (int *) params[0] ), *( (int *) params[1] ), (char *) params[2] );
}
#endif /* MBEDTLS_CAN_HANDLE_RSA_TEST_KEY */
#endif /* MBEDTLS_SSL_RENEGOTIATION */
#endif /* MBEDTLS_SHA256_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_CERTS_C)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
#if defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#if defined(MBEDTLS_CTR_DRBG_C)
#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_ECDSA_C)
#line 2352 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_raw_key_agreement_fail(int bad_server_ecdhe_key)
{
    enum { BUFFSIZE = 17000 };
    mbedtls_test_ssl_endpoint client, server;
    mbedtls_psa_stats_t stats;
    size_t free_slots_before = -1;

    mbedtls_ecp_group_id curve_list[] = { MBEDTLS_ECP_DP_SECP256R1,
                                          MBEDTLS_ECP_DP_NONE };
    USE_PSA_INIT();
    mbedtls_platform_zeroize(&client, sizeof(client));
    mbedtls_platform_zeroize(&server, sizeof(server));

    /* Client side, force SECP256R1 to make one key bitflip fail
     * the raw key agreement. Flipping the first byte makes the
     * required 0x04 identifier invalid. */
    TEST_EQUAL(mbedtls_test_ssl_endpoint_init(&client, MBEDTLS_SSL_IS_CLIENT,
                                              MBEDTLS_PK_ECDSA, NULL, NULL,
                                              NULL, curve_list), 0);

    /* Server side */
    TEST_EQUAL(mbedtls_test_ssl_endpoint_init(&server, MBEDTLS_SSL_IS_SERVER,
                                              MBEDTLS_PK_ECDSA, NULL, NULL,
                                              NULL, NULL), 0);

    TEST_EQUAL(mbedtls_test_mock_socket_connect(&(client.socket),
                                                &(server.socket),
                                                BUFFSIZE), 0);

    TEST_EQUAL(mbedtls_test_move_handshake_to_state(
                   &(client.ssl), &(server.ssl),
                   MBEDTLS_SSL_CLIENT_KEY_EXCHANGE)
               , 0);

    mbedtls_psa_get_stats(&stats);
    /* Save the number of slots in use up to this point.
     * With PSA, one can be used for the ECDH private key. */
    free_slots_before = stats.empty_slots;

    if (bad_server_ecdhe_key) {
        /* Force a simulated bitflip in the server key. to make the
         * raw key agreement in ssl_write_client_key_exchange fail. */
        (client.ssl).handshake->ecdh_psa_peerkey[0] ^= 0x02;
    }

    TEST_EQUAL(mbedtls_test_move_handshake_to_state(
                   &(client.ssl), &(server.ssl), MBEDTLS_SSL_HANDSHAKE_OVER),
               bad_server_ecdhe_key ? MBEDTLS_ERR_SSL_HW_ACCEL_FAILED : 0);

    mbedtls_psa_get_stats(&stats);

    /* Make sure that the key slot is already destroyed in case of failure,
     * without waiting to close the connection. */
    if (bad_server_ecdhe_key) {
        TEST_EQUAL(free_slots_before, stats.empty_slots);
    }

exit:
    mbedtls_test_ssl_endpoint_free(&client, NULL);
    mbedtls_test_ssl_endpoint_free(&server, NULL);

    USE_PSA_DONE();
}

void test_raw_key_agreement_fail_wrapper( void ** params )
{

    test_raw_key_agreement_fail( *( (int *) params[0] ) );
}
#endif /* MBEDTLS_ECDSA_C */
#endif /* MBEDTLS_ECP_C */
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#endif /* MBEDTLS_RSA_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_PKCS1_V15 */
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_CERTS_C */
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#if defined(MBEDTLS_SSL_SRV_C)
#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE)
#if defined(MBEDTLS_TEST_HOOKS)
#line 2418 "/home/sean/installBySrc/mbedtls-2.28.3/tests/suites/test_suite_ssl.function"
void test_cookie_parsing(data_t *cookie, int exp_ret)
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    size_t len;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    TEST_EQUAL(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT),
               0);

    TEST_EQUAL(mbedtls_ssl_setup(&ssl, &conf), 0);
    TEST_EQUAL(mbedtls_ssl_check_dtls_clihlo_cookie(&ssl, ssl.cli_id,
                                                    ssl.cli_id_len,
                                                    cookie->x, cookie->len,
                                                    ssl.out_buf,
                                                    MBEDTLS_SSL_OUT_CONTENT_LEN,
                                                    &len),
               exp_ret);

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
exit:
    ;
}

void test_cookie_parsing_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], *( (uint32_t *) params[1] )};

    test_cookie_parsing( &data0, *( (int *) params[2] ) );
}
#endif /* MBEDTLS_TEST_HOOKS */
#endif /* MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE */
#endif /* MBEDTLS_SSL_SRV_C */
#endif /* MBEDTLS_SSL_TLS_C */


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
    
#if defined(MBEDTLS_SSL_TLS_C)

        case 0:
            {
                *out_value = MBEDTLS_SSL_IS_CLIENT;
            }
            break;
        case 1:
            {
                *out_value = MBEDTLS_SSL_IS_SERVER;
            }
            break;
        case 2:
            {
                *out_value = MBEDTLS_SSL_HELLO_REQUEST;
            }
            break;
        case 3:
            {
                *out_value = MBEDTLS_SSL_CLIENT_HELLO;
            }
            break;
        case 4:
            {
                *out_value = MBEDTLS_SSL_SERVER_HELLO;
            }
            break;
        case 5:
            {
                *out_value = MBEDTLS_SSL_SERVER_CERTIFICATE;
            }
            break;
        case 6:
            {
                *out_value = MBEDTLS_SSL_SERVER_KEY_EXCHANGE;
            }
            break;
        case 7:
            {
                *out_value = MBEDTLS_SSL_CERTIFICATE_REQUEST;
            }
            break;
        case 8:
            {
                *out_value = MBEDTLS_SSL_SERVER_HELLO_DONE;
            }
            break;
        case 9:
            {
                *out_value = MBEDTLS_SSL_CLIENT_CERTIFICATE;
            }
            break;
        case 10:
            {
                *out_value = MBEDTLS_SSL_CLIENT_KEY_EXCHANGE;
            }
            break;
        case 11:
            {
                *out_value = MBEDTLS_SSL_CERTIFICATE_VERIFY;
            }
            break;
        case 12:
            {
                *out_value = MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC;
            }
            break;
        case 13:
            {
                *out_value = MBEDTLS_SSL_CLIENT_FINISHED;
            }
            break;
        case 14:
            {
                *out_value = MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC;
            }
            break;
        case 15:
            {
                *out_value = MBEDTLS_SSL_SERVER_FINISHED;
            }
            break;
        case 16:
            {
                *out_value = MBEDTLS_SSL_FLUSH_BUFFERS;
            }
            break;
        case 17:
            {
                *out_value = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
            }
            break;
        case 18:
            {
                *out_value = MBEDTLS_SSL_HANDSHAKE_OVER;
            }
            break;
        case 19:
            {
                *out_value = MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT;
            }
            break;
        case 20:
            {
                *out_value = MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET;
            }
            break;
        case 21:
            {
                *out_value = MBEDTLS_SSL_MINOR_VERSION_0;
            }
            break;
        case 22:
            {
                *out_value = MBEDTLS_SSL_MINOR_VERSION_1;
            }
            break;
        case 23:
            {
                *out_value = MBEDTLS_SSL_MINOR_VERSION_2;
            }
            break;
        case 24:
            {
                *out_value = MBEDTLS_SSL_MINOR_VERSION_3;
            }
            break;
        case 25:
            {
                *out_value = MBEDTLS_PK_RSA;
            }
            break;
        case 26:
            {
                *out_value = MBEDTLS_PK_ECDSA;
            }
            break;
        case 27:
            {
                *out_value = MBEDTLS_SSL_MAX_FRAG_LEN_512;
            }
            break;
        case 28:
            {
                *out_value = MBEDTLS_SSL_MAX_FRAG_LEN_1024;
            }
            break;
        case 29:
            {
                *out_value = TEST_SSL_MINOR_VERSION_NONE;
            }
            break;
        case 30:
            {
                *out_value = MBEDTLS_SSL_MAX_FRAG_LEN_2048;
            }
            break;
        case 31:
            {
                *out_value = MBEDTLS_SSL_MAX_FRAG_LEN_4096;
            }
            break;
        case 32:
            {
                *out_value = MBEDTLS_SSL_MAX_FRAG_LEN_NONE;
            }
            break;
        case 33:
            {
                *out_value = MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION;
            }
            break;
        case 34:
            {
                *out_value = MBEDTLS_SSL_LEGACY_ALLOW_RENEGOTIATION;
            }
            break;
        case 35:
            {
                *out_value = MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE;
            }
            break;
        case 36:
            {
                *out_value = -1;
            }
            break;
        case 37:
            {
                *out_value = MBEDTLS_CIPHER_AES_128_CBC;
            }
            break;
        case 38:
            {
                *out_value = MBEDTLS_MD_SHA384;
            }
            break;
        case 39:
            {
                *out_value = MBEDTLS_MD_SHA256;
            }
            break;
        case 40:
            {
                *out_value = MBEDTLS_MD_SHA1;
            }
            break;
        case 41:
            {
                *out_value = MBEDTLS_MD_MD5;
            }
            break;
        case 42:
            {
                *out_value = MBEDTLS_CIPHER_AES_192_CBC;
            }
            break;
        case 43:
            {
                *out_value = MBEDTLS_CIPHER_AES_256_CBC;
            }
            break;
        case 44:
            {
                *out_value = MBEDTLS_CIPHER_ARIA_128_CBC;
            }
            break;
        case 45:
            {
                *out_value = MBEDTLS_CIPHER_ARIA_192_CBC;
            }
            break;
        case 46:
            {
                *out_value = MBEDTLS_CIPHER_ARIA_256_CBC;
            }
            break;
        case 47:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_128_CBC;
            }
            break;
        case 48:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_192_CBC;
            }
            break;
        case 49:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_256_CBC;
            }
            break;
        case 50:
            {
                *out_value = MBEDTLS_CIPHER_AES_128_GCM;
            }
            break;
        case 51:
            {
                *out_value = MBEDTLS_SSL_MINOR_VERSION_4;
            }
            break;
        case 52:
            {
                *out_value = MBEDTLS_CIPHER_AES_192_GCM;
            }
            break;
        case 53:
            {
                *out_value = MBEDTLS_CIPHER_AES_256_GCM;
            }
            break;
        case 54:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_128_GCM;
            }
            break;
        case 55:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_192_GCM;
            }
            break;
        case 56:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_256_GCM;
            }
            break;
        case 57:
            {
                *out_value = MBEDTLS_CIPHER_AES_128_CCM;
            }
            break;
        case 58:
            {
                *out_value = MBEDTLS_CIPHER_AES_192_CCM;
            }
            break;
        case 59:
            {
                *out_value = MBEDTLS_CIPHER_AES_256_CCM;
            }
            break;
        case 60:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_128_CCM;
            }
            break;
        case 61:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_192_CCM;
            }
            break;
        case 62:
            {
                *out_value = MBEDTLS_CIPHER_CAMELLIA_256_CCM;
            }
            break;
        case 63:
            {
                *out_value = MBEDTLS_CIPHER_ARC4_128;
            }
            break;
        case 64:
            {
                *out_value = MBEDTLS_CIPHER_NULL;
            }
            break;
        case 65:
            {
                *out_value = MBEDTLS_CIPHER_CHACHA20_POLY1305;
            }
            break;
        case 66:
            {
                *out_value = -2;
            }
            break;
        case 67:
            {
                *out_value = MBEDTLS_CIPHER_DES_EDE3_CBC;
            }
            break;
        case 68:
            {
                *out_value = tls1_3_label_key;
            }
            break;
        case 69:
            {
                *out_value = tls1_3_label_iv;
            }
            break;
        case 70:
            {
                *out_value = tls1_3_label_finished;
            }
            break;
        case 71:
            {
                *out_value = tls1_3_label_resumption;
            }
            break;
        case 72:
            {
                *out_value = tls1_3_label_derived;
            }
            break;
        case 73:
            {
                *out_value = MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED;
            }
            break;
        case 74:
            {
                *out_value = tls1_3_label_s_ap_traffic;
            }
            break;
        case 75:
            {
                *out_value = MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED;
            }
            break;
        case 76:
            {
                *out_value = tls1_3_label_c_e_traffic;
            }
            break;
        case 77:
            {
                *out_value = tls1_3_label_e_exp_master;
            }
            break;
        case 78:
            {
                *out_value = tls1_3_label_c_hs_traffic;
            }
            break;
        case 79:
            {
                *out_value = tls1_3_label_s_hs_traffic;
            }
            break;
        case 80:
            {
                *out_value = tls1_3_label_c_ap_traffic;
            }
            break;
        case 81:
            {
                *out_value = tls1_3_label_exp_master;
            }
            break;
        case 82:
            {
                *out_value = tls1_3_label_res_master;
            }
            break;
        case 83:
            {
                *out_value = MBEDTLS_SSL_TLS_PRF_NONE;
            }
            break;
        case 84:
            {
                *out_value = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
            }
            break;
        case 85:
            {
                *out_value = MBEDTLS_SSL_TLS_PRF_SSL3;
            }
            break;
        case 86:
            {
                *out_value = MBEDTLS_SSL_TLS_PRF_TLS1;
            }
            break;
        case 87:
            {
                *out_value = MBEDTLS_SSL_TLS_PRF_SHA384;
            }
            break;
        case 88:
            {
                *out_value = MBEDTLS_SSL_TLS_PRF_SHA256;
            }
            break;
        case 89:
            {
                *out_value = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            }
            break;
        case 90:
            {
                *out_value = MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO;
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
    
#if defined(MBEDTLS_SSL_TLS_C)

        case 0:
            {
#if defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(MBEDTLS_SSL_PROTO_SSL3)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(MBEDTLS_RSA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if defined(MBEDTLS_CIPHER_MODE_CBC)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 7:
            {
#if defined(MBEDTLS_SSL_PROTO_TLS1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 8:
            {
#if defined(MBEDTLS_SSL_PROTO_TLS1_1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 9:
            {
#if defined(MBEDTLS_SHA512_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 10:
            {
#if !defined(MBEDTLS_SHA512_NO_SHA384)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 11:
            {
#if defined(MBEDTLS_AES_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 12:
            {
#if defined(MBEDTLS_GCM_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 13:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 14:
            {
#if defined(MBEDTLS_CCM_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 15:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 16:
            {
#if defined(MBEDTLS_SHA256_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 17:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 18:
            {
#if defined(MBEDTLS_ECDSA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 19:
            {
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 20:
            {
#if defined(MBEDTLS_CAMELLIA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 21:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 22:
            {
#if defined(MBEDTLS_SHA1_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 23:
            {
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 24:
            {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 25:
            {
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 26:
            {
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 27:
            {
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 28:
            {
#if defined(MBEDTLS_MD5_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 29:
            {
#if defined(MBEDTLS_ARIA_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 30:
            {
#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 31:
            {
#if defined(MBEDTLS_ARC4_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 32:
            {
#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 33:
            {
#if defined(MBEDTLS_CHACHAPOLY_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 34:
            {
#if defined(MBEDTLS_DES_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 35:
            {
#if defined(MBEDTLS_ECP_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 36:
            {
#if !defined(MBEDTLS_SSL_PROTO_SSL3)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 37:
            {
#if !defined(MBEDTLS_SSL_PROTO_TLS1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 38:
            {
#if !defined(MBEDTLS_SSL_PROTO_TLS1_1)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 39:
            {
#if !defined(MBEDTLS_SHA512_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 40:
            {
#if !defined(MBEDTLS_SHA256_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 41:
            {
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 42:
            {
#if defined(MBEDTLS_SSL_CLI_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 43:
            {
#if defined(MBEDTLS_X509_USE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 44:
            {
#if defined(MBEDTLS_PEM_PARSE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 45:
            {
#if defined(MBEDTLS_FS_IO)
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

#if defined(MBEDTLS_SSL_TLS_C)
    test_test_callback_buffer_sanity_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_test_callback_buffer_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_mock_sanity_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_mock_tcp_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_mock_tcp_interleaving_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_queue_sanity_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_queue_basic_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_queue_overflow_underflow_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_queue_interleaved_wrapper,
#else
    NULL,
#endif
/* Function Id: 9 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_queue_insufficient_buffer_wrapper,
#else
    NULL,
#endif
/* Function Id: 10 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_uninitialized_wrapper,
#else
    NULL,
#endif
/* Function Id: 11 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_basic_wrapper,
#else
    NULL,
#endif
/* Function Id: 12 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_queue_overflow_underflow_wrapper,
#else
    NULL,
#endif
/* Function Id: 13 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_socket_overflow_wrapper,
#else
    NULL,
#endif
/* Function Id: 14 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_truncated_wrapper,
#else
    NULL,
#endif
/* Function Id: 15 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_socket_read_error_wrapper,
#else
    NULL,
#endif
/* Function Id: 16 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_interleaved_one_way_wrapper,
#else
    NULL,
#endif
/* Function Id: 17 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_message_mock_interleaved_two_ways_wrapper,
#else
    NULL,
#endif
/* Function Id: 18 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    test_ssl_dtls_replay_wrapper,
#else
    NULL,
#endif
/* Function Id: 19 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C)
    test_ssl_set_hostname_twice_wrapper,
#else
    NULL,
#endif
/* Function Id: 20 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_crypt_record_wrapper,
#else
    NULL,
#endif
/* Function Id: 21 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_crypt_record_small_wrapper,
#else
    NULL,
#endif
/* Function Id: 22 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_CIPHER_MODE_CBC) && defined(MBEDTLS_AES_C) && defined(MBEDTLS_SSL_PROTO_TLS1_2)
    test_ssl_decrypt_non_etm_cbc_wrapper,
#else
    NULL,
#endif
/* Function Id: 23 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
    test_ssl_tls1_3_hkdf_expand_label_wrapper,
#else
    NULL,
#endif
/* Function Id: 24 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
    test_ssl_tls1_3_traffic_key_generation_wrapper,
#else
    NULL,
#endif
/* Function Id: 25 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
    test_ssl_tls1_3_derive_secret_wrapper,
#else
    NULL,
#endif
/* Function Id: 26 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
    test_ssl_tls1_3_key_evolution_wrapper,
#else
    NULL,
#endif
/* Function Id: 27 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_tls_prf_wrapper,
#else
    NULL,
#endif
/* Function Id: 28 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_serialize_session_save_load_wrapper,
#else
    NULL,
#endif
/* Function Id: 29 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_serialize_session_load_save_wrapper,
#else
    NULL,
#endif
/* Function Id: 30 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_serialize_session_save_buf_size_wrapper,
#else
    NULL,
#endif
/* Function Id: 31 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_serialize_session_load_buf_size_wrapper,
#else
    NULL,
#endif
/* Function Id: 32 */

#if defined(MBEDTLS_SSL_TLS_C)
    test_ssl_session_serialize_version_check_wrapper,
#else
    NULL,
#endif
/* Function Id: 33 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C)
    test_mbedtls_endpoint_sanity_wrapper,
#else
    NULL,
#endif
/* Function Id: 34 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_ECP_C) && defined(MBEDTLS_SHA256_C)
    test_move_handshake_to_state_wrapper,
#else
    NULL,
#endif
/* Function Id: 35 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_ECP_C) && defined(MBEDTLS_SHA256_C) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_handshake_version_wrapper,
#else
    NULL,
#endif
/* Function Id: 36 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C)
    test_handshake_psk_cipher_wrapper,
#else
    NULL,
#endif
/* Function Id: 37 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C)
    test_handshake_cipher_wrapper,
#else
    NULL,
#endif
/* Function Id: 38 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C)
    test_app_data_wrapper,
#else
    NULL,
#endif
/* Function Id: 39 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_ECP_C) && defined(MBEDTLS_SHA256_C) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_app_data_tls_wrapper,
#else
    NULL,
#endif
/* Function Id: 40 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_app_data_dtls_wrapper,
#else
    NULL,
#endif
/* Function Id: 41 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_handshake_serialization_wrapper,
#else
    NULL,
#endif
/* Function Id: 42 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_DEBUG_C) && defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) && defined(MBEDTLS_CIPHER_MODE_CBC) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C) && defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
    test_handshake_fragmentation_wrapper,
#else
    NULL,
#endif
/* Function Id: 43 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_renegotiation_wrapper,
#else
    NULL,
#endif
/* Function Id: 44 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C)
    test_resize_buffers_wrapper,
#else
    NULL,
#endif
/* Function Id: 45 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH) && defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_resize_buffers_serialize_mfl_wrapper,
#else
    NULL,
#endif
/* Function Id: 46 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_SHA256_C) && defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_CAN_HANDLE_RSA_TEST_KEY)
    test_resize_buffers_renegotiate_mfl_wrapper,
#else
    NULL,
#endif
/* Function Id: 47 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) && defined(MBEDTLS_CERTS_C) && defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) && defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_RSA_C) && defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_ECP_C) && defined(MBEDTLS_ECDSA_C)
    test_raw_key_agreement_fail_wrapper,
#else
    NULL,
#endif
/* Function Id: 48 */

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(MBEDTLS_TEST_HOOKS)
    test_cookie_parsing_wrapper,
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
    const char *default_filename = "./test_suite_ssl.datax";
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
