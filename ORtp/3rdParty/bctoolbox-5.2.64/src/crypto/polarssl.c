/*
 * Copyright (c) 2016-2020 Belledonne Communications SARL.
 *
 * This file is part of bctoolbox.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "utils.h"
#include <bctoolbox/crypto.h>

#include <polarssl/ssl.h>
#include <polarssl/error.h>
#include <polarssl/pem.h>
#include "polarssl/base64.h"
#include <polarssl/x509.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/md5.h>
#include <polarssl/sha1.h>
#include <polarssl/sha256.h>
#include <polarssl/sha512.h>
#include <polarssl/gcm.h>

#include "bctoolbox/logging.h"

#ifdef _WIN32
#define snprintf _snprintf
#endif

/*** Cleaning ***/
/**
 * @brief force a buffer value to zero in a way that shall prevent the compiler from optimizing it out
 *
 * @param[in/out]	buffer	the buffer to be cleared
 * @param[in]		size	buffer size
 */
void bctbx_clean(void *buffer, size_t size) {
	volatile uint8_t *p = buffer;
	while(size--) *p++ = 0;
}

static int bctbx_ssl_sendrecv_callback_return_remap(int32_t ret_code) {
	switch (ret_code) {
		case BCTBX_ERROR_NET_WANT_READ:
			return POLARSSL_ERR_NET_WANT_READ;
		case BCTBX_ERROR_NET_WANT_WRITE:
			return POLARSSL_ERR_NET_WANT_WRITE;
		case BCTBX_ERROR_NET_CONN_RESET:
			return POLARSSL_ERR_NET_CONN_RESET;
		default:
			return (int)ret_code;
	}
}

bctbx_type_implementation_t bctbx_ssl_get_implementation_type(void) {
	return BCTBX_POLARSSL;
}

void bctbx_strerror(int32_t error_code, char *buffer, size_t buffer_length) {
	if (error_code>0) {
		snprintf(buffer, buffer_length, "%s", "Invalid Error code");
		return ;
	}

	/* polarssl error code are all negatived and bas smaller than 0x0000F000 */
	/* bctoolbox defined error codes are all in format -0x7XXXXXXX */
	if (-error_code<0x00010000) { /* it's a polarssl error code */
		error_strerror(error_code, buffer, buffer_length);
		return;
	}

	snprintf(buffer, buffer_length, "%s [-0x%x]", "bctoolbox defined error code", -error_code);
	return;
}

int32_t bctbx_base64_encode(unsigned char *output, size_t *output_length, const unsigned char *input, size_t input_length) {
	int ret = base64_encode(output, output_length, input, input_length);
	if (ret == POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL) {
		return BCTBX_ERROR_OUTPUT_BUFFER_TOO_SMALL;
	}
	return ret;
}

int32_t bctbx_base64_decode(unsigned char *output, size_t *output_length, const unsigned char *input, size_t input_length) {
	int ret = base64_decode(output, output_length, input, input_length);
	if (ret == POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL) {
		return BCTBX_ERROR_OUTPUT_BUFFER_TOO_SMALL;
	}
	if (ret == POLARSSL_ERR_BASE64_INVALID_CHARACTER) {
		return BCTBX_ERROR_INVALID_BASE64_INPUT;
	}

	return ret;
}

/*** Random Number Generation ***/
struct bctbx_rng_context_struct {
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
};

bctbx_rng_context_t *bctbx_rng_context_new(void) {
	bctbx_rng_context_t *ctx = bctbx_malloc0(sizeof(bctbx_rng_context_t));
	entropy_init(&(ctx->entropy));
	ctr_drbg_init(&(ctx->ctr_drbg), entropy_func, &(ctx->entropy), NULL, 0);
	return ctx;
}

int32_t bctbx_rng_get(bctbx_rng_context_t *context, unsigned char*output, size_t output_length) {
	return ctr_drbg_random(&(context->ctr_drbg), output, output_length);
}

void bctbx_rng_context_free(bctbx_rng_context_t *context) {
/* ctr_drg_free function is available from polarssl1.3.8 but we want to support previous versions */
#ifdef HAVE_CTR_DRGB_FREE
	ctr_drbg_free(&(context->ctr_drbg));
#endif
	entropy_free(&(context->entropy));
	bctbx_free(context);
}

/*** signing key ***/
bctbx_signing_key_t *bctbx_signing_key_new(void) {
	pk_context *key = bctbx_malloc0(sizeof(pk_context));
	pk_init(key);
	return (bctbx_signing_key_t *)key;
}

void bctbx_signing_key_free(bctbx_signing_key_t *key) {
	pk_free((pk_context *)key);
	bctbx_free(key);
}

char *bctbx_signing_key_get_pem(bctbx_signing_key_t *key) {
	char *pem_key;
	if (key == NULL) return NULL;
	pem_key = (char *)bctbx_malloc0(4096);
	pk_write_key_pem( (pk_context *)key, (unsigned char *)pem_key, 4096);
	return pem_key;
}

int32_t bctbx_signing_key_parse(bctbx_signing_key_t *key, const char *buffer, size_t buffer_length, const unsigned char *password, size_t password_length) {
	int err;
	err=pk_parse_key((pk_context *)key, (const unsigned char *)buffer, buffer_length+1, password, password_length);
	if(err==0 && !pk_can_do((pk_context *)key, POLARSSL_PK_RSA)) {
		err=POLARSSL_ERR_PK_TYPE_MISMATCH;
	}
	if (err<0) {
		char tmp[128];
		error_strerror(err,tmp,sizeof(tmp));
		bctbx_error("cannot parse public key because [%s]",tmp);
		return BCTBX_ERROR_UNABLE_TO_PARSE_KEY;
	}
	return 0;
}

int32_t bctbx_signing_key_parse_file(bctbx_signing_key_t *key, const char *path, const char *password) {
	int err;
	err=pk_parse_keyfile((pk_context *)key, path, password);
	if(err==0 && !pk_can_do((pk_context *)key,POLARSSL_PK_RSA)) {
		err=POLARSSL_ERR_PK_TYPE_MISMATCH;
	}
	if (err<0) {
		char tmp[128];
		error_strerror(err,tmp,sizeof(tmp));
		bctbx_error("cannot parse public key because [%s]",tmp);
		return BCTBX_ERROR_UNABLE_TO_PARSE_KEY;
	}
	return 0;
}



/*** Certificate ***/
char *bctbx_x509_certificates_chain_get_pem(const bctbx_x509_certificate_t *cert) {
	char *pem_certificate = NULL;
	size_t olen=0;

	pem_certificate = (char *)bctbx_malloc0(4096);
	pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n", ((x509_crt *)cert)->raw.p, ((x509_crt *)cert)->raw.len, (unsigned char*)pem_certificate, 4096, &olen );
	return pem_certificate;
}


bctbx_x509_certificate_t *bctbx_x509_certificate_new(void) {
	x509_crt *cert = bctbx_malloc0(sizeof(x509_crt));
	x509_crt_init(cert);
	return (bctbx_x509_certificate_t *)cert;
}

void bctbx_x509_certificate_free(bctbx_x509_certificate_t *cert) {
	x509_crt_free((x509_crt *)cert);
	bctbx_free(cert);
}

int32_t bctbx_x509_certificate_get_info_string(char *buf, size_t size, const char *prefix, const bctbx_x509_certificate_t *cert) {
	return x509_crt_info(buf, size, prefix, (x509_crt *)cert);
}

int32_t bctbx_x509_certificate_parse_file(bctbx_x509_certificate_t *cert, const char *path) {
	return x509_crt_parse_file((x509_crt *)cert, path);
}

int32_t bctbx_x509_certificate_parse_path(bctbx_x509_certificate_t *cert, const char *path) {
	return x509_crt_parse_path((x509_crt *)cert, path);
}

int32_t bctbx_x509_certificate_parse(bctbx_x509_certificate_t *cert, const char *buffer, size_t buffer_length) {
	return x509_crt_parse((x509_crt *)cert, (const unsigned char *)buffer, buffer_length+1);
}

int32_t bctbx_x509_certificate_get_der_length(bctbx_x509_certificate_t *cert) {
	if (cert!=NULL) {
		return ((x509_crt *)cert)->raw.len;
	}
	return 0;
}

int32_t bctbx_x509_certificate_get_der(bctbx_x509_certificate_t *cert, unsigned char *buffer, size_t buffer_length) {
	if (cert==NULL) {
		return BCTBX_ERROR_INVALID_CERTIFICATE;
	}
	if (((x509_crt *)cert)->raw.len>buffer_length-1) { /* check buffer size is ok, +1 for the NULL termination added at the end */
		return BCTBX_ERROR_OUTPUT_BUFFER_TOO_SMALL;
	}
	memcpy(buffer, ((x509_crt *)cert)->raw.p, ((x509_crt *)cert)->raw.len);
	buffer[((x509_crt *)cert)->raw.len] = '\0'; /* add a null termination char */

	return 0;
}

int32_t bctbx_x509_certificate_get_subject_dn(const bctbx_x509_certificate_t *cert, char *dn, size_t dn_length) {
	if (cert==NULL) {
		return BCTBX_ERROR_INVALID_CERTIFICATE;
	}

	return x509_dn_gets(dn, dn_length, &(((x509_crt *)cert)->subject));
}

bctbx_list_t *bctbx_x509_certificate_get_subjects(const bctbx_x509_certificate_t *cert){
	bctbx_error("bctbx_x509_certificate_get_subjects(): not implemented for polarssl.");
	return NULL;
}

int32_t bctbx_x509_certificate_generate_selfsigned(const char *subject, bctbx_x509_certificate_t *certificate, bctbx_signing_key_t *pkey, char * pem, size_t pem_length) {
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	int ret;
	mpi serial;
	x509write_cert crt;
	char file_buffer[8192];
	size_t file_buffer_len = 0;
	char formatted_subject[512];

	/* subject may be a sip URL or linphone-dtls-default-identity, add CN= before it to make a valid name */
	memcpy(formatted_subject, "CN=", 3);
	memcpy(formatted_subject+3, subject, strlen(subject)+1); /* +1 to get the \0 termination */

	entropy_init( &entropy );
	if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy, NULL, 0 ) )   != 0 )
	{
		bctbx_error("Certificate generation can't init ctr_drbg: -%x", -ret);
		return BCTBX_ERROR_CERTIFICATE_GENERATION_FAIL;
	}

	/* generate 3072 bits RSA public/private key */
	if ( (ret = pk_init_ctx( (pk_context *)pkey, pk_info_from_type( POLARSSL_PK_RSA ) )) != 0) {
		bctbx_error("Certificate generation can't init pk_ctx: -%x", -ret);
		return BCTBX_ERROR_CERTIFICATE_GENERATION_FAIL;
	}

	if ( ( ret = rsa_gen_key( pk_rsa( *(pk_context *)pkey ), ctr_drbg_random, &ctr_drbg, 3072, 65537 ) ) != 0) {
		bctbx_error("Certificate generation can't generate rsa key: -%x", -ret);
		return BCTBX_ERROR_CERTIFICATE_GENERATION_FAIL;
	}

	/* if there is no pem pointer, don't save the key in pem format */
	if (pem!=NULL) {
		pk_write_key_pem((pk_context *)pkey, (unsigned char *)file_buffer, 4096);
		file_buffer_len = strlen(file_buffer);
	}

	/* generate the certificate */
	x509write_crt_init( &crt );
	x509write_crt_set_md_alg( &crt, POLARSSL_MD_SHA256 );

	mpi_init( &serial );

	if ( (ret = mpi_read_string( &serial, 10, "1" ) ) != 0 ) {
		bctbx_error("Certificate generation can't read serial mpi: -%x", -ret);
		return BCTBX_ERROR_CERTIFICATE_GENERATION_FAIL;
	}

	x509write_crt_set_subject_key( &crt, (pk_context *)pkey);
	x509write_crt_set_issuer_key( &crt, (pk_context *)pkey);

	if ( (ret = x509write_crt_set_subject_name( &crt, formatted_subject) ) != 0) {
		bctbx_error("Certificate generation can't set subject name: -%x", -ret);
		return BCTBX_ERROR_CERTIFICATE_GENERATION_FAIL;
	}

	if ( (ret = x509write_crt_set_issuer_name( &crt, formatted_subject) ) != 0) {
		bctbx_error("Certificate generation can't set issuer name: -%x", -ret);
		return BCTBX_ERROR_CERTIFICATE_GENERATION_FAIL;
	}

	if ( (ret = x509write_crt_set_serial( &crt, &serial ) ) != 0) {
		bctbx_error("Certificate generation can't set serial: -%x", -ret);
		return BCTBX_ERROR_CERTIFICATE_GENERATION_FAIL;
	}
	mpi_free(&serial);

	if ( (ret = x509write_crt_set_validity( &crt, "20010101000000", "20300101000000" ) ) != 0) {
		bctbx_error("Certificate generation can't set validity: -%x", -ret);
		return BCTBX_ERROR_CERTIFICATE_GENERATION_FAIL;
	}

	/* store anyway certificate in pem format in a string even if we do not have file to write as we need it to get it in a x509_crt structure */
	if ( (ret = x509write_crt_pem( &crt, (unsigned char *)file_buffer+file_buffer_len, 4096, ctr_drbg_random, &ctr_drbg ) ) != 0) {
		bctbx_error("Certificate generation can't write crt pem: -%x", -ret);
		return BCTBX_ERROR_CERTIFICATE_WRITE_PEM;
	}

	x509write_crt_free(&crt);
/* ctr_drg_free function is available from polarssl1.3.8 but we want to support previous versions */
#ifdef HAVE_CTR_DRGB_FREE
	ctr_drbg_free(&ctr_drbg);
#endif
	entropy_free(&entropy);

	/* copy the key+cert in pem format into the given buffer */
	if (pem != NULL) {
		if (strlen(file_buffer)+1>pem_length) {
			bctbx_error("Certificate generation can't copy the certificate to pem buffer: too short [%ld] but need [%ld] bytes", (long)pem_length, (long)strlen(file_buffer));
			return BCTBX_ERROR_OUTPUT_BUFFER_TOO_SMALL;
		}
		strncpy(pem, file_buffer, pem_length);
	}

	if ( (ret = x509_crt_parse((x509_crt *)certificate, (unsigned char *)file_buffer, strlen(file_buffer)) ) != 0) {
		bctbx_error("Certificate generation can't parse crt pem: -%x", -ret);
		return BCTBX_ERROR_CERTIFICATE_PARSE_PEM;
	}

	return 0;
}


int32_t bctbx_x509_certificate_get_signature_hash_function(const bctbx_x509_certificate_t *certificate, bctbx_md_type_t *hash_algorithm) {

	x509_crt *crt;
	if (certificate == NULL) return BCTBX_ERROR_INVALID_CERTIFICATE;

	crt = (x509_crt *)certificate;

	switch (crt->sig_md) {
		case POLARSSL_MD_SHA1:
			*hash_algorithm = BCTBX_MD_SHA1;
		break;

		case POLARSSL_MD_SHA224:
			*hash_algorithm = BCTBX_MD_SHA224;
		break;

		case POLARSSL_MD_SHA256:
			*hash_algorithm = BCTBX_MD_SHA256;
		break;

		case POLARSSL_MD_SHA384:
			*hash_algorithm = BCTBX_MD_SHA384;
		break;

		case POLARSSL_MD_SHA512:
			*hash_algorithm = BCTBX_MD_SHA512;
		break;

		default:
			*hash_algorithm = BCTBX_MD_UNDEFINED;
			return BCTBX_ERROR_UNSUPPORTED_HASH_FUNCTION;
		break;
	}

	return 0;

}

/* maximum length of returned buffer will be 7(SHA-512 string)+3*hash_length(64)+null char = 200 bytes */
int32_t bctbx_x509_certificate_get_fingerprint(const bctbx_x509_certificate_t *certificate, char *fingerprint, size_t fingerprint_length, bctbx_md_type_t hash_algorithm) {
	unsigned char buffer[64]={0}; /* buffer is max length of returned hash, which is 64 in case we use sha-512 */
	size_t hash_length = 0;
	const char *hash_alg_string=NULL;
	size_t fingerprint_size = 0;
	x509_crt *crt;
	md_type_t hash_id;
	if (certificate == NULL) return BCTBX_ERROR_INVALID_CERTIFICATE;

	crt = (x509_crt *)certificate;

	/* if there is a specified hash algorithm, use it*/
	switch (hash_algorithm) {
		case BCTBX_MD_SHA1:
			hash_id = POLARSSL_MD_SHA1;
			break;
		case BCTBX_MD_SHA224:
			hash_id = POLARSSL_MD_SHA224;
			break;
		case BCTBX_MD_SHA256:
			hash_id = POLARSSL_MD_SHA256;
			break;
		case BCTBX_MD_SHA384:
			hash_id = POLARSSL_MD_SHA384;
			break;
		case BCTBX_MD_SHA512:
			hash_id = POLARSSL_MD_SHA512;
			break;
		default: /* nothing specified, use the hash algo used in the certificate signature */
			hash_id = crt->sig_md;
			break;
	}

	/* fingerprint is a hash of the DER formated certificate (found in crt->raw.p) using the same hash function used by certificate signature */
	switch (hash_id) {
		case POLARSSL_MD_SHA1:
			sha1(crt->raw.p, crt->raw.len, buffer);
			hash_length = 20;
			hash_alg_string="SHA-1";
		break;

		case POLARSSL_MD_SHA224:
			sha256(crt->raw.p, crt->raw.len, buffer, 1); /* last argument is a boolean, indicate to output sha-224 and not sha-256 */
			hash_length = 28;
			hash_alg_string="SHA-224";
		break;

		case POLARSSL_MD_SHA256:
			sha256(crt->raw.p, crt->raw.len, buffer, 0);
			hash_length = 32;
			hash_alg_string="SHA-256";
		break;

		case POLARSSL_MD_SHA384:
			sha512(crt->raw.p, crt->raw.len, buffer, 1); /* last argument is a boolean, indicate to output sha-384 and not sha-512 */
			hash_length = 48;
			hash_alg_string="SHA-384";
		break;

		case POLARSSL_MD_SHA512:
            sha512(crt->raw.p, crt->raw.len, buffer, 0);
			hash_length = 64;
			hash_alg_string="SHA-512";
		break;

		default:
			return BCTBX_ERROR_UNSUPPORTED_HASH_FUNCTION;
		break;
	}

	if (hash_length>0) {
		size_t i;
		int fingerprint_index = strlen(hash_alg_string);
		char prefix=' ';

		fingerprint_size=fingerprint_index+3*hash_length+1;
		/* fingerprint will be : hash_alg_string+' '+HEX : separated values: length is strlen(hash_alg_string)+3*hash_lenght + 1 for null termination */
		if (fingerprint_length<fingerprint_size) {
			return BCTBX_ERROR_OUTPUT_BUFFER_TOO_SMALL;
		}

		snprintf(fingerprint, fingerprint_size, "%s", hash_alg_string);
		for (i=0; i<hash_length; i++, fingerprint_index+=3) {
			snprintf((char*)fingerprint+fingerprint_index, fingerprint_size-fingerprint_index, "%c%02X", prefix,buffer[i]);
			prefix=':';
		}
		*(fingerprint+fingerprint_index) = '\0';
	}

	return (int32_t)fingerprint_size;
}

#define BCTBX_MAX_CERTIFICATE_FLAGS_STRING_LENGTH 128
int32_t bctbx_x509_certificate_flags_to_string(char *buffer, size_t buffer_size, uint32_t flags) {
	size_t i=0;
	char outputString[BCTBX_MAX_CERTIFICATE_FLAGS_STRING_LENGTH];

	if (flags & BADCERT_EXPIRED)
		i+=snprintf(outputString+i, BCTBX_MAX_CERTIFICATE_FLAGS_STRING_LENGTH-i, "expired ");
	if (flags & BADCERT_REVOKED)
		i+=snprintf(outputString+i, BCTBX_MAX_CERTIFICATE_FLAGS_STRING_LENGTH-i, "revoked ");
	if (flags & BADCERT_CN_MISMATCH)
		i+=snprintf(outputString+i, BCTBX_MAX_CERTIFICATE_FLAGS_STRING_LENGTH-i, "CN-mismatch ");
	if (flags & BADCERT_NOT_TRUSTED)
		i+=snprintf(outputString+i, BCTBX_MAX_CERTIFICATE_FLAGS_STRING_LENGTH-i, "not-trusted ");
	if (flags & BADCERT_MISSING)
		i+=snprintf(outputString+i, BCTBX_MAX_CERTIFICATE_FLAGS_STRING_LENGTH-i, "missing ");
	if (flags & BADCRL_NOT_TRUSTED)
		i+=snprintf(outputString+i, BCTBX_MAX_CERTIFICATE_FLAGS_STRING_LENGTH-i, "crl-not-trusted ");
	if (flags & BADCRL_EXPIRED)
		i+=snprintf(outputString+i, BCTBX_MAX_CERTIFICATE_FLAGS_STRING_LENGTH-i, "crl-expired ");

	outputString[i] = '\0'; /* null terminate the string */

	if (i+1>buffer_size) {
		return BCTBX_ERROR_OUTPUT_BUFFER_TOO_SMALL;
	}

	strncpy(buffer, outputString, buffer_size);

	return 0;
}

int32_t bctbx_x509_certificate_set_flag(uint32_t *flags, uint32_t flags_to_set) {
	if (flags_to_set & BCTBX_CERTIFICATE_VERIFY_BADCERT_EXPIRED)
		*flags |= BADCERT_EXPIRED;
	if (flags_to_set & BCTBX_CERTIFICATE_VERIFY_BADCERT_REVOKED)
		*flags |= BADCERT_REVOKED;
	if (flags_to_set & BCTBX_CERTIFICATE_VERIFY_BADCERT_CN_MISMATCH)
		*flags |= BADCERT_CN_MISMATCH;
	if (flags_to_set & BCTBX_CERTIFICATE_VERIFY_BADCERT_NOT_TRUSTED)
		*flags |= BADCERT_NOT_TRUSTED;
	if (flags_to_set & BCTBX_CERTIFICATE_VERIFY_BADCERT_MISSING)
		*flags |= BADCERT_MISSING;
	if (flags_to_set & BCTBX_CERTIFICATE_VERIFY_BADCRL_NOT_TRUSTED)
		*flags |= BADCRL_NOT_TRUSTED;
	if (flags_to_set & BCTBX_CERTIFICATE_VERIFY_BADCRL_EXPIRED)
		*flags |= BADCRL_EXPIRED;

	return 0;
}

uint32_t bctbx_x509_certificate_remap_flag(uint32_t flags) {
	uint32_t ret = 0;
	if (flags & BADCERT_EXPIRED)
		ret |= BCTBX_CERTIFICATE_VERIFY_BADCERT_EXPIRED;
	if (flags & BADCERT_REVOKED)
		ret |= BCTBX_CERTIFICATE_VERIFY_BADCERT_REVOKED;
	if (flags & BADCERT_CN_MISMATCH)
		ret |= BCTBX_CERTIFICATE_VERIFY_BADCERT_CN_MISMATCH;
	if (flags & BADCERT_NOT_TRUSTED)
		ret |= BCTBX_CERTIFICATE_VERIFY_BADCERT_NOT_TRUSTED;
	if (flags & BADCERT_MISSING)
		ret |= BCTBX_CERTIFICATE_VERIFY_BADCERT_MISSING;
	if (flags & BADCRL_NOT_TRUSTED)
		ret |= BCTBX_CERTIFICATE_VERIFY_BADCRL_NOT_TRUSTED;
	if (flags & BADCRL_EXPIRED)
		ret |= BCTBX_CERTIFICATE_VERIFY_BADCRL_EXPIRED;

	return ret;
}

int32_t bctbx_x509_certificate_unset_flag(uint32_t *flags, uint32_t flags_to_unset) {
	if (flags_to_unset & BCTBX_CERTIFICATE_VERIFY_BADCERT_EXPIRED)
		*flags &= ~BADCERT_EXPIRED;
	if (flags_to_unset & BCTBX_CERTIFICATE_VERIFY_BADCERT_REVOKED)
		*flags &= ~BADCERT_REVOKED;
	if (flags_to_unset & BCTBX_CERTIFICATE_VERIFY_BADCERT_CN_MISMATCH)
		*flags &= ~BADCERT_CN_MISMATCH;
	if (flags_to_unset & BCTBX_CERTIFICATE_VERIFY_BADCERT_NOT_TRUSTED)
		*flags &= ~BADCERT_NOT_TRUSTED;
	if (flags_to_unset & BCTBX_CERTIFICATE_VERIFY_BADCERT_MISSING)
		*flags &= ~BADCERT_MISSING;
	if (flags_to_unset & BCTBX_CERTIFICATE_VERIFY_BADCRL_NOT_TRUSTED)
		*flags &= ~BADCRL_NOT_TRUSTED;
	if (flags_to_unset & BCTBX_CERTIFICATE_VERIFY_BADCRL_EXPIRED)
		*flags &= ~BADCRL_EXPIRED;

	return 0;
}
/*** Diffie-Hellman-Merkle  ***/
/* initialise de DHM context according to requested algorithm */
bctbx_DHMContext_t *bctbx_CreateDHMContext(uint8_t DHMAlgo, uint8_t secretLength)
{
	dhm_context *polarsslDhmContext;

	/* create the context */
	bctbx_DHMContext_t *context = (bctbx_DHMContext_t *)malloc(sizeof(bctbx_DHMContext_t));
	memset (context, 0, sizeof(bctbx_DHMContext_t));

	/* create the polarssl context for DHM */
	polarsslDhmContext=(dhm_context *)malloc(sizeof(dhm_context));
	memset(polarsslDhmContext, 0, sizeof(dhm_context));
	context->cryptoModuleData=(void *)polarsslDhmContext;

	/* initialise pointer to NULL to ensure safe call to free() when destroying context */
	context->secret = NULL;
	context->self = NULL;
	context->key = NULL;
	context->peer = NULL;

	/* set parameters in the context */
	context->algo=DHMAlgo;
	context->secretLength = secretLength;
	switch (DHMAlgo) {
		case BCTBX_DHM_2048:
			/* set P and G in the polarssl context */
			if ((mpi_read_string(&(polarsslDhmContext->P), 16, POLARSSL_DHM_RFC3526_MODP_2048_P) != 0) ||
			(mpi_read_string(&(polarsslDhmContext->G), 16, POLARSSL_DHM_RFC3526_MODP_2048_G) != 0)) {
				return NULL;
			}
			context->primeLength=256;
			polarsslDhmContext->len=256;
			break;
		case BCTBX_DHM_3072:
			/* set P and G in the polarssl context */
			if ((mpi_read_string(&(polarsslDhmContext->P), 16, POLARSSL_DHM_RFC3526_MODP_3072_P) != 0) ||
			(mpi_read_string(&(polarsslDhmContext->G), 16, POLARSSL_DHM_RFC3526_MODP_3072_G) != 0)) {
				return NULL;
			}
			context->primeLength=384;
			polarsslDhmContext->len=384;
			break;
		default:
			free(context);
			return NULL;
			break;
	}

	return context;
}

/* generate the random secret and compute the public value */
void bctbx_DHMCreatePublic(bctbx_DHMContext_t *context, int (*rngFunction)(void *, uint8_t *, size_t), void *rngContext) {
	/* get the polarssl context */
	dhm_context *polarsslContext = (dhm_context *)context->cryptoModuleData;

	/* allocate output buffer */
	context->self = (uint8_t *)malloc(context->primeLength*sizeof(uint8_t));

	dhm_make_public(polarsslContext, context->secretLength, context->self, context->primeLength, (int (*)(void *, unsigned char *, size_t))rngFunction, rngContext);

}

/* compute secret - the ->peer field of context must have been set before calling this function */
void bctbx_DHMComputeSecret(bctbx_DHMContext_t *context, int (*rngFunction)(void *, uint8_t *, size_t), void *rngContext) {
	size_t keyLength;
	uint8_t sharedSecretBuffer[384]; /* longest shared secret available in these mode */

	/* import the peer public value G^Y mod P in the polar ssl context */
	dhm_read_public((dhm_context *)(context->cryptoModuleData), context->peer, context->primeLength);

	/* compute the secret key */
	keyLength = context->primeLength; /* undocumented but this value seems to be in/out, so we must set it to the expected key length */
	context->key = (uint8_t *)malloc(keyLength*sizeof(uint8_t)); /* allocate and reset the key buffer */
	memset(context->key,0, keyLength);

	dhm_calc_secret((dhm_context *)(context->cryptoModuleData), sharedSecretBuffer, &keyLength, (int (*)(void *, unsigned char *, size_t))rngFunction, rngContext);
	/* now copy the resulting secret in the correct place in buffer(result may actually miss some front zero bytes, real length of output is now in keyLength but we want primeLength bytes) */
	memcpy(context->key+(context->primeLength-keyLength), sharedSecretBuffer, keyLength);
	memset(sharedSecretBuffer, 0, 384); /* purge secret from temporary buffer */
}

/* clean DHM context */
void bctbx_DestroyDHMContext(bctbx_DHMContext_t *context) {
	if (context!= NULL) {
		/* key and secret must be erased from memory and not just freed */
		if (context->secret != NULL) {
			memset(context->secret, 0, context->secretLength);
			free(context->secret);
		}
		free(context->self);
		if (context->key != NULL) {
			memset(context->key, 0, context->primeLength);
			free(context->key);
		}
		free(context->peer);

		dhm_free((dhm_context *)context->cryptoModuleData);
		free(context->cryptoModuleData);

		free(context);
	}
}

/*** SSL Client ***/
/** context **/
struct bctbx_ssl_context_struct {
	ssl_context ssl_ctx;
	char *cn;
	int(*callback_cli_cert_function)(void *, bctbx_ssl_context_t *, unsigned char *, size_t); /**< pointer to the callback called to update client certificate during handshake
													callback params are user_data, ssl_context, certificate distinguished name, name length */
	void *callback_cli_cert_data; /**< data passed to the client cert callback */
	int(*callback_send_function)(void *, const unsigned char *, size_t); /* callbacks args are: callback data, data buffer to be send, size of data buffer */
	int(*callback_recv_function)(void *, unsigned char *, size_t); /* args: callback data, data buffer to be read, size of data buffer */
	void *callback_sendrecv_data; /**< data passed to send/recv callbacks */
};

bctbx_ssl_context_t *bctbx_ssl_context_new(void) {
	bctbx_ssl_context_t *ssl_ctx = bctbx_malloc0(sizeof(bctbx_ssl_context_t));
	ssl_init(&(ssl_ctx->ssl_ctx));
	ssl_ctx->callback_cli_cert_function = NULL;
	ssl_ctx->callback_cli_cert_data = NULL;
	ssl_ctx->callback_send_function = NULL;
	ssl_ctx->callback_recv_function = NULL;
	ssl_ctx->callback_sendrecv_data = NULL;
	return ssl_ctx;
}

void bctbx_ssl_context_free(bctbx_ssl_context_t *ssl_ctx) {
	if (ssl_ctx->cn) bctbx_free(ssl_ctx->cn);
	ssl_free(&(ssl_ctx->ssl_ctx));
	bctbx_free(ssl_ctx);
}

int32_t bctbx_ssl_close_notify(bctbx_ssl_context_t *ssl_ctx) {
	return ssl_close_notify(&(ssl_ctx->ssl_ctx));
}

int32_t bctbx_ssl_session_reset(bctbx_ssl_context_t *ssl_ctx) {
	return ssl_session_reset(&(ssl_ctx->ssl_ctx));
}

int32_t bctbx_ssl_write(bctbx_ssl_context_t *ssl_ctx, const unsigned char *buf, size_t buf_length) {
	int ret = ssl_write(&(ssl_ctx->ssl_ctx), buf, buf_length);
	/* remap some output code */
	if (ret == POLARSSL_ERR_NET_WANT_WRITE) {
		ret = BCTBX_ERROR_NET_WANT_WRITE;
	}
	return ret;
}

int32_t bctbx_ssl_read(bctbx_ssl_context_t *ssl_ctx, unsigned char *buf, size_t buf_length) {
	int ret = ssl_read(&(ssl_ctx->ssl_ctx), buf, buf_length);
	/* remap some output code */
	if (ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY) {
		ret = BCTBX_ERROR_SSL_PEER_CLOSE_NOTIFY;
	}
	if (ret == POLARSSL_ERR_NET_WANT_READ) {
		ret = BCTBX_ERROR_NET_WANT_READ;
	}
	return ret;
}

int32_t bctbx_ssl_handshake(bctbx_ssl_context_t *ssl_ctx) {

	int ret = 0;
	while( ssl_ctx->ssl_ctx.state != SSL_HANDSHAKE_OVER )
	{
		ret = ssl_handshake_step(&(ssl_ctx->ssl_ctx));
		if( ret != 0 ) {
			break;
		}

		/* insert the callback function for client certificate request */
		if (ssl_ctx->callback_cli_cert_function != NULL) { /* check we have a callback function */
			/* when in state SSL_CLIENT_CERTIFICATE - which means, next call to ssl_handshake_step will send the client certificate to server -
			 * and the client_auth flag is set - which means the server requested a client certificate - */
			if (ssl_ctx->ssl_ctx.state == SSL_CLIENT_CERTIFICATE && ssl_ctx->ssl_ctx.client_auth > 0) {
				/* note: polarssl 1.3 is unable to retrieve certificate dn during handshake from server certificate request
				 * so the dn params in the callback are set to NULL and 0(dn string length) */
				if (ssl_ctx->callback_cli_cert_function(ssl_ctx->callback_cli_cert_data, ssl_ctx, NULL, 0)!=0) {
					if((ret=ssl_send_fatal_handshake_failure(&(ssl_ctx->ssl_ctx))) != 0 )
						return( ret );
				}
			}
		}

	}

	/* remap some output codes */
	if (ret == POLARSSL_ERR_NET_WANT_READ) {
		ret = BCTBX_ERROR_NET_WANT_READ;
	} else if (ret == POLARSSL_ERR_NET_WANT_WRITE) {
		ret = BCTBX_ERROR_NET_WANT_WRITE;
	}

	return(ret);
}

int32_t bctbx_ssl_set_hs_own_cert(bctbx_ssl_context_t *ssl_ctx, bctbx_x509_certificate_t *cert, bctbx_signing_key_t *key) {
	return ssl_set_own_cert(&(ssl_ctx->ssl_ctx) , (x509_crt *)cert , (pk_context *)key);
}

int bctbx_ssl_send_callback(void *data, const unsigned char *buffer, size_t buffer_length) {
	int ret = 0;
	/* data is the ssl_context which contains the actual callback and data */
	bctbx_ssl_context_t *ssl_ctx = (bctbx_ssl_context_t *)data;

	ret = ssl_ctx->callback_send_function(ssl_ctx->callback_sendrecv_data, buffer, buffer_length);

	return bctbx_ssl_sendrecv_callback_return_remap(ret);
}

int bctbx_ssl_recv_callback(void *data, unsigned char *buffer, size_t buffer_length) {
	int ret = 0;
	/* data is the ssl_context which contains the actual callback and data */
	bctbx_ssl_context_t *ssl_ctx = (bctbx_ssl_context_t *)data;

	ret = ssl_ctx->callback_recv_function(ssl_ctx->callback_sendrecv_data, buffer, buffer_length);

	return bctbx_ssl_sendrecv_callback_return_remap(ret);
}

void bctbx_ssl_set_io_callbacks(bctbx_ssl_context_t *ssl_ctx, void *callback_data,
		int(*callback_send_function)(void *, const unsigned char *, size_t), /* callbacks args are: callback data, data buffer to be send, size of data buffer */
		int(*callback_recv_function)(void *, unsigned char *, size_t)){ /* args: callback data, data buffer to be read, size of data buffer */

	if (ssl_ctx==NULL) {
		return;
	}

	ssl_ctx->callback_send_function = callback_send_function;
	ssl_ctx->callback_recv_function = callback_recv_function;
	ssl_ctx->callback_sendrecv_data = callback_data;

	ssl_set_bio(&(ssl_ctx->ssl_ctx), bctbx_ssl_recv_callback, ssl_ctx, bctbx_ssl_send_callback, ssl_ctx);
}

const bctbx_x509_certificate_t *bctbx_ssl_get_peer_certificate(bctbx_ssl_context_t *ssl_ctx) {
	return (const bctbx_x509_certificate_t *)ssl_get_peer_cert(&(ssl_ctx->ssl_ctx));
}

const char *bctbx_ssl_get_ciphersuite(bctbx_ssl_context_t *ssl_ctx){
	return ssl_get_ciphersuite(&(ssl_ctx->ssl_ctx));
}

int bctbx_ssl_get_ciphersuite_id(const char *ciphersuite){
	return BCTBX_ERROR_UNAVAILABLE_FUNCTION;
}
const char *bctbx_ssl_get_version(bctbx_ssl_context_t *ssl_ctx){
	return ssl_get_version(&(ssl_ctx->ssl_ctx));
}

int32_t bctbx_ssl_set_hostname(bctbx_ssl_context_t *ssl_ctx, const char *hostname){
	if (ssl_ctx->cn) bctbx_free(ssl_ctx->cn);
	if (hostname) ssl_ctx->cn = bctbx_strdup(hostname);
	else ssl_ctx->cn = NULL;
	ssl_ctx->ssl_ctx.peer_cn = ssl_ctx->cn;
	return 0;
}

/** DTLS SRTP functions **/
/* used for DTLS SRTP but not implemented on polarssl, available on mbedtls only */
void bctbx_ssl_set_mtu(bctbx_ssl_context_t *ssl_ctx, uint16_t mtu) { };

#ifdef HAVE_DTLS_SRTP
uint8_t bctbx_dtls_srtp_supported(void) {
	return 1;
}

static bctbx_dtls_srtp_profile_t bctbx_srtp_profile_polarssl2bctoolbox(enum DTLS_SRTP_protection_profiles polarssl_profile) {
	switch (polarssl_profile) {
		case SRTP_AES128_CM_HMAC_SHA1_80:
			return BCTBX_SRTP_AES128_CM_HMAC_SHA1_80;
		case SRTP_AES128_CM_HMAC_SHA1_32:
			return BCTBX_SRTP_AES128_CM_HMAC_SHA1_32;
		case SRTP_NULL_HMAC_SHA1_80:
			return BCTBX_SRTP_NULL_HMAC_SHA1_80;
		case SRTP_NULL_HMAC_SHA1_32:
			return BCTBX_SRTP_NULL_HMAC_SHA1_32;
		default:
			return BCTBX_SRTP_UNDEFINED;
	}
}

static enum DTLS_SRTP_protection_profiles bctbx_srtp_profile_bctoolbox2polarssl(bctbx_dtls_srtp_profile_t bctbx_profile) {
	switch (bctbx_profile) {
		case BCTBX_SRTP_AES128_CM_HMAC_SHA1_80:
			return SRTP_AES128_CM_HMAC_SHA1_80;
		case BCTBX_SRTP_AES128_CM_HMAC_SHA1_32:
			return SRTP_AES128_CM_HMAC_SHA1_32;
		case BCTBX_SRTP_NULL_HMAC_SHA1_80:
			return SRTP_NULL_HMAC_SHA1_80;
		case BCTBX_SRTP_NULL_HMAC_SHA1_32:
			return SRTP_NULL_HMAC_SHA1_32;
		default:
			return SRTP_UNSET_PROFILE;
	}
}

bctbx_dtls_srtp_profile_t bctbx_ssl_get_dtls_srtp_protection_profile(bctbx_ssl_context_t *ssl_ctx) {
	if (ssl_ctx==NULL) {
		return BCTBX_ERROR_INVALID_SSL_CONTEXT;
	}

	return bctbx_srtp_profile_polarssl2bctoolbox(ssl_get_dtls_srtp_protection_profile(&(ssl_ctx->ssl_ctx)));
};


int32_t bctbx_ssl_get_dtls_srtp_key_material(bctbx_ssl_context_t *ssl_ctx, char *output, size_t *output_length) {
	if (ssl_ctx==NULL) {
		return BCTBX_ERROR_INVALID_SSL_CONTEXT;
	}

	/* check output buffer size */
	if (*output_length<ssl_ctx->ssl_ctx.dtls_srtp_keys_len) {
		return BCTBX_ERROR_OUTPUT_BUFFER_TOO_SMALL;
	}

	memcpy(output, ssl_ctx->ssl_ctx.dtls_srtp_keys, ssl_ctx->ssl_ctx.dtls_srtp_keys_len);
	*output_length = ssl_ctx->ssl_ctx.dtls_srtp_keys_len;

	return 0;
}
#else /* HAVE_DTLS_SRTP */
/* dummy DTLS api when not available */
uint8_t bctbx_dtls_srtp_supported(void) {
	return 0;
}

bctbx_dtls_srtp_profile_t bctbx_ssl_get_dtls_srtp_protection_profile(bctbx_ssl_context_t *ssl_ctx) {
	return BCTBX_SRTP_UNDEFINED;
}

int32_t bctbx_ssl_get_dtls_srtp_key_material(bctbx_ssl_context_t *ssl_ctx, char *output, size_t *output_length) {
	*output_length = 0;
	return BCTBX_ERROR_UNAVAILABLE_FUNCTION;
}
#endif /* HAVE_DTLS_SRTP */

/** DTLS SRTP functions **/

/** config **/
struct bctbx_ssl_config_struct {
	int8_t endpoint; /**< BCTBX_SSL_IS_CLIENT or BCTBX_SSL_IS_SERVER */
	int8_t authmode; /**< BCTBX_SSL_VERIFY_NONE, BCTBX_SSL_VERIFY_OPTIONAL, BCTBX_SSL_VERIFY_REQUIRED */
	int8_t transport; /**< BCTBX_SSL_TRANSPORT_STREAM(TLS) or BCTBX_SSL_TRANSPORT_DATAGRAM(DTLS) */
	int(*rng_function)(void *, unsigned char *, size_t); /**< pointer to a random number generator function */
	void *rng_context; /**< pointer to a the random number generator context */
	int(*callback_verify_function)(void *, x509_crt *, int, int *); /**< pointer to the verify callback function */
	void *callback_verify_data; /**< data passed to the verify callback */
	x509_crt *ca_chain; /**< trusted CA chain */
	x509_crt *own_cert;
	pk_context *own_cert_pk;
	int(*callback_cli_cert_function)(void *, bctbx_ssl_context_t *, unsigned char *, size_t); /**< pointer to the callback called to update client certificate during handshake
													callback params are user_data, ssl_context, certificate distinguished name, name length */
	void *callback_cli_cert_data; /**< data passed to the client cert callback */
#ifdef HAVE_DTLS_SRTP
	enum DTLS_SRTP_protection_profiles dtls_srtp_profiles[4]; /**< Store a maximum of 4 DTLS SRTP profiles to use */
	int dtls_srtp_profiles_number; /**< Number of DTLS SRTP profiles in use */
#endif
};

bctbx_ssl_config_t *bctbx_ssl_config_new(void) {
#ifdef HAVE_DTLS_SRTP
	int i;
#endif
	bctbx_ssl_config_t *ssl_config = bctbx_malloc0(sizeof(bctbx_ssl_config_t));

	/* set all properties to BCTBX_SSL_UNSET or NULL */
	ssl_config->endpoint = BCTBX_SSL_UNSET;
	ssl_config->authmode = BCTBX_SSL_UNSET;
	ssl_config->transport = BCTBX_SSL_UNSET;
	ssl_config->rng_function = NULL;
	ssl_config->rng_context = NULL;
	ssl_config->callback_verify_function= NULL;
	ssl_config->callback_verify_data = NULL;
	ssl_config->callback_cli_cert_function = NULL;
	ssl_config->callback_cli_cert_data = NULL;
	ssl_config->ca_chain = NULL;
	ssl_config->own_cert = NULL;
	ssl_config->own_cert_pk = NULL;
#ifdef HAVE_DTLS_SRTP
	for (i=0; i<4; i++) {
		ssl_config->dtls_srtp_profiles[i] = SRTP_UNSET_PROFILE;
	}
	ssl_config->dtls_srtp_profiles_number = 0;
#endif
	return ssl_config;
}

int32_t bctbx_ssl_config_set_crypto_library_config(bctbx_ssl_config_t *ssl_config, void *internal_config) {
	return BCTBX_ERROR_UNAVAILABLE_FUNCTION;
}

void bctbx_ssl_config_free(bctbx_ssl_config_t *ssl_config) {
	bctbx_free(ssl_config);
}

int32_t bctbx_ssl_config_defaults(bctbx_ssl_config_t *ssl_config, int endpoint, int transport) {
	if (ssl_config != NULL) {
		if (endpoint == BCTBX_SSL_IS_CLIENT) {
			ssl_config->endpoint = SSL_IS_CLIENT;
		} else if (endpoint == BCTBX_SSL_IS_SERVER) {
			ssl_config->endpoint = SSL_IS_SERVER;
		} else {
			return BCTBX_ERROR_INVALID_SSL_ENDPOINT;
		}
/* useful only for versions of polarssl which have SSL_TRANSPORT_XXX defined */
#ifdef SSL_TRANSPORT_DATAGRAM
		if (transport == BCTBX_SSL_TRANSPORT_STREAM) {
			ssl_config->transport = SSL_TRANSPORT_STREAM;
		} else if (transport == BCTBX_SSL_TRANSPORT_DATAGRAM) {
			ssl_config->transport = SSL_TRANSPORT_DATAGRAM;
		} else {
			return BCTBX_ERROR_INVALID_SSL_TRANSPORT;
		}
#endif
		return 0;
	}
	return BCTBX_ERROR_INVALID_SSL_CONFIG;
}

int32_t bctbx_ssl_config_set_endpoint(bctbx_ssl_config_t *ssl_config, int endpoint) {
	if (ssl_config == NULL) {
		return BCTBX_ERROR_INVALID_SSL_CONFIG;
	}

	if (endpoint == BCTBX_SSL_IS_CLIENT) {
		ssl_config->endpoint = SSL_IS_CLIENT;
	} else if (endpoint == BCTBX_SSL_IS_SERVER) {
		ssl_config->endpoint = SSL_IS_SERVER;
	} else {
		return BCTBX_ERROR_INVALID_SSL_ENDPOINT;
	}

	return 0;
}

int32_t bctbx_ssl_config_set_transport (bctbx_ssl_config_t *ssl_config, int transport) {
	if (ssl_config == NULL) {
		return BCTBX_ERROR_INVALID_SSL_CONFIG;
	}

/* useful only for versions of polarssl which have SSL_TRANSPORT_XXX defined */
#ifdef SSL_TRANSPORT_DATAGRAM
		if (transport == BCTBX_SSL_TRANSPORT_STREAM) {
			ssl_config->transport = SSL_TRANSPORT_STREAM;
		} else if (transport == BCTBX_SSL_TRANSPORT_DATAGRAM) {
			ssl_config->transport = SSL_TRANSPORT_DATAGRAM;
		} else {
			return BCTBX_ERROR_INVALID_SSL_TRANSPORT;
		}
#endif
	return 0;
}

int32_t bctbx_ssl_config_set_ciphersuites(bctbx_ssl_config_t *ssl_config, const int *ciphersuites) {
	return BCTBX_ERROR_INVALID_SSL_CONFIG;
}

/* unavailable function */
void *bctbx_ssl_config_get_private_config(bctbx_ssl_config_t *ssl_config) {
	return NULL;
}

int32_t bctbx_ssl_config_set_authmode(bctbx_ssl_config_t *ssl_config, int authmode) {
	if (ssl_config != NULL) {
		switch (authmode) {
			case BCTBX_SSL_VERIFY_NONE:
				ssl_config->authmode = SSL_VERIFY_NONE;
				break;
			case BCTBX_SSL_VERIFY_OPTIONAL:
				ssl_config->authmode = SSL_VERIFY_OPTIONAL;
				break;
			case BCTBX_SSL_VERIFY_REQUIRED:
				ssl_config->authmode = SSL_VERIFY_REQUIRED;
				break;
			default:
				return BCTBX_ERROR_INVALID_SSL_AUTHMODE;
				break;
		}
		return 0;
	}
	return BCTBX_ERROR_INVALID_SSL_CONFIG;
}

int32_t bctbx_ssl_config_set_rng(bctbx_ssl_config_t *ssl_config, int(*rng_function)(void *, unsigned char *, size_t), void *rng_context) {
	if (ssl_config != NULL) {
		ssl_config->rng_function = rng_function;
		ssl_config->rng_context = rng_context;
	}
	return BCTBX_ERROR_INVALID_SSL_CONFIG;
}

int32_t bctbx_ssl_config_set_callback_verify(bctbx_ssl_config_t *ssl_config, int(*callback_function)(void *, bctbx_x509_certificate_t *, int, uint32_t *), void *callback_data) {
	if (ssl_config != NULL) {
		ssl_config->callback_verify_function = (int(*)(void *, x509_crt *, int, int *))callback_function;
		ssl_config->callback_verify_data = callback_data;
	}
	return BCTBX_ERROR_INVALID_SSL_CONFIG;
}

int32_t bctbx_ssl_config_set_callback_cli_cert(bctbx_ssl_config_t *ssl_config, int(*callback_function)(void *, bctbx_ssl_context_t *, unsigned char *, size_t), void *callback_data) {
	if (ssl_config != NULL) {
		ssl_config->callback_cli_cert_function = callback_function;
		ssl_config->callback_cli_cert_data = callback_data;
	}
	return BCTBX_ERROR_INVALID_SSL_CONFIG;
}

int32_t bctbx_ssl_config_set_ca_chain(bctbx_ssl_config_t *ssl_config, bctbx_x509_certificate_t *ca_chain) {
	if (ssl_config != NULL) {
		ssl_config->ca_chain = (x509_crt *)ca_chain;
	}
	return BCTBX_ERROR_INVALID_SSL_CONFIG;
}

int32_t bctbx_ssl_config_set_own_cert(bctbx_ssl_config_t *ssl_config, bctbx_x509_certificate_t *cert, bctbx_signing_key_t *key) {
	if (ssl_config != NULL) {
		ssl_config->own_cert = (x509_crt *)cert;
		ssl_config->own_cert_pk = (pk_context *)key;
	}
	return BCTBX_ERROR_INVALID_SSL_CONFIG;
}


/** DTLS SRTP functions **/
#ifdef HAVE_DTLS_SRTP
int32_t bctbx_ssl_config_set_dtls_srtp_protection_profiles(bctbx_ssl_config_t *ssl_config, const bctbx_dtls_srtp_profile_t *profiles, size_t profiles_number) {
	size_t i;

	if (ssl_config == NULL) {
		return BCTBX_ERROR_INVALID_SSL_CONFIG;
	}

	/* convert the profiles array into a polarssl profiles array */
	for (i=0; i<profiles_number && i<4; i++) { /* 4 profiles defined max */
		ssl_config->dtls_srtp_profiles[i] = bctbx_srtp_profile_bctoolbox2polarssl(profiles[i]);
	}
	for (;i<4; i++) { /* make sure to have harmless values in the rest of the array */
		ssl_config->dtls_srtp_profiles[i] = SRTP_UNSET_PROFILE;
	}

	ssl_config->dtls_srtp_profiles_number = profiles_number;

	return 0;
}

#else /* HAVE_DTLS_SRTP */
int32_t bctbx_ssl_config_set_dtls_srtp_protection_profiles(bctbx_ssl_config_t *ssl_config, const bctbx_dtls_srtp_profile_t *profiles, size_t profiles_number) {
	return BCTBX_ERROR_UNAVAILABLE_FUNCTION;
}
#endif /* HAVE_DTLS_SRTP */
/** DTLS SRTP functions **/

int32_t bctbx_ssl_context_setup(bctbx_ssl_context_t *ssl_ctx, bctbx_ssl_config_t *ssl_config) {
	/* Check validity of context and config */
	if (ssl_config == NULL) {
		return BCTBX_ERROR_INVALID_SSL_CONFIG;
	}

	if (ssl_ctx == NULL) {
		return BCTBX_ERROR_INVALID_SSL_CONTEXT;
	}

	/* apply all valids settings to the ssl_context */
	if (ssl_config->endpoint != BCTBX_SSL_UNSET) {
		ssl_set_endpoint(&(ssl_ctx->ssl_ctx), ssl_config->endpoint);
	}

	if (ssl_config->authmode != BCTBX_SSL_UNSET) {
		ssl_set_authmode(&(ssl_ctx->ssl_ctx), ssl_config->authmode);
	}

#ifdef HAVE_DTLS_SRTP
	if (ssl_config->transport != BCTBX_SSL_UNSET) {
		ssl_set_transport(&(ssl_ctx->ssl_ctx), ssl_config->transport);
	}

#endif
	if (ssl_config->rng_function != NULL) {
		ssl_set_rng(&(ssl_ctx->ssl_ctx), ssl_config->rng_function, ssl_config->rng_context);
	}

	if (ssl_config->callback_verify_function != NULL) {
		ssl_set_verify(&(ssl_ctx->ssl_ctx), ssl_config->callback_verify_function, ssl_config->callback_verify_data);
	}

	if (ssl_config->callback_cli_cert_function != NULL) {
		ssl_ctx->callback_cli_cert_function = ssl_config->callback_cli_cert_function;
		ssl_ctx->callback_cli_cert_data = ssl_config->callback_cli_cert_data;
	}

	if (ssl_config->ca_chain != NULL) {
		ssl_set_ca_chain(&(ssl_ctx->ssl_ctx), ssl_config->ca_chain, NULL, ssl_ctx->cn);
	}

	if (ssl_config->own_cert != NULL && ssl_config->own_cert_pk != NULL) {
		ssl_set_own_cert(&(ssl_ctx->ssl_ctx) , ssl_config->own_cert , ssl_config->own_cert_pk);
	}

#ifdef HAVE_DTLS_SRTP
	if (ssl_config->dtls_srtp_profiles_number > 0) {
		ssl_set_dtls_srtp_protection_profiles(&(ssl_ctx->ssl_ctx), ssl_config->dtls_srtp_profiles, ssl_config->dtls_srtp_profiles_number );
	}

	/* We do not use DTLS SRTP cookie, so we must set to NULL the callbacks. Cookies are used to prevent DoS attack but our server is on only when during a brief period so we do not need this */
	ssl_set_dtls_cookies(&(ssl_ctx->ssl_ctx), NULL, NULL, NULL);
#endif

	return 0;
}

/*****************************************************************************/
/***** Hashing                                                           *****/
/*****************************************************************************/
/**
 * @brief HMAC-SHA512 wrapper
 * @param[in] 	key		HMAC secret key
 * @param[in] 	keyLength	HMAC key length in bytes
 * @param[in]	input 		Input data buffer
 * @param[in]   inputLength	Input data length in bytes
 * @param[in]	hmacLength	Length of output required in bytes, HMAC output is truncated to the hmacLength left bytes. 48 bytes maximum
 * @param[out]	output		Output data buffer.
 *
 */
void bctbx_hmacSha512(const uint8_t *key,
		size_t keyLength,
		const uint8_t *input,
		size_t inputLength,
		uint8_t hmacLength,
		uint8_t *output)
{
	uint8_t hmacOutput[64];
	sha512_hmac(key, keyLength, input, inputLength, hmacOutput, 0); /* last param to one to select SHA512 and not SHA384 */

	/* check output length, can't be>64 */
	if (hmacLength>64) {
		memcpy(output, hmacOutput, 64);
	} else {
		memcpy(output, hmacOutput, hmacLength);
	}
}

/**
 * @brief HMAC-SHA384 wrapper
 * @param[in] 	key		HMAC secret key
 * @param[in] 	keyLength	HMAC key length in bytes
 * @param[in]	input 		Input data buffer
 * @param[in]   inputLength	Input data length in bytes
 * @param[in]	hmacLength	Length of output required in bytes, HMAC output is truncated to the hmacLength left bytes. 48 bytes maximum
 * @param[out]	output		Output data buffer.
 *
 */
void bctbx_hmacSha384(const uint8_t *key,
		size_t keyLength,
		const uint8_t *input,
		size_t inputLength,
		uint8_t hmacLength,
		uint8_t *output)
{
	uint8_t hmacOutput[48];
	sha512_hmac(key, keyLength, input, inputLength, hmacOutput, 1); /* last param to one to select SHA384 and not SHA512 */

	/* check output length, can't be>48 */
	if (hmacLength>48) {
		memcpy(output, hmacOutput, 48);
	} else {
		memcpy(output, hmacOutput, hmacLength);
	}
}

/**
 * @brief HMAC-SHA256 wrapper
 * @param[in] 	key			HMAC secret key
 * @param[in] 	keyLength	HMAC key length in bytes
 * @param[in]	input 		Input data buffer
 * @param[in]   inputLength	Input data length in bytes
 * @param[in]	hmacLength	Length of output required in bytes, HMAC output is truncated to the hmacLength left bytes. 32 bytes maximum
 * @param[out]	output		Output data buffer.
 *
 */
void bctbx_hmacSha256(const uint8_t *key,
		size_t keyLength,
		const uint8_t *input,
		size_t inputLength,
		uint8_t hmacLength,
		uint8_t *output)
{
	uint8_t hmacOutput[32];
	sha256_hmac(key, keyLength, input, inputLength, hmacOutput, 0); /* last param to zero to select SHA256 and not SHA224 */

	/* check output length, can't be>32 */
	if (hmacLength>32) {
		memcpy(output, hmacOutput, 32);
	} else {
		memcpy(output, hmacOutput, hmacLength);
	}
}

/*
 * @brief SHA512 wrapper
 * @param[in]	input 		Input data buffer
 * @param[in]   inputLength	Input data length in bytes
 * @param[in]	hashLength	Length of output required in bytes, Output is truncated to the hashLength left bytes. 64 bytes maximum
 * @param[out]	output		Output data buffer.
 *
 */
void bctbx_sha512(const uint8_t *input,
		size_t inputLength,
		uint8_t hashLength,
		uint8_t *output)
{
	uint8_t hashOutput[64];
	sha512(input, inputLength, hashOutput, 0); /* last param to zero to select SHA512 and not SHA384 */

	/* check output length, can't be>64 */
	if (hashLength>64) {
		memcpy(output, hashOutput, 64);
	} else {
		memcpy(output, hashOutput, hashLength);
	}
}

/*
 * @brief SHA384 wrapper
 * @param[in]	input 		Input data buffer
 * @param[in]   inputLength	Input data length in bytes
 * @param[in]	hashLength	Length of output required in bytes, Output is truncated to the hashLength left bytes. 48 bytes maximum
 * @param[out]	output		Output data buffer.
 *
 */
void bctbx_sha384(const uint8_t *input,
		size_t inputLength,
		uint8_t hashLength,
		uint8_t *output)
{
	uint8_t hashOutput[48];
	sha512(input, inputLength, hashOutput, 1); /* last param to one to select SHA384 and not SHA512 */

	/* check output length, can't be>48 */
	if (hashLength>48) {
		memcpy(output, hashOutput, 48);
	} else {
		memcpy(output, hashOutput, hashLength);
	}
}

/**
 * @brief SHA256 wrapper
 * @param[in]	input 		Input data buffer
 * @param[in]   inputLength	Input data length in bytes
 * @param[in]	hmacLength	Length of output required in bytes, SHA256 output is truncated to the hashLength left bytes. 32 bytes maximum
 * @param[out]	output		Output data buffer.
 *
 */
void bctbx_sha256(const uint8_t *input,
		size_t inputLength,
		uint8_t hashLength,
		uint8_t *output)
{
	uint8_t hashOutput[32];
	sha256(input, inputLength, hashOutput, 0); /* last param to zero to select SHA256 and not SHA224 */

	/* check output length, can't be>32 */
	if (hashLength>32) {
		memcpy(output, hashOutput, 32);
	} else {
		memcpy(output, hashOutput, hashLength);
	}
}

/**
 * @brief HMAC-SHA1 wrapper
 * @param[in] 	key			HMAC secret key
 * @param[in] 	keyLength	HMAC key length
 * @param[in]	input 		Input data buffer
 * @param[in]   inputLength	Input data length
 * @param[in]	hmacLength	Length of output required in bytes, HMAC output is truncated to the hmacLength left bytes. 20 bytes maximum
 * @param[out]	output		Output data buffer
 *
 */
void bctbx_hmacSha1(const uint8_t *key,
		size_t keyLength,
		const uint8_t *input,
		size_t inputLength,
		uint8_t hmacLength,
		uint8_t *output)
{
	uint8_t hmacOutput[20];
	sha1_hmac(key, keyLength, input, inputLength, hmacOutput);

	/* check output length, can't be>20 */
	if (hmacLength>20) {
		memcpy(output, hmacOutput, 20);
	} else {
		memcpy(output, hmacOutput, hmacLength);
	}
}

/**
 * @brief MD5 wrapper
 * output = md5(input)
 * @param[in]	input 		Input data buffer
 * @param[in]   inputLength	Input data length in bytes
 * @param[out]	output		Output data buffer.
 *
 */
void bctbx_md5(const uint8_t *input,
		size_t inputLength,
		uint8_t output[16])
{
	md5(input, inputLength, output);
}

/*****************************************************************************/
/***** Encryption/Decryption                                             *****/
/*****************************************************************************/
/***** GCM *****/
/**
 * @Brief AES-GCM encrypt and tag buffer
 *
 * @param[in]	key							Encryption key
 * @param[in]	keyLength					Key buffer length, in bytes, must be 16,24 or 32
 * @param[in]	plainText					Buffer to be encrypted
 * @param[in]	plainTextLength				Length in bytes of buffer to be encrypted
 * @param[in]	authenticatedData			Buffer holding additional data to be used in tag computation
 * @param[in]	authenticatedDataLength		Additional data length in bytes
 * @param[in]	initializationVector		Buffer holding the initialisation vector
 * @param[in]	initializationVectorLength	Initialisation vector length in bytes
 * @param[out]	tag							Buffer holding the generated tag
 * @param[in]	tagLength					Requested length for the generated tag
 * @param[out]	output						Buffer holding the output, shall be at least the length of plainText buffer
 */
int32_t bctbx_aes_gcm_encrypt_and_tag(const uint8_t *key, size_t keyLength,
		const uint8_t *plainText, size_t plainTextLength,
		const uint8_t *authenticatedData, size_t authenticatedDataLength,
		const uint8_t *initializationVector, size_t initializationVectorLength,
		uint8_t *tag, size_t tagLength,
		uint8_t *output) {
	gcm_context gcmContext;
	int ret;

	ret = gcm_init(&gcmContext, POLARSSL_CIPHER_ID_AES, key, keyLength*8);
	if (ret != 0) return ret;

	ret = gcm_crypt_and_tag(&gcmContext, GCM_ENCRYPT, plainTextLength, initializationVector, initializationVectorLength, authenticatedData, authenticatedDataLength, plainText, output, tagLength, tag);
	gcm_free(&gcmContext);

	return ret;
}

/**
 * @Brief AES-GCM decrypt, compute authentication tag and compare it to the one provided
 *
 * @param[in]	key							Encryption key
 * @param[in]	keyLength					Key buffer length, in bytes, must be 16,24 or 32
 * @param[in]	cipherText					Buffer to be decrypted
 * @param[in]	cipherTextLength			Length in bytes of buffer to be decrypted
 * @param[in]	authenticatedData			Buffer holding additional data to be used in auth tag computation
 * @param[in]	authenticatedDataLength		Additional data length in bytes
 * @param[in]	initializationVector		Buffer holding the initialisation vector
 * @param[in]	initializationVectorLength	Initialisation vector length in bytes
 * @param[in]	tag							Buffer holding the authentication tag
 * @param[in]	tagLength					Length in bytes for the authentication tag
 * @param[out]	output						Buffer holding the output, shall be at least the length of cipherText buffer
 *
 * @return 0 on succes, BCTBX_ERROR_AUTHENTICATION_FAILED if tag doesn't match or polarssl error code
 */
int32_t bctbx_aes_gcm_decrypt_and_auth(const uint8_t *key, size_t keyLength,
		const uint8_t *cipherText, size_t cipherTextLength,
		const uint8_t *authenticatedData, size_t authenticatedDataLength,
		const uint8_t *initializationVector, size_t initializationVectorLength,
		const uint8_t *tag, size_t tagLength,
		uint8_t *output) {
	gcm_context gcmContext;
	int ret;

	ret = gcm_init(&gcmContext, POLARSSL_CIPHER_ID_AES, key, keyLength*8);
	if (ret != 0) return ret;

	ret = gcm_auth_decrypt(&gcmContext, cipherTextLength, initializationVector, initializationVectorLength, authenticatedData, authenticatedDataLength, tag, tagLength, cipherText, output);
	gcm_free(&gcmContext);

	if (ret == POLARSSL_ERR_GCM_AUTH_FAILED) {
		return BCTBX_ERROR_AUTHENTICATION_FAILED;
	}

	return ret;
}


/**
 * @Brief create and initialise an AES-GCM encryption context
 *
 * @param[in]	key							encryption key
 * @param[in]	keyLength					key buffer length, in bytes, must be 16,24 or 32
 * @param[in]	authenticatedData			Buffer holding additional data to be used in tag computation (can be NULL)
 * @param[in]	authenticatedDataLength		additional data length in bytes (can be 0)
 * @param[in]	initializationVector		Buffer holding the initialisation vector
 * @param[in]	initializationVectorLength	Initialisation vector length in bytes
 * @param[in]	mode						Operation mode : BCTBX_GCM_ENCRYPT or BCTBX_GCM_DECRYPT
 *
 * @return 0 on success, crypto library error code otherwise
 */
bctbx_aes_gcm_context_t *bctbx_aes_gcm_context_new(const uint8_t *key, size_t keyLength,
		const uint8_t *authenticatedData, size_t authenticatedDataLength,
		const uint8_t *initializationVector, size_t initializationVectorLength,
		uint8_t mode) {

	int ret = 0;
	int polarssl_mode;
	gcm_context *ctx = NULL;

	if (mode == BCTBX_GCM_ENCRYPT) {
		polarssl_mode = GCM_ENCRYPT;
	} else if ( mode == BCTBX_GCM_DECRYPT) {
		polarssl_mode = GCM_DECRYPT;
	} else {
		return NULL;
	}

	ctx = bctbx_malloc0(sizeof(gcm_context));
	ret = gcm_init(ctx, POLARSSL_CIPHER_ID_AES, key, keyLength*8);
	if (ret != 0) {
		bctbx_free(ctx);
		return NULL;
	}

	ret = gcm_starts(ctx, polarssl_mode, initializationVector, initializationVectorLength, authenticatedData, authenticatedDataLength);
	if (ret != 0) {
		bctbx_free(ctx);
		return NULL;
	}

	return (bctbx_aes_gcm_context_t *)ctx;
}

/**
 * @Brief AES-GCM encrypt or decrypt a chunk of data
 *
 * @param[in/out]	context			a context already initialized using bctbx_aes_gcm_context_new
 * @param[in]		input			buffer holding the input data
 * @param[in]		inputLength		lenght of the input data
 * @param[out]		output			buffer to store the output data (same length as input one)
 *
 * @return 0 on success, crypto library error code otherwise
 */
int32_t bctbx_aes_gcm_process_chunk(bctbx_aes_gcm_context_t *context,
		const uint8_t *input, size_t inputLength,
		uint8_t *output) {
	return gcm_update((gcm_context *)context, inputLength, input, output);
}

/**
 * @Brief Conclude a AES-GCM encryption stream, generate tag if requested, free resources
 *
 * @param[in/out]	context			a context already initialized using bctbx_aes_gcm_context_new
 * @param[out]		tag				a buffer to hold the authentication tag. Can be NULL if tagLength is 0
 * @param[in]		tagLength		length of reqested authentication tag, max 16
 *
 * @return 0 on success, crypto library error code otherwise
 */
int32_t bctbx_aes_gcm_finish(bctbx_aes_gcm_context_t *context,
		uint8_t *tag, size_t tagLength) {
	int ret;

	ret = gcm_finish((gcm_context *)context, tag, tagLength);
	gcm_free((gcm_context *)context);

	bctbx_free(context);

	return ret;
}

/*
 * @brief Wrapper for AES-128 in CFB128 mode encryption
 * Both key and IV must be 16 bytes long, IV is not updated
 *
 * @param[in]	key			encryption key, 128 bits long
 * @param[in]	IV			Initialisation vector, 128 bits long, is not modified by this function.
 * @param[in]	input		Input data buffer
 * @param[in]	inputLength	Input data length
 * @param[out]	output		Output data buffer
 *
 */
void bctbx_aes128CfbEncrypt(const uint8_t key[16],
		const uint8_t IV[16],
		const uint8_t *input,
		size_t inputLength,
		uint8_t *output)
{
	uint8_t IVbuffer[16];
	size_t iv_offset=0; /* is not used by us but needed and updated by polarssl */
	aes_context context;
	memset (&context, 0, sizeof(aes_context));

	/* make a local copy of IV which is modified by the polar ssl AES-CFB function */
	memcpy(IVbuffer, IV, 16*sizeof(uint8_t));

	/* initialise the aes context and key */
	aes_setkey_enc(&context, key, 128);

	/* encrypt */
	aes_crypt_cfb128 (&context, AES_ENCRYPT, inputLength, &iv_offset, IVbuffer, input, output);
}

/*
 * @brief Wrapper for AES-128 in CFB128 mode decryption
 * Both key and IV must be 16 bytes long, IV is not updated
 *
 * @param[in]	key			decryption key, 128 bits long
 * @param[in]	IV			Initialisation vector, 128 bits long, is not modified by this function.
 * @param[in]	input		Input data buffer
 * @param[in]	inputLength	Input data length
 * @param[out]	output		Output data buffer
 *
 */
void bctbx_aes128CfbDecrypt(const uint8_t key[16],
		const uint8_t IV[16],
		const uint8_t *input,
		size_t inputLength,
		uint8_t *output)
{
	uint8_t IVbuffer[16];
	size_t iv_offset=0; /* is not used by us but needed and updated by polarssl */
	aes_context context;
	memset (&context, 0, sizeof(aes_context));

	/* make a local copy of IV which is modified by the polar ssl AES-CFB function */
	memcpy(IVbuffer, IV, 16*sizeof(uint8_t));

	/* initialise the aes context and key - use the aes_setkey_enc function as requested by the documentation of aes_crypt_cfb128 function */
	aes_setkey_enc(&context, key, 128);

	/* encrypt */
	aes_crypt_cfb128 (&context, AES_DECRYPT, inputLength, &iv_offset, IVbuffer, input, output);
}

/*
 * @brief Wrapper for AES-256 in CFB128 mode encryption
 * The key must be 32 bytes long and the IV must be 16 bytes long, IV is not updated
 *
 * @param[in]	key			encryption key, 256 bits long
 * @param[in]	IV			Initialisation vector, 128 bits long, is not modified by this function.
 * @param[in]	input		Input data buffer
 * @param[in]	inputLength	Input data length
 * @param[out]	output		Output data buffer
 *
 */
void bctbx_aes256CfbEncrypt(const uint8_t key[32],
		const uint8_t IV[16],
		const uint8_t *input,
		size_t inputLength,
		uint8_t *output)
{
	uint8_t IVbuffer[16];
	size_t iv_offset=0;
	aes_context context;

	memcpy(IVbuffer, IV, 16*sizeof(uint8_t));
	memset (&context, 0, sizeof(aes_context));
	aes_setkey_enc(&context, key, 256);

	/* encrypt */
	aes_crypt_cfb128 (&context, AES_ENCRYPT, inputLength, &iv_offset, IVbuffer, input, output);
}

/*
 * @brief Wrapper for AES-256 in CFB128 mode decryption
 * The key must be 32 bytes long and the IV must be 16 bytes long, IV is not updated
 *
 * @param[in]	key			decryption key, 256 bits long
 * @param[in]	IV			Initialisation vector, 128 bits long, is not modified by this function.
 * @param[in]	input		Input data buffer
 * @param[in]	inputLength	Input data length
 * @param[out]	output		Output data buffer
 *
 */
void bctbx_aes256CfbDecrypt(const uint8_t key[32],
		const uint8_t IV[16],
		const uint8_t *input,
		size_t inputLength,
		uint8_t *output)
{
	uint8_t IVbuffer[16];
	size_t iv_offset=0;
	aes_context context;

	memcpy(IVbuffer, IV, 16*sizeof(uint8_t));
	memset (&context, 0, sizeof(aes_context));
	aes_setkey_enc(&context, key, 256);

	/* decrypt */
	aes_crypt_cfb128 (&context, AES_DECRYPT, inputLength, &iv_offset, IVbuffer, input, output);
}
