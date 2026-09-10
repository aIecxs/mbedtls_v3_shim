/*
 * RSA operations compatibility wrappers for mbedTLS v4.
 * 
 * Provides compatibility for RSA operations that differ between v3 and v4:
 * - mbedtls_rsa_set_padding(): Configure RSA padding mode and hash algorithm
 * - mbedtls_rsa_gen_key(): Generate RSA key pairs
 */
#pragma once

#include "mbedtls/rsa.h"
#include "mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Wrapper for mbedtls_rsa_set_padding()
 * Sets the padding mode (PKCS#1 v1.5 or OAEP) and hash algorithm.
 */
int mbedtls_v3_shim_rsa_set_padding(mbedtls_rsa_context *ctx,
                                     int padding,
                                     mbedtls_md_type_t hash_id);

/*
 * Wrapper for mbedtls_rsa_gen_key()
 * Generates an RSA key pair.
 */
int mbedtls_v3_shim_rsa_gen_key(mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 unsigned int nbits,
                                 int exponent);

#ifdef __cplusplus
}
#endif
