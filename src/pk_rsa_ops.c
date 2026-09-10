/*
 * mbedTLS v3 compatibility wrappers for RSA operations in v4.
 * 
 * Handles:
 * - mbedtls_rsa_set_padding(): v3 wrapper for setting RSA padding mode
 * - mbedtls_rsa_gen_key(): v3 wrapper for RSA key generation
 */

#define MBEDTLS_V3_SHIM_INTERNAL

#include <string.h>

#include "mbedtls/build_info.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"

#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

#include "mbedtls/pk.h"
#include "mbedtls/private/pk_private.h"
#include "mbedtls/private/rsa.h"

/*
 * mbedtls_rsa_set_padding() wrapper
 * 
 * In mbedTLS v4, this is still available in private rsa.h. We ensure it's callable
 * with proper error handling by setting the padding and hash_id fields directly.
 */
int mbedtls_v3_shim_rsa_set_padding(mbedtls_rsa_context *ctx,
                                     int padding, mbedtls_md_type_t hash_id)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    ctx->MBEDTLS_PRIVATE(padding) = padding;
    ctx->MBEDTLS_PRIVATE(hash_id) = hash_id;

    return 0;
}

/*
 * mbedtls_rsa_gen_key() wrapper
 * 
 * In mbedTLS v3: mbedtls_rsa_gen_key(ctx, f_rng, p_rng, nbits, exponent)
 * In mbedTLS v4: mbedtls_rsa_gen_key(ctx, f_rng, p_rng, nbits, exponent)
 * 
 * The signature is the same in both versions. This wrapper ensures compatibility
 * by performing input validation before calling the real function.
 */
int mbedtls_v3_shim_rsa_gen_key(mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 unsigned int nbits,
                                 int exponent)
{
    if (ctx == NULL || f_rng == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    /* Call the real v4 function */
    return mbedtls_rsa_gen_key(ctx, f_rng, p_rng, nbits, exponent);
}
