/*
 * Compatibility header for mbedTLS v4 PK API changes.
 *
 * Changes handled:
 * - mbedtls_pk_parse_key: v3 has 7 args (includes f_rng, p_rng), v4 has 5 args
 * - mbedtls_pk_sign: v3 has 9 args (includes f_rng, p_rng), v4 has 7 args
 * - mbedtls_pk_decrypt: v3 has 8 args (includes f_rng, p_rng), v4 has 6 args
 * - Exposes private types: mbedtls_pk_type_t, MBEDTLS_PK_RSA, MBEDTLS_PK_ECDSA, etc.
 * - Exposes private functions: mbedtls_pk_can_do, mbedtls_pk_get_type, mbedtls_pk_setup,
 *   mbedtls_pk_info_from_type, mbedtls_pk_rsa, mbedtls_pk_ec
 * - Also includes RSA and ECDSA private headers needed by legacy code
 */
#pragma once

/* Enable private identifiers to access legacy types and functions */
#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

#include "mbedtls/build_info.h"

/* Include the real pk.h first to get the public types and functions */
#include_next "mbedtls/pk.h"

/* Include the private pk header for legacy types like mbedtls_pk_type_t,
 * MBEDTLS_PK_RSA, mbedtls_pk_can_do, mbedtls_pk_get_type, etc. */
#include "mbedtls/private/pk_private.h"

/* Include RSA and ECDSA private headers as many legacy files only include
 * mbedtls/pk.h but use RSA/ECDSA types and functions directly */
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"

/* Include bignum for mbedtls_mpi functions (ESP-IDF port exposes this) */
#include "mbedtls/bignum.h"

/* Include ECP for mbedtls_ecp functions (ESP-IDF port exposes this) */
#include "mbedtls/ecp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Inline wrapper that calls the real v4 5-arg mbedtls_pk_parse_key().
 * Must be defined before the macro so the macro doesn't expand here.
 */
static inline int mbedtls_pk_parse_key_v4_real(
    mbedtls_pk_context *ctx,
    const unsigned char *key, size_t keylen,
    const unsigned char *pwd, size_t pwdlen)
{
    return mbedtls_pk_parse_key(ctx, key, keylen, pwd, pwdlen);
}

/*
 * Inline wrapper that calls the real v4 7-arg mbedtls_pk_sign().
 * Must be defined before the macro so the macro doesn't expand here.
 */
static inline int mbedtls_pk_sign_v4_real(
    mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
    const unsigned char *hash, size_t hash_len,
    unsigned char *sig, size_t sig_size, size_t *sig_len)
{
    return mbedtls_pk_sign(ctx, md_alg, hash, hash_len, sig, sig_size, sig_len);
}

/*
 * Inline wrapper that calls the real v4 6-arg mbedtls_pk_decrypt().
 * Must be defined before the macro so the macro doesn't expand here.
 */
static inline int mbedtls_pk_decrypt_v4_real(
    mbedtls_pk_context *ctx,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize)
{
    return mbedtls_pk_decrypt(ctx, input, ilen, output, olen, osize);
}

#ifdef __cplusplus
}
#endif

/*
 * Macro that accepts the legacy 7-arg signature for mbedtls_pk_parse_key
 * and discards f_rng, p_rng.
 * This allows code written for v3 to compile unchanged on v4.
 */
#define mbedtls_pk_parse_key(ctx, key, keylen, pwd, pwdlen, f_rng, p_rng) \
    mbedtls_pk_parse_key_v4_real(ctx, key, keylen, pwd, pwdlen)

/*
 * Macro that accepts the legacy 9-arg signature for mbedtls_pk_sign
 * and discards f_rng, p_rng.
 * Old: mbedtls_pk_sign(ctx, md_alg, hash, hash_len, sig, sig_size, sig_len, f_rng, p_rng)
 * New: mbedtls_pk_sign(ctx, md_alg, hash, hash_len, sig, sig_size, sig_len)
 */
#define mbedtls_pk_sign(ctx, md_alg, hash, hash_len, sig, sig_size, sig_len, f_rng, p_rng) \
    mbedtls_pk_sign_v4_real(ctx, md_alg, hash, hash_len, sig, sig_size, sig_len)

/*
 * Macro that accepts the legacy 8-arg signature for mbedtls_pk_decrypt
 * and discards f_rng, p_rng.
 * Old: mbedtls_pk_decrypt(ctx, input, ilen, output, olen, osize, f_rng, p_rng)
 * New: mbedtls_pk_decrypt(ctx, input, ilen, output, olen, osize)
 */
#define mbedtls_pk_decrypt(ctx, input, ilen, output, olen, osize, f_rng, p_rng) \
    mbedtls_pk_decrypt_v4_real(ctx, input, ilen, output, olen, osize)

#if !defined(MBEDTLS_V3_SHIM_INTERNAL)
#include "mbedtls_v3_shim/pk_rsa.h"
#include "mbedtls_v3_shim/pk_rsa_ops.h"

static inline size_t mbedtls_pk_get_bitlen_v4_compat(const mbedtls_pk_context *ctx)
{
    size_t bits;

    if (ctx == NULL || ctx->pk_info == NULL) {
        return 0;
    }

    bits = ctx->bits;
    if (bits != 0) {
        return bits;
    }

    if (mbedtls_pk_get_type(ctx) == MBEDTLS_PK_RSA) {
        mbedtls_rsa_context *rsa =
            mbedtls_v3_shim_pk_rsa((mbedtls_pk_context *) ctx);

        if (rsa != NULL &&
            mbedtls_mpi_cmp_int(&rsa->N, 0) != 0) {
            bits = mbedtls_mpi_bitlen(&rsa->N);
            if (bits > 0) {
                ((mbedtls_pk_context *) ctx)->bits = bits;
                return bits;
            }
        }
    }

    return 0;
}

static inline int mbedtls_pk_verify_v4_real(mbedtls_pk_context *ctx,
                                            mbedtls_md_type_t md_alg,
                                            const unsigned char *hash,
                                            size_t hash_len,
                                            const unsigned char *sig,
                                            size_t sig_len)
{
    return mbedtls_pk_verify(ctx, md_alg, hash, hash_len, sig, sig_len);
}

static inline int mbedtls_pk_verify_v4_compat(mbedtls_pk_context *ctx,
                                              mbedtls_md_type_t md_alg,
                                              const unsigned char *hash,
                                              size_t hash_len,
                                              const unsigned char *sig,
                                              size_t sig_len)
{
    if (ctx != NULL && ctx->pk_info != NULL &&
        mbedtls_pk_get_type(ctx) == MBEDTLS_PK_RSA &&
        ctx->pub_raw_len == 0) {
        mbedtls_v3_shim_pk_rsa(ctx);
    }

    return mbedtls_pk_verify_v4_real(ctx, md_alg, hash, hash_len, sig, sig_len);
}
#endif /* !MBEDTLS_V3_SHIM_INTERNAL */

#if !defined(MBEDTLS_V3_SHIM_INTERNAL)
/*
 * Legacy type aliases for code compiled against mbedTLS v3 headers.
 * Do not apply inside the shim itself: v4 still has distinct enum values
 * at runtime (e.g. ECKEY vs ECKEY_DH) and switch/case needs the real names.
 */
#ifndef MBEDTLS_PK_RSA_ALT
#define MBEDTLS_PK_RSA_ALT MBEDTLS_PK_NONE  /* RSA_ALT was removed in v4 */
#endif

#ifndef MBEDTLS_PK_ECKEY_DH
#define MBEDTLS_PK_ECKEY_DH MBEDTLS_PK_ECKEY  /* DH is now part of ECKEY */
#endif
#endif /* !MBEDTLS_V3_SHIM_INTERNAL */

#if !defined(MBEDTLS_V3_SHIM_INTERNAL)
#include "mbedtls_v3_shim/pk_ec.h"

/*
 * Legacy mbedtls_pk_rsa() took the PK context by value and returned pk_ctx.
 * On mbedTLS v4 the RSA material lives in PSA; mbedtls_v3_shim_pk_rsa()
 * materializes a transparent RSA context on demand.
 */
#ifdef mbedtls_pk_rsa
#undef mbedtls_pk_rsa
#endif
#define mbedtls_pk_rsa(ctx) mbedtls_v3_shim_pk_rsa(&(ctx))

#ifdef mbedtls_pk_ec
#undef mbedtls_pk_ec
#endif
#define mbedtls_pk_ec(ctx) mbedtls_v3_shim_pk_ec(&(ctx))

#ifdef mbedtls_pk_setup
#undef mbedtls_pk_setup
#endif
#define mbedtls_pk_setup(ctx, info) mbedtls_v3_shim_pk_setup((ctx), (info))

#ifdef mbedtls_pk_free
#undef mbedtls_pk_free
#endif
#define mbedtls_pk_free(ctx) mbedtls_v3_shim_pk_free(ctx)

#ifdef mbedtls_pk_get_bitlen
#undef mbedtls_pk_get_bitlen
#endif
#define mbedtls_pk_get_bitlen(ctx) mbedtls_pk_get_bitlen_v4_compat(ctx)

#ifdef mbedtls_pk_verify
#undef mbedtls_pk_verify
#endif
#define mbedtls_pk_verify(ctx, md_alg, hash, hash_len, sig, sig_len) \
    mbedtls_pk_verify_v4_compat(ctx, md_alg, hash, hash_len, sig, sig_len)

/* RSA operations compatibility */
#ifdef mbedtls_rsa_set_padding
#undef mbedtls_rsa_set_padding
#endif
#define mbedtls_rsa_set_padding(ctx, padding, hash_id) \
    mbedtls_v3_shim_rsa_set_padding(ctx, padding, hash_id)

#ifdef mbedtls_rsa_gen_key
#undef mbedtls_rsa_gen_key
#endif
#define mbedtls_rsa_gen_key(ctx, f_rng, p_rng, nbits, exponent) \
    mbedtls_v3_shim_rsa_gen_key(ctx, f_rng, p_rng, nbits, exponent)

#endif /* !MBEDTLS_V3_SHIM_INTERNAL */
