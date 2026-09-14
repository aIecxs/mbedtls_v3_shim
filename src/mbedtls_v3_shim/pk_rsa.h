/*
 * Lazy RSA context materialization for PSA-backed PK contexts (mbedTLS v4).
 *
 * Single home for every prototype/constant that pk.h and pk_rsa.c need to
 * share, so neither has to forward-declare the other's symbols ad hoc.
 */
#pragma once

typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_rsa_context mbedtls_rsa_context;
typedef struct mbedtls_pk_info_t mbedtls_pk_info_t;

#ifdef __cplusplus
extern "C" {
#endif

mbedtls_rsa_context *mbedtls_v3_shim_pk_rsa(mbedtls_pk_context *pk);
void mbedtls_v3_shim_pk_rsa_sync_bits_from_ctx(mbedtls_rsa_context *rsa);
void mbedtls_v3_shim_pk_rsa_cache_release(mbedtls_pk_context *pk);
int mbedtls_v3_shim_pk_setup(mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info);
void mbedtls_v3_shim_pk_free(mbedtls_pk_context *ctx);

/*
 * mbedtls_pk_decrypt()/mbedtls_pk_encrypt() were dropped from the pk layer
 * in v4. Implemented in pk_rsa.c on top of the lazily materialized RSA
 * context (mbedtls_v3_shim_pk_rsa()) via the real v4 mbedtls_rsa_pkcs1_decrypt()/
 * _encrypt() - i.e. the legacy (hardware-accelerated where supported) RSA
 * code path, not PSA's software implementation. PSA is only touched once per
 * key, inside materialization itself.
 */
int mbedtls_pk_decrypt_v4_compat(
    mbedtls_pk_context *ctx,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int mbedtls_pk_encrypt_v4_compat(
    mbedtls_pk_context *ctx,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

/*
 * DER/PEM re-serialization for lazily materialized RSA contexts: reads from
 * the RSA cache when an entry exists, otherwise falls back to the real v4
 * mbedtls_pk_write_*() (see the MBEDTLS_V3_SHIM_INTERNAL guard in pk.h).
 */
int mbedtls_v3_shim_pk_write_key_der(const mbedtls_pk_context *ctx,
                                     unsigned char *buf, size_t size);
int mbedtls_v3_shim_pk_write_pubkey_der(const mbedtls_pk_context *ctx,
                                        unsigned char *buf, size_t size);
#if defined(MBEDTLS_PK_WRITE_C) && defined(MBEDTLS_PEM_WRITE_C)
int mbedtls_v3_shim_pk_write_key_pem(const mbedtls_pk_context *ctx,
                                     unsigned char *buf, size_t size);
int mbedtls_v3_shim_pk_write_pubkey_pem(const mbedtls_pk_context *ctx,
                                        unsigned char *buf, size_t size);
#endif

/* Implemented in rsa_import_export.c; not part of the real mbedTLS v4 API. */
int mbedtls_rsa_write_key_der(const mbedtls_rsa_context *ctx,
                              unsigned char *buf, size_t size);

/*
 * Dummy non-NULL pk_info pointer handed back by the mbedtls_pk_info_from_type()
 * shim in pk.h. Legacy code only NULL-checks the result before passing it to
 * mbedtls_pk_setup(), which recognizes this sentinel and substitutes the real
 * v4 info struct (see mbedtls_v3_shim_pk_setup() in pk_rsa.c).
 */
#define MBEDTLS_V3_SHIM_PK_INFO_DUMMY ((const mbedtls_pk_info_t *) 1)

#ifdef __cplusplus
}
#endif
