/*
 * Lazy RSA context materialization for PSA-backed PK contexts (mbedTLS v4).
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

#ifdef __cplusplus
}
#endif
