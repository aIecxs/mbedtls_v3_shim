/*
 * Lazy ECP keypair materialization for PSA-backed PK contexts (mbedTLS v4).
 */
#pragma once

typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_ecp_keypair mbedtls_ecp_keypair;

#ifdef __cplusplus
extern "C" {
#endif

mbedtls_ecp_keypair *mbedtls_v3_shim_pk_ec(mbedtls_pk_context *pk);
void mbedtls_v3_shim_pk_ec_cache_release(mbedtls_pk_context *pk);

#ifdef __cplusplus
}
#endif
