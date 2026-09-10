/*
 * Compatibility header for mbedTLS v4 ECDH API removal.
 *
 * The ECDH module was removed in mbedTLS v4 (use PSA ECDH instead).
 * libssh still calls the legacy helper mbedtls_ecdh_compute_shared().
 */
#pragma once

#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

#include "mbedtls/build_info.h"
#include "mbedtls/private/bignum.h"
#include "mbedtls/private/ecp.h"

#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng);

#ifdef __cplusplus
}
#endif
