/*
 * Compatibility header to expose mbedTLS v4 private RSA APIs.
 *
 * mbedTLS v4 moved RSA types and functions entirely to private headers.
 * There is no public mbedtls/rsa.h in v4, so this header provides the
 * interface by including the private RSA header directly.
 */
#pragma once

#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

#include "mbedtls/build_info.h"

/* In mbedTLS v4, there is no public rsa.h - RSA APIs are entirely private.
 * Include the private RSA header directly for mbedtls_rsa_context and RSA functions. */
#include "mbedtls/private/rsa.h"

/*
 * Progressive RSA key import/export helpers removed from mbedTLS v4.
 * See tf-psa-crypto/docs/psa-transition.md ("RSA functionality with no PSA equivalent").
 */
#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_rsa_import(mbedtls_rsa_context *ctx,
                       const mbedtls_mpi *N,
                       const mbedtls_mpi *P, const mbedtls_mpi *Q,
                       const mbedtls_mpi *D, const mbedtls_mpi *E);

int mbedtls_rsa_import_raw(mbedtls_rsa_context *ctx,
                           unsigned char const *N, size_t N_len,
                           unsigned char const *P, size_t P_len,
                           unsigned char const *Q, size_t Q_len,
                           unsigned char const *D, size_t D_len,
                           unsigned char const *E, size_t E_len);

int mbedtls_rsa_complete(mbedtls_rsa_context *ctx);

int mbedtls_rsa_export(const mbedtls_rsa_context *ctx,
                       mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q,
                       mbedtls_mpi *D, mbedtls_mpi *E);

int mbedtls_rsa_export_raw(const mbedtls_rsa_context *ctx,
                           unsigned char *N, size_t N_len,
                           unsigned char *P, size_t P_len,
                           unsigned char *Q, size_t Q_len,
                           unsigned char *D, size_t D_len,
                           unsigned char *E, size_t E_len);

int mbedtls_rsa_export_crt(const mbedtls_rsa_context *ctx,
                           mbedtls_mpi *DP, mbedtls_mpi *DQ, mbedtls_mpi *QP);

#ifdef __cplusplus
}
#endif
