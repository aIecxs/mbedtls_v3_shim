/*
 * RSA import/export/complete shims for mbedTLS v4.
 *
 * Progressive RSA key construction (mbedtls_rsa_import, mbedtls_rsa_complete,
 * mbedtls_rsa_export, etc.) was removed from the v4 API. libssh and other legacy
 * code still depend on these functions. Implementations are adapted from
 * mbedTLS v3 rsa.c and rsa_alt_helpers.c.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#define MBEDTLS_V3_SHIM_INTERNAL

#include "mbedtls/build_info.h"
#include <string.h> 

#if defined(MBEDTLS_RSA_C)

#include "mbedtls/error.h"
#include "mbedtls/private/bignum.h"
#include "mbedtls/private/error_common.h"
#include "mbedtls/rsa.h"
#include "mbedtls_v3_shim/pk_rsa.h"
#include "mbedtls/asn1write.h"

#include <stdint.h>

/* Internal bignum helpers still present in libmbedcrypto. */
int mbedtls_mpi_gcd_modinv_odd(mbedtls_mpi *G,
                               mbedtls_mpi *I,
                               const mbedtls_mpi *A,
                               const mbedtls_mpi *N);

/* Still built into libmbedcrypto but not declared in public headers. */
int mbedtls_rsa_deduce_private_exponent(mbedtls_mpi const *P,
                                        mbedtls_mpi const *Q,
                                        mbedtls_mpi const *E,
                                        mbedtls_mpi *D);
int mbedtls_rsa_deduce_crt(const mbedtls_mpi *P, const mbedtls_mpi *Q,
                           const mbedtls_mpi *D, mbedtls_mpi *DP,
                           mbedtls_mpi *DQ, mbedtls_mpi *QP);

static int rsa_check_context(mbedtls_rsa_context const *ctx, int is_priv,
                             int blinding_needed)
{
#if !defined(MBEDTLS_RSA_NO_CRT)
    ((void) blinding_needed);
#endif

    if (ctx->len != mbedtls_mpi_size(&ctx->N) ||
        ctx->len > MBEDTLS_MPI_MAX_SIZE) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    if (mbedtls_mpi_cmp_int(&ctx->N, 0) <= 0 ||
        mbedtls_mpi_get_bit(&ctx->N, 0) == 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

#if !defined(MBEDTLS_RSA_NO_CRT)
    if (is_priv &&
        (mbedtls_mpi_cmp_int(&ctx->P, 0) <= 0 ||
         mbedtls_mpi_get_bit(&ctx->P, 0) == 0 ||
         mbedtls_mpi_cmp_int(&ctx->Q, 0) <= 0 ||
         mbedtls_mpi_get_bit(&ctx->Q, 0) == 0)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
#endif

    if (mbedtls_mpi_cmp_int(&ctx->E, 0) <= 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_RSA_NO_CRT)
    if (is_priv && mbedtls_mpi_cmp_int(&ctx->D, 0) <= 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
#else
    if (is_priv &&
        (mbedtls_mpi_cmp_int(&ctx->DP, 0) <= 0 ||
         mbedtls_mpi_cmp_int(&ctx->DQ, 0) <= 0)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
#endif

#if defined(MBEDTLS_RSA_NO_CRT)
    if (is_priv && blinding_needed &&
        (mbedtls_mpi_cmp_int(&ctx->P, 0) <= 0 ||
         mbedtls_mpi_cmp_int(&ctx->Q, 0) <= 0)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    if (is_priv && mbedtls_mpi_cmp_int(&ctx->QP, 0) <= 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }
#endif

    return 0;
}

/*
 * Factor N given (N, E, D). Removed from mbedTLS v4 rsa_alt_helpers.
 */
static int rsa_deduce_primes(mbedtls_mpi const *N,
                             mbedtls_mpi const *E, mbedtls_mpi const *D,
                             mbedtls_mpi *P, mbedtls_mpi *Q)
{
    int ret = 0;
    uint16_t attempt;
    uint16_t iter;
    uint16_t order;
    mbedtls_mpi T;
    mbedtls_mpi K;

    const unsigned char primes[] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
        61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
        193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251
    };
    const size_t num_primes = sizeof(primes) / sizeof(*primes);

    if (P == NULL || Q == NULL || P->p != NULL || Q->p != NULL) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (mbedtls_mpi_cmp_int(N, 0) <= 0 ||
        mbedtls_mpi_cmp_int(D, 1) <= 0 ||
        mbedtls_mpi_cmp_mpi(D, N) >= 0 ||
        mbedtls_mpi_cmp_int(E, 1) <= 0 ||
        mbedtls_mpi_cmp_mpi(E, N) >= 0) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&K);
    mbedtls_mpi_init(&T);

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&T, D, E));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&T, &T, 1));

    order = (uint16_t) mbedtls_mpi_lsb(&T);
    if (order == 0) {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&T, order));

    attempt = 0;
    if (N->p[0] % 8 == 1) {
        attempt = 1;
    }

    for (; attempt < num_primes; ++attempt) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&K, primes[attempt]));

        MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(P, NULL, &K, N));
        if (mbedtls_mpi_cmp_int(P, 1) != 0) {
            continue;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&K, &K, &T, N, Q));

        for (iter = 1; iter <= order; ++iter) {
            if (mbedtls_mpi_cmp_int(&K, 1) == 0) {
                break;
            }

            MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&K, &K, 1));
            MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(P, NULL, &K, N));

            if (mbedtls_mpi_cmp_int(P, 1) == 1 &&
                mbedtls_mpi_cmp_mpi(P, N) == -1) {
                MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(Q, NULL, N, P));
                goto cleanup;
            }

            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&K, &K, 1));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&K, &K, &K));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&K, &K, N));
        }

        if (mbedtls_mpi_cmp_int(&K, 1) != 0) {
            break;
        }
    }

    ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

cleanup:
    mbedtls_mpi_free(&K);
    mbedtls_mpi_free(&T);
    return ret;
}

int mbedtls_rsa_import(mbedtls_rsa_context *ctx,
                       const mbedtls_mpi *N,
                       const mbedtls_mpi *P, const mbedtls_mpi *Q,
                       const mbedtls_mpi *D, const mbedtls_mpi *E)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((N != NULL && (ret = mbedtls_mpi_copy(&ctx->N, N)) != 0) ||
        (P != NULL && (ret = mbedtls_mpi_copy(&ctx->P, P)) != 0) ||
        (Q != NULL && (ret = mbedtls_mpi_copy(&ctx->Q, Q)) != 0) ||
        (D != NULL && (ret = mbedtls_mpi_copy(&ctx->D, D)) != 0) ||
        (E != NULL && (ret = mbedtls_mpi_copy(&ctx->E, E)) != 0)) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }

    if (N != NULL) {
        ctx->len = mbedtls_mpi_size(&ctx->N);
    }

    return 0;
}

int mbedtls_rsa_import_raw(mbedtls_rsa_context *ctx,
                           unsigned char const *N, size_t N_len,
                           unsigned char const *P, size_t P_len,
                           unsigned char const *Q, size_t Q_len,
                           unsigned char const *D, size_t D_len,
                           unsigned char const *E, size_t E_len)
{
    int ret = 0;

    if (N != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->N, N, N_len));
        ctx->len = mbedtls_mpi_size(&ctx->N);
    }

    if (P != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->P, P, P_len));
    }

    if (Q != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->Q, Q, Q_len));
    }

    if (D != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->D, D, D_len));
    }

    if (E != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->E, E, E_len));
    }

cleanup:
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }

    return 0;
}

int mbedtls_rsa_complete(mbedtls_rsa_context *ctx)
{
    int ret = 0;
    int have_N, have_P, have_Q, have_D, have_E;
#if !defined(MBEDTLS_RSA_NO_CRT)
    int have_DP, have_DQ, have_QP;
#endif
    int n_missing, pq_missing, d_missing, is_pub, is_priv;

    have_N = (mbedtls_mpi_cmp_int(&ctx->N, 0) != 0);
    have_P = (mbedtls_mpi_cmp_int(&ctx->P, 0) != 0);
    have_Q = (mbedtls_mpi_cmp_int(&ctx->Q, 0) != 0);
    have_D = (mbedtls_mpi_cmp_int(&ctx->D, 0) != 0);
    have_E = (mbedtls_mpi_cmp_int(&ctx->E, 0) != 0);

#if !defined(MBEDTLS_RSA_NO_CRT)
    have_DP = (mbedtls_mpi_cmp_int(&ctx->DP, 0) != 0);
    have_DQ = (mbedtls_mpi_cmp_int(&ctx->DQ, 0) != 0);
    have_QP = (mbedtls_mpi_cmp_int(&ctx->QP, 0) != 0);
#endif

    n_missing  =              have_P &&  have_Q &&  have_D && have_E;
    pq_missing =   have_N && !have_P && !have_Q &&  have_D && have_E;
    d_missing  =              have_P &&  have_Q && !have_D && have_E;
    is_pub     =   have_N && !have_P && !have_Q && !have_D && have_E;
    is_priv = n_missing || pq_missing || d_missing;

    if (!is_priv && !is_pub) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    if (!have_N && have_P && have_Q) {
        if ((ret = mbedtls_mpi_mul_mpi(&ctx->N, &ctx->P, &ctx->Q)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
        }

        ctx->len = mbedtls_mpi_size(&ctx->N);
    }

    if (pq_missing) {
        ret = rsa_deduce_primes(&ctx->N, &ctx->E, &ctx->D, &ctx->P, &ctx->Q);
        if (ret != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
        }
    } else if (d_missing) {
        ret = mbedtls_rsa_deduce_private_exponent(&ctx->P, &ctx->Q, &ctx->E,
                                                  &ctx->D);
        if (ret != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
        }
    }

#if !defined(MBEDTLS_RSA_NO_CRT)
    if (is_priv && !(have_DP && have_DQ && have_QP)) {
        ret = mbedtls_rsa_deduce_crt(&ctx->P, &ctx->Q, &ctx->D,
                                     &ctx->DP, &ctx->DQ, &ctx->QP);
        if (ret != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
        }
    }
#endif

    ret = rsa_check_context(ctx, is_priv, 1);
    if (ret == 0) {
        mbedtls_v3_shim_pk_rsa_sync_bits_from_ctx(ctx);
    }
    return ret;
}

int mbedtls_rsa_export_raw(const mbedtls_rsa_context *ctx,
                           unsigned char *N, size_t N_len,
                           unsigned char *P, size_t P_len,
                           unsigned char *Q, size_t Q_len,
                           unsigned char *D, size_t D_len,
                           unsigned char *E, size_t E_len)
{
    int ret = 0;
    int is_priv;

    is_priv =
        mbedtls_mpi_cmp_int(&ctx->N, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->P, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->Q, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->D, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->E, 0) != 0;

    if (!is_priv && (P != NULL || Q != NULL || D != NULL)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    if (N != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->N, N, N_len));
    }

    if (P != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->P, P, P_len));
    }

    if (Q != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->Q, Q, Q_len));
    }

    if (D != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->D, D, D_len));
    }

    if (E != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->E, E, E_len));
    }

cleanup:
    return ret;
}

int mbedtls_rsa_export(const mbedtls_rsa_context *ctx,
                       mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q,
                       mbedtls_mpi *D, mbedtls_mpi *E)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int is_priv;

    is_priv =
        mbedtls_mpi_cmp_int(&ctx->N, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->P, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->Q, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->D, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->E, 0) != 0;

    if (!is_priv && (P != NULL || Q != NULL || D != NULL)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    if ((N != NULL && (ret = mbedtls_mpi_copy(N, &ctx->N)) != 0) ||
        (P != NULL && (ret = mbedtls_mpi_copy(P, &ctx->P)) != 0) ||
        (Q != NULL && (ret = mbedtls_mpi_copy(Q, &ctx->Q)) != 0) ||
        (D != NULL && (ret = mbedtls_mpi_copy(D, &ctx->D)) != 0) ||
        (E != NULL && (ret = mbedtls_mpi_copy(E, &ctx->E)) != 0)) {
        return ret;
    }

    return 0;
}

int mbedtls_rsa_export_crt(const mbedtls_rsa_context *ctx,
                           mbedtls_mpi *DP, mbedtls_mpi *DQ, mbedtls_mpi *QP)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int is_priv;

    is_priv =
        mbedtls_mpi_cmp_int(&ctx->N, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->P, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->Q, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->D, 0) != 0 &&
        mbedtls_mpi_cmp_int(&ctx->E, 0) != 0;

    if (!is_priv) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

#if !defined(MBEDTLS_RSA_NO_CRT)
    if ((DP != NULL && (ret = mbedtls_mpi_copy(DP, &ctx->DP)) != 0) ||
        (DQ != NULL && (ret = mbedtls_mpi_copy(DQ, &ctx->DQ)) != 0) ||
        (QP != NULL && (ret = mbedtls_mpi_copy(QP, &ctx->QP)) != 0)) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }
#else
    if ((ret = mbedtls_rsa_deduce_crt(&ctx->P, &ctx->Q, &ctx->D,
                                      DP, DQ, QP)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret);
    }
#endif

    return 0;
}

int mbedtls_rsa_write_key_der(const mbedtls_rsa_context *rsa, 
                              unsigned char *buf, size_t size)
{
    int ret = 0;
    unsigned char *p = buf + size;
    size_t len = 0;

    /* RSA private keys are serialized as a sequence of 9 fields:
     * Version (0), N, E, D, P, Q, DP, DQ, QP 
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &rsa->MBEDTLS_PRIVATE(QP)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &rsa->MBEDTLS_PRIVATE(DQ)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &rsa->MBEDTLS_PRIVATE(DP)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &rsa->MBEDTLS_PRIVATE(Q)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &rsa->MBEDTLS_PRIVATE(P)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &rsa->MBEDTLS_PRIVATE(D)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &rsa->MBEDTLS_PRIVATE(E)));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, &rsa->MBEDTLS_PRIVATE(N)));
    
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&p, buf, 0)); /* Version 0 */
    
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    /* The data is written backwards from the end of the buffer. 
     * Shift it to the beginning of the buffer.
     */
    memmove(buf, p, len);

    return (int) len;
}
#endif /* MBEDTLS_RSA_C */
