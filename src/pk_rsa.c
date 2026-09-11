/*
 * Lazy RSA context materialization for PSA-backed PK contexts (mbedTLS v4).
 *
 * mbedTLS v4 stores RSA private keys in PSA slots; legacy code expects a
 * transparent mbedtls_rsa_context from mbedtls_pk_rsa(). We materialize one
 * on demand and cache it by pk_context pointer until mbedtls_pk_free().
 */

#define MBEDTLS_V3_SHIM_INTERNAL

#include <stdlib.h>
#include <string.h>

#include "mbedtls/build_info.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "psa/crypto.h"

#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

#include "mbedtls/pk.h"
#include "mbedtls/private/pk_private.h"
#include "mbedtls/private/rsa.h"

#include "mbedtls_v3_shim/pk_ec.h"
#include "mbedtls_v3_shim/pk_rsa.h"


/* Forward declaration in case mbedtls_pk_write_key_der is not exposed in pk.h */
int mbedtls_pk_write_key_der(const mbedtls_pk_context *ctx,
                             unsigned char *buf,
                             size_t size);

#define PK_DECRYPT_DER_BUFFER_SIZE 4096


static int pk_decrypt_psa_error(psa_status_t status)
{
    return (status == PSA_SUCCESS) ? 0 : -1;
}


static psa_status_t pk_decrypt_import_rsa_key(
    mbedtls_pk_context *ctx,
    psa_key_id_t *key_id,
    unsigned char **der_allocated)
{
    unsigned char *der;
    int der_len;
    psa_key_attributes_t attributes;
    psa_status_t status;

    if (ctx == NULL || key_id == NULL || der_allocated == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *key_id = PSA_KEY_ID_NULL;
    *der_allocated = NULL;

    der = (unsigned char *) malloc(PK_DECRYPT_DER_BUFFER_SIZE);
    if (der == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    der_len = mbedtls_pk_write_key_der(
        ctx,
        der,
        PK_DECRYPT_DER_BUFFER_SIZE
    );

    if (der_len <= 0 || (size_t) der_len > PK_DECRYPT_DER_BUFFER_SIZE) {
        free(der);
        return PSA_ERROR_DATA_INVALID;
    }

    attributes = psa_key_attributes_init();

    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_CRYPT);

    status = psa_import_key(
        &attributes,
        der + PK_DECRYPT_DER_BUFFER_SIZE - der_len,
        (size_t) der_len,
        key_id
    );

    psa_reset_key_attributes(&attributes);

    if (status != PSA_SUCCESS) {
        free(der);
        return status;
    }

    *der_allocated = der;
    return PSA_SUCCESS;
}


int mbedtls_pk_decrypt_v3_compat(
    mbedtls_pk_context *ctx,
    const unsigned char *input,
    size_t ilen,
    unsigned char *output,
    size_t *olen,
    size_t osize,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    unsigned char *der = NULL;
    psa_status_t status;

    (void) f_rng;
    (void) p_rng;

    if (ctx == NULL || input == NULL || output == NULL || olen == NULL) {
        return -1;
    }

    *olen = 0;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return pk_decrypt_psa_error(status);
    }

    if (mbedtls_pk_get_type(ctx) != MBEDTLS_PK_RSA) {
        return -1;
    }

    status = pk_decrypt_import_rsa_key(ctx, &key_id, &der);
    if (status != PSA_SUCCESS) {
        return pk_decrypt_psa_error(status);
    }

    status = psa_asymmetric_decrypt(
        key_id,
        PSA_ALG_RSA_PKCS1V15_CRYPT,
        input,
        ilen,
        NULL,
        0,
        output,
        osize,
        olen
    );

    if (key_id != PSA_KEY_ID_NULL) {
        psa_status_t destroy_status = psa_destroy_key(key_id);
        if (status == PSA_SUCCESS && destroy_status != PSA_SUCCESS) {
            status = destroy_status;
        }
    }

    free(der);

    return pk_decrypt_psa_error(status);
}

typedef struct mbedtls_v3_shim_pk_rsa_entry {
    mbedtls_pk_context *pk;
    mbedtls_rsa_context *rsa;
    struct mbedtls_v3_shim_pk_rsa_entry *next;
} mbedtls_v3_shim_pk_rsa_entry;

static mbedtls_v3_shim_pk_rsa_entry *s_pk_rsa_cache;

/* Declared in rsa.c but not exposed in rsa.h on all TF-PSA-Crypto versions. */
int mbedtls_rsa_parse_key(mbedtls_rsa_context *rsa,
                          const unsigned char *key,
                          size_t keylen);
int mbedtls_rsa_write_pubkey(const mbedtls_rsa_context *rsa,
                             unsigned char *start,
                             unsigned char **p);

static mbedtls_v3_shim_pk_rsa_entry *cache_find(mbedtls_pk_context *pk)
{
    mbedtls_v3_shim_pk_rsa_entry *entry;

    for (entry = s_pk_rsa_cache; entry != NULL; entry = entry->next) {
        if (entry->pk == pk) {
            return entry;
        }
    }

    return NULL;
}

static void cache_remove(mbedtls_pk_context *pk)
{
    mbedtls_v3_shim_pk_rsa_entry **cursor = &s_pk_rsa_cache;

    while (*cursor != NULL) {
        if ((*cursor)->pk == pk) {
            mbedtls_v3_shim_pk_rsa_entry *dead = *cursor;

            *cursor = dead->next;
            if (dead->rsa != NULL) {
                mbedtls_rsa_free(dead->rsa);
                mbedtls_free(dead->rsa);
            }
            mbedtls_free(dead);
            return;
        }
        cursor = &(*cursor)->next;
    }
}

static int cache_insert(mbedtls_pk_context *pk, mbedtls_rsa_context *rsa)
{
    mbedtls_v3_shim_pk_rsa_entry *entry =
        mbedtls_calloc(1, sizeof(*entry));

    if (entry == NULL) {
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    entry->pk = pk;
    entry->rsa = rsa;
    entry->next = s_pk_rsa_cache;
    s_pk_rsa_cache = entry;

    return 0;
}

static int pk_is_rsa(const mbedtls_pk_context *pk)
{
    return mbedtls_pk_get_type(pk) == MBEDTLS_PK_RSA;
}

static int pk_is_empty_rsa_template(const mbedtls_pk_context *pk)
{
    if (!pk_is_rsa(pk)) {
        return 0;
    }

    if (!mbedtls_svc_key_id_is_null(pk->MBEDTLS_PRIVATE(priv_id))) {
        return 0;
    }

    if (pk->MBEDTLS_PRIVATE(pub_raw_len) > 0) {
        return 0;
    }

    return pk->MBEDTLS_PRIVATE(pk_info) != NULL;
}

static int pk_has_private_psa_key(const mbedtls_pk_context *pk)
{
    return pk_is_rsa(pk) &&
           !mbedtls_svc_key_id_is_null(pk->MBEDTLS_PRIVATE(priv_id));
}

static mbedtls_rsa_context *alloc_empty_rsa(void)
{
    mbedtls_rsa_context *rsa =
        mbedtls_calloc(1, sizeof(*rsa));

    if (rsa == NULL) {
        return NULL;
    }

    mbedtls_rsa_init(rsa);
    return rsa;
}

#if defined(MBEDTLS_PK_WRITE_C)
static mbedtls_rsa_context *materialize_rsa_from_pk_der(
    const mbedtls_pk_context *pk)
{
    unsigned char der_buf[6144];
    int written;
    mbedtls_rsa_context *rsa;
    unsigned char *der_start;
    size_t der_len;
    int rc;

    written = mbedtls_pk_write_key_der(pk, der_buf, sizeof(der_buf));
    if (written < 0) {
        return NULL;
    }

    der_start = der_buf + sizeof(der_buf) - (size_t) written;
    der_len = (size_t) written;

    rsa = alloc_empty_rsa();
    if (rsa == NULL) {
        return NULL;
    }

    rc = mbedtls_rsa_parse_key(rsa, der_start, der_len);
    if (rc != 0) {
        mbedtls_rsa_free(rsa);
        mbedtls_free(rsa);
        return NULL;
    }

    return rsa;
}
#endif /* MBEDTLS_PK_WRITE_C */

#if defined(MBEDTLS_PSA_CRYPTO_C)
static mbedtls_rsa_context *materialize_rsa_from_psa(
    const mbedtls_pk_context *pk)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    size_t export_size;
    size_t export_len;
    unsigned char *export_buf = NULL;
    mbedtls_rsa_context *rsa = NULL;
    int rc;

    status = psa_get_key_attributes(pk->MBEDTLS_PRIVATE(priv_id), &attributes);
    if (status != PSA_SUCCESS) {
        return NULL;
    }

    export_size = PSA_EXPORT_KEY_OUTPUT_SIZE(
        psa_get_key_type(&attributes),
        psa_get_key_bits(&attributes));
    psa_reset_key_attributes(&attributes);

    if (export_size == 0) {
        return NULL;
    }

    export_buf = mbedtls_calloc(1, export_size);
    if (export_buf == NULL) {
        return NULL;
    }

    status = psa_export_key(pk->MBEDTLS_PRIVATE(priv_id),
                            export_buf,
                            export_size,
                            &export_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    rsa = alloc_empty_rsa();
    if (rsa == NULL) {
        goto cleanup;
    }

    rc = mbedtls_rsa_parse_key(rsa, export_buf, export_len);
    if (rc != 0) {
        mbedtls_rsa_free(rsa);
        mbedtls_free(rsa);
        rsa = NULL;
    }

cleanup:
    mbedtls_free(export_buf);
    return rsa;
}
#endif /* MBEDTLS_PSA_CRYPTO_C */

static void pk_sync_bits_from_rsa(mbedtls_pk_context *pk,
                                  const mbedtls_rsa_context *rsa)
{
    size_t bits;

    if (pk == NULL || rsa == NULL ||
        pk->MBEDTLS_PRIVATE(bits) != 0) {
        return;
    }

    if (mbedtls_mpi_cmp_int(&rsa->MBEDTLS_PRIVATE(N), 0) == 0) {
        return;
    }

    bits = mbedtls_mpi_bitlen(&rsa->MBEDTLS_PRIVATE(N));
    if (bits > 0) {
        pk->MBEDTLS_PRIVATE(bits) = bits;
    }
}

/*
 * mbedTLS v4 rsa_verify_wrap() imports pk->pub_raw into PSA. Legacy code that
 * builds RSA keys via mbedtls_rsa_import/complete only populates the lazy RSA
 * context, leaving pub_raw empty. Export PKCS#1 RSAPublicKey DER so verify works.
 */
static void pk_sync_pubkey_raw_from_rsa(mbedtls_pk_context *pk,
                                        const mbedtls_rsa_context *rsa)
{
    unsigned char buf[MBEDTLS_PK_MAX_PUBKEY_RAW_LEN];
    unsigned char *end;
    int written;
    size_t len;

    if (pk == NULL || rsa == NULL || pk->MBEDTLS_PRIVATE(pub_raw_len) > 0) {
        return;
    }

    if (mbedtls_mpi_cmp_int(&rsa->MBEDTLS_PRIVATE(N), 0) == 0 ||
        mbedtls_mpi_cmp_int(&rsa->MBEDTLS_PRIVATE(E), 0) == 0) {
        return;
    }

    end = buf + sizeof(buf);
    written = mbedtls_rsa_write_pubkey(rsa, buf, &end);
    if (written <= 0) {
        return;
    }

    len = (size_t) written;
    if (len > sizeof(pk->MBEDTLS_PRIVATE(pub_raw))) {
        return;
    }

    memcpy(pk->MBEDTLS_PRIVATE(pub_raw), end, len);
    pk->MBEDTLS_PRIVATE(pub_raw_len) = len;
#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
    pk->MBEDTLS_PRIVATE(psa_type) = PSA_KEY_TYPE_RSA_PUBLIC_KEY;
#endif
}

static void pk_sync_from_rsa(mbedtls_pk_context *pk,
                             const mbedtls_rsa_context *rsa)
{
    pk_sync_bits_from_rsa(pk, rsa);
    pk_sync_pubkey_raw_from_rsa(pk, rsa);
}

void mbedtls_v3_shim_pk_rsa_sync_bits_from_ctx(mbedtls_rsa_context *rsa)
{
    mbedtls_v3_shim_pk_rsa_entry *entry;

    if (rsa == NULL) {
        return;
    }

    for (entry = s_pk_rsa_cache; entry != NULL; entry = entry->next) {
        if (entry->rsa == rsa) {
            pk_sync_from_rsa(entry->pk, rsa);
            return;
        }
    }
}

static mbedtls_rsa_context *materialize_rsa(mbedtls_pk_context *pk)
{
    mbedtls_rsa_context *rsa = NULL;

    if (pk_is_empty_rsa_template(pk)) {
        return alloc_empty_rsa();
    }

#if defined(MBEDTLS_PK_WRITE_C)
    if (pk_has_private_psa_key(pk) || pk->MBEDTLS_PRIVATE(pub_raw_len) > 0) {
        rsa = materialize_rsa_from_pk_der(pk);
        if (rsa != NULL) {
            return rsa;
        }
    }
#endif /* MBEDTLS_PK_WRITE_C */

#if defined(MBEDTLS_PSA_CRYPTO_C)
    if (pk_has_private_psa_key(pk)) {
        rsa = materialize_rsa_from_psa(pk);
    }
#endif /* MBEDTLS_PSA_CRYPTO_C */

    return rsa;
}

mbedtls_rsa_context *mbedtls_v3_shim_pk_rsa(mbedtls_pk_context *pk)
{
    mbedtls_v3_shim_pk_rsa_entry *entry;
    mbedtls_rsa_context *rsa;
    int rc;

    if (pk == NULL || !pk_is_rsa(pk)) {
        return NULL;
    }

    entry = cache_find(pk);
    if (entry != NULL) {
        pk_sync_from_rsa(pk, entry->rsa);
        return entry->rsa;
    }

    rsa = materialize_rsa(pk);
    if (rsa == NULL) {
        return NULL;
    }

    rc = cache_insert(pk, rsa);
    if (rc != 0) {
        mbedtls_rsa_free(rsa);
        mbedtls_free(rsa);
        return NULL;
    }

    pk_sync_from_rsa(pk, rsa);
    return rsa;
}

void mbedtls_v3_shim_pk_rsa_cache_release(mbedtls_pk_context *pk)
{
    if (pk != NULL) {
        cache_remove(pk);
    }
}

void mbedtls_v3_shim_pk_free(mbedtls_pk_context *ctx)
{
    if (ctx != NULL) {
        mbedtls_v3_shim_pk_rsa_cache_release(ctx);
        mbedtls_v3_shim_pk_ec_cache_release(ctx);
    }

    mbedtls_pk_free(ctx);
}

int mbedtls_v3_shim_pk_setup(mbedtls_pk_context *ctx,
                             const mbedtls_pk_info_t *info)
{
    int ret = mbedtls_pk_setup(ctx, info);

    if (ret == 0 && mbedtls_pk_get_type(ctx) == MBEDTLS_PK_RSA) {
        if (mbedtls_v3_shim_pk_rsa(ctx) == NULL) {
            mbedtls_pk_free(ctx);
            return MBEDTLS_ERR_PK_ALLOC_FAILED;
        }
    }

    return ret;
}