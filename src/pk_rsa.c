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
    if (ctx == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    // Check if the caller supplied the dummy v3 compatibility pointer
    if (info == (const mbedtls_pk_info_t *)1) {
        // Temporarily bypass macro definition to fetch the real 
        // underlying v4 info struct mapping out of the core crypto stack
        #undef mbedtls_pk_info_from_type
        const mbedtls_pk_info_t *real_v4_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
        
        // Re-establish macro expansion context immediately
        #define mbedtls_pk_info_from_type(pk_type) mbedtls_pk_info_from_type_shim(pk_type)

        if (real_v4_info != NULL && real_v4_info != (const mbedtls_pk_info_t *)1) {
            info = real_v4_info;
        }
    }

    // Execute the real core setup routine using a valid v4 structural descriptor
    int ret = mbedtls_pk_setup(ctx, info);

    if (ret == 0 && mbedtls_pk_get_type(ctx) == MBEDTLS_PK_RSA) {
        if (mbedtls_v3_shim_pk_rsa(ctx) == NULL) {
            mbedtls_pk_free(ctx);
            return MBEDTLS_ERR_PK_ALLOC_FAILED;
        }
    }

    return ret;
}

// Forward declaration of shimmed key exporter
int mbedtls_rsa_write_key_der(const mbedtls_rsa_context *rsa, 
                              unsigned char *buf, size_t size);

int mbedtls_v3_shim_pk_write_key_der(const mbedtls_pk_context *ctx, 
                                     unsigned char *buf, size_t size)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    // If it's an RSA key and we have a materialized context, write from that
    if (mbedtls_pk_get_type(ctx) == MBEDTLS_PK_RSA) {
        mbedtls_v3_shim_pk_rsa_entry *entry = cache_find((mbedtls_pk_context *)ctx);
        if (entry != NULL && entry->rsa != NULL) {
            return mbedtls_rsa_write_key_der(entry->rsa, buf, size);
        }
    }

    // Otherwise, fall back to native core lookup behavior
    #undef mbedtls_pk_write_key_der
    int ret = mbedtls_pk_write_key_der(ctx, buf, size);
    #define mbedtls_pk_write_key_der(ctx, buf, size) mbedtls_v3_shim_pk_write_key_der((ctx), (buf), (size))
    return ret;
}

#if defined(MBEDTLS_PK_WRITE_C) && defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"

int mbedtls_v3_shim_pk_write_key_pem(const mbedtls_pk_context *ctx, 
                                     unsigned char *buf, size_t size)
{
    size_t olene = 0;
    unsigned char der_buf[4096];
    
    // Convert the cached context fields into raw DER bytes first
    int ret = mbedtls_v3_shim_pk_write_key_der(ctx, der_buf, sizeof(der_buf));
    if (ret < 0) {
        return ret;
    }

    size_t der_len = (size_t)ret;
    unsigned char *der_start = der_buf + sizeof(der_buf) - der_len;

    // Wrap the output into a standard legacy PEM armor layout block
    ret = mbedtls_pem_write_buffer("-----BEGIN RSA PRIVATE KEY-----\n",
                                   "-----END RSA PRIVATE KEY-----\n",
                                   der_start, der_len, buf, size, &olene);
    if (ret != 0) {
        return ret;
    }

    return 0;
}
#endif

/* 
 * Public key synchronization and export hooks for the shim layer
 */

int mbedtls_v3_shim_pk_write_pubkey_der(const mbedtls_pk_context *ctx, 
                                        unsigned char *buf, size_t size)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (mbedtls_pk_get_type(ctx) == MBEDTLS_PK_RSA) {
        mbedtls_v3_shim_pk_rsa_entry *entry = cache_find((mbedtls_pk_context *)ctx);
        if (entry != NULL && entry->rsa != NULL) {
            /* Force clear internal length guard so sync can update fields seamlessly */
            ((mbedtls_pk_context *)ctx)->MBEDTLS_PRIVATE(pub_raw_len) = 0;
            
            /* Synchronize N and E into the native v4 pub_raw buffer array */
            pk_sync_pubkey_raw_from_rsa((mbedtls_pk_context *)ctx, entry->rsa);
        }
    }

    /* Pass execution safely back down into the native core v4 engine */
    #undef mbedtls_pk_write_pubkey_der
    int ret = mbedtls_pk_write_pubkey_der(ctx, buf, size);
    #define mbedtls_pk_write_pubkey_der(ctx, buf, size) mbedtls_v3_shim_pk_write_pubkey_der((ctx), (buf), (size))
    return ret;
}

#if defined(MBEDTLS_PK_WRITE_C) && defined(MBEDTLS_PEM_WRITE_C)
int mbedtls_v3_shim_pk_write_pubkey_pem(const mbedtls_pk_context *ctx, 
                                        unsigned char *buf, size_t size)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* Sync key matrices before attempting native public PEM transformation layouts */
    if (mbedtls_pk_get_type(ctx) == MBEDTLS_PK_RSA) {
        mbedtls_v3_shim_pk_rsa_entry *entry = cache_find((mbedtls_pk_context *)ctx);
        if (entry != NULL && entry->rsa != NULL) {
            ((mbedtls_pk_context *)ctx)->MBEDTLS_PRIVATE(pub_raw_len) = 0;
            pk_sync_pubkey_raw_from_rsa((mbedtls_pk_context *)ctx, entry->rsa);
        }
    }

    #undef mbedtls_pk_write_pubkey_pem
    int ret = mbedtls_pk_write_pubkey_pem(ctx, buf, size);
    #define mbedtls_pk_write_pubkey_pem(ctx, buf, size) mbedtls_v3_shim_pk_write_pubkey_pem((ctx), (buf), (size))
    return ret;
}
#endif
