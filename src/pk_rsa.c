/*
 * Lazy RSA context materialization for PSA-backed PK contexts (mbedTLS v4).
 *
 * mbedTLS v4 stores RSA private keys in PSA slots; legacy code expects a
 * transparent mbedtls_rsa_context from mbedtls_pk_rsa(). We materialize one
 * on demand and cache it by pk_context pointer until mbedtls_pk_free().
 */

#define MBEDTLS_V3_SHIM_INTERNAL

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
int mbedtls_rsa_parse_key(mbedtls_rsa_context *rsa,
                          const unsigned char *key,
                          size_t keylen);
int mbedtls_rsa_write_pubkey(const mbedtls_rsa_context *rsa,
                             unsigned char *start,
                             unsigned char **p);

/*
 * ============================================================================
 * 5. Lazy RSA materialization
 * ============================================================================
 */

typedef struct mbedtls_v3_shim_pk_rsa_entry {
    mbedtls_pk_context *pk;
    mbedtls_rsa_context *rsa;
    struct mbedtls_v3_shim_pk_rsa_entry *next;
} mbedtls_v3_shim_pk_rsa_entry;

static mbedtls_v3_shim_pk_rsa_entry *s_pk_rsa_cache;

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

/*
 * If a cache entry still has an empty pub_raw (e.g. the RSA context was
 * completed via mbedtls_rsa_import()/_complete() after materialization
 * rather than reparsed), resync it. Shared by mbedtls_pk_write_pubkey_der()
 * and mbedtls_pk_write_pubkey_pem() below.
 */
static void pk_resync_pubkey_raw_if_cached(mbedtls_pk_context *pk)
{
    mbedtls_v3_shim_pk_rsa_entry *entry;

    if (!pk_is_rsa(pk)) {
        return;
    }

    entry = cache_find(pk);
    if (entry != NULL && entry->rsa != NULL) {
        pk->MBEDTLS_PRIVATE(pub_raw_len) = 0;
        pk_sync_pubkey_raw_from_rsa(pk, entry->rsa);
    }
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

/*
 * mbedtls_pk_decrypt()/mbedtls_pk_encrypt() were dropped from the pk layer
 * in v4. Both are implemented here on top of the same materialized RSA
 * context as the rest of this section, and dispatch to mbedtls_rsa_pkcs1_decrypt()/
 * mbedtls_rsa_pkcs1_encrypt() - the real v4 padding-aware wrappers, which pick
 * PKCS#1 v1.5 vs OAEP from the context's configured padding scheme and run on
 * the legacy (hardware-accelerated, where the target supports it) RSA code
 * path. PSA is only ever touched once per key, inside mbedtls_v3_shim_pk_rsa()
 * above, to pull the key out of its PSA slot; every actual encrypt/decrypt
 * operation after that runs through the legacy math, not psa_asymmetric_*().
 */

int mbedtls_pk_decrypt_v4_compat(
    mbedtls_pk_context *ctx,
    const unsigned char *input,
    size_t ilen,
    unsigned char *output,
    size_t *olen,
    size_t osize,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    mbedtls_rsa_context *rsa;

    if (ctx == NULL || input == NULL || output == NULL || olen == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    *olen = 0;

    if (mbedtls_pk_get_type(ctx) != MBEDTLS_PK_RSA) {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    rsa = mbedtls_v3_shim_pk_rsa(ctx);
    if (rsa == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ilen != mbedtls_rsa_get_len(rsa)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    return mbedtls_rsa_pkcs1_decrypt(rsa, f_rng, p_rng, olen, input, output, osize);
}

int mbedtls_pk_encrypt_v4_compat(
    mbedtls_pk_context *ctx,
    const unsigned char *input,
    size_t ilen,
    unsigned char *output,
    size_t *olen,
    size_t osize,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    mbedtls_rsa_context *rsa;
    size_t key_len;
    int ret;

    if (ctx == NULL || input == NULL || output == NULL || olen == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    *olen = 0;

    if (mbedtls_pk_get_type(ctx) != MBEDTLS_PK_RSA) {
        return MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    /* Materializes (or reuses the cached) transparent RSA context; works
     * for both public-only and private+public pk contexts, since encryption
     * only ever needs the public half (N, E). */
    rsa = mbedtls_v3_shim_pk_rsa(ctx);
    if (rsa == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    key_len = mbedtls_rsa_get_len(rsa);
    if (osize < key_len) {
        return MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }

    ret = mbedtls_rsa_pkcs1_encrypt(rsa, f_rng, p_rng, ilen, input, output);
    if (ret == 0) {
        *olen = key_len;
    }

    return ret;
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
    int ret;

    if (ctx == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /*
     * mbedtls_pk_info_from_type() (pk.h, 4. PSA-Backed Stubs) hands back a
     * dummy pointer for types v4's info table doesn't cover. Swap it for the
     * real v4 info struct before calling the real pk_setup below.
     *
     * LIMITATION: the dummy pointer doesn't carry the originally requested
     * pk_type, so this always resolves it as RSA. That matches every known
     * caller (libssh only ever does this for RSA_ALT-style setup), but a
     * caller requesting a non-RSA type via the dummy path would misbehave.
     */
    if (info == MBEDTLS_V3_SHIM_PK_INFO_DUMMY) {
        const mbedtls_pk_info_t *real_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);

        if (real_info != NULL && real_info != MBEDTLS_V3_SHIM_PK_INFO_DUMMY) {
            info = real_info;
        }
    }

    ret = mbedtls_pk_setup(ctx, info);

    if (ret == 0 && mbedtls_pk_get_type(ctx) == MBEDTLS_PK_RSA) {
        if (mbedtls_v3_shim_pk_rsa(ctx) == NULL) {
            mbedtls_pk_free(ctx);
            return MBEDTLS_ERR_PK_ALLOC_FAILED;
        }
    }

    return ret;
}

int mbedtls_v3_shim_pk_write_key_der(const mbedtls_pk_context *ctx,
                                     unsigned char *buf, size_t size)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    // If it's an RSA key and we have a materialized context, write from that
    if (pk_is_rsa(ctx)) {
        mbedtls_v3_shim_pk_rsa_entry *entry = cache_find((mbedtls_pk_context *) ctx);

        if (entry != NULL && entry->rsa != NULL) {
            return mbedtls_rsa_write_key_der(entry->rsa, buf, size);
        }
    }

    // Otherwise, fall back to native core lookup behavior
    return mbedtls_pk_write_key_der(ctx, buf, size);
}

int mbedtls_v3_shim_pk_write_pubkey_der(const mbedtls_pk_context *ctx,
                                        unsigned char *buf, size_t size)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pk_resync_pubkey_raw_if_cached((mbedtls_pk_context *) ctx);

    return mbedtls_pk_write_pubkey_der(ctx, buf, size);
}

#if defined(MBEDTLS_PK_WRITE_C) && defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"

int mbedtls_v3_shim_pk_write_key_pem(const mbedtls_pk_context *ctx,
                                     unsigned char *buf, size_t size)
{
    unsigned char der_buf[4096];
    unsigned char *der_start;
    size_t der_len;
    size_t olen;
    int ret;

    // Convert the cached context fields into raw DER bytes first
    ret = mbedtls_v3_shim_pk_write_key_der(ctx, der_buf, sizeof(der_buf));
    if (ret < 0) {
        return ret;
    }

    der_len = (size_t) ret;
    der_start = der_buf + sizeof(der_buf) - der_len;

    // Wrap the output into a standard legacy PEM armor layout block
    return mbedtls_pem_write_buffer("-----BEGIN RSA PRIVATE KEY-----\n",
                                    "-----END RSA PRIVATE KEY-----\n",
                                    der_start, der_len, buf, size, &olen);
}

int mbedtls_v3_shim_pk_write_pubkey_pem(const mbedtls_pk_context *ctx,
                                        unsigned char *buf, size_t size)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pk_resync_pubkey_raw_if_cached((mbedtls_pk_context *) ctx);

    return mbedtls_pk_write_pubkey_pem(ctx, buf, size);
}
#endif /* MBEDTLS_PK_WRITE_C && MBEDTLS_PEM_WRITE_C */
