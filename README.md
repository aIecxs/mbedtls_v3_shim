# mbedtls_v3_shim

An ESP-IDF component that allows legacy code written for mbedTLS v3 to compile and run against mbedTLS v4 (PSA-based API).

## Background

ESP-IDF v6+ ships with mbedTLS v4, which introduces significant API changes:

1. **PSA Crypto API** - Random number generation and many cryptographic operations now use PSA internally
2. **Private headers** - Many types and functions moved from public headers to `mbedtls/private/*.h`
3. **Removed APIs** - Functions like `mbedtls_ssl_conf_rng()`, `mbedtls_ctr_drbg_reseed()`, and 3DES support were removed
4. **Changed signatures** - Functions like `mbedtls_pk_parse_key()` and `mbedtls_pk_sign()` no longer take RNG parameters

This component bridges the gap so that libraries like **libssh** (which use the legacy mbedTLS API) can compile without source modifications.

## How It Works

### 1. Private Header Exposure

mbedTLS v4 provides a mechanism to access private APIs via the `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` macro. When defined before including mbedTLS headers, it exposes internal types and functions from `mbedtls/private/*.h`.

Our compatibility headers define this macro and include the appropriate private headers:

```c
#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

#include "mbedtls/private/rsa.h"      // For mbedtls_rsa_context, mbedtls_rsa_*()
#include "mbedtls/private/ecdsa.h"    // For mbedtls_ecdsa_context, mbedtls_ecdsa_*()
#include "mbedtls/private/pk_private.h"  // For mbedtls_pk_type_t, MBEDTLS_PK_RSA, etc.
```

### 2. Header Chaining with `#include_next`

For headers that still exist publicly but need augmentation, we use GCC's `#include_next` directive to include the real header first, then add our compatibility extensions:

```c
#include_next "mbedtls/pk.h"           // Get the real public API
#include "mbedtls/private/pk_private.h" // Add private types
```

### 3. Signature Adaptation Macros

Where function signatures changed (RNG arguments removed), we provide inline wrappers and macros:

```c
// Wrapper calls the real v4 5-arg function
static inline int mbedtls_pk_parse_key_v4_real(
    mbedtls_pk_context *ctx,
    const unsigned char *key, size_t keylen,
    const unsigned char *pwd, size_t pwdlen)
{
    return mbedtls_pk_parse_key(ctx, key, keylen, pwd, pwdlen);
}

// Macro accepts legacy 7-arg calls, discards f_rng and p_rng
#define mbedtls_pk_parse_key(ctx, key, keylen, pwd, pwdlen, f_rng, p_rng) \
    mbedtls_pk_parse_key_v4_real(ctx, key, keylen, pwd, pwdlen)
```

### 4. PSA-Backed Stubs

For removed APIs like entropy and CTR_DRBG, we provide stub implementations backed by PSA:

```c
static inline int mbedtls_entropy_func(void *data, unsigned char *output, size_t len)
{
    (void) psa_crypto_init();  // Idempotent
    return psa_generate_random(output, len) == PSA_SUCCESS ? 0 : -1;
}
```

## Compatibility Headers

| Header | Purpose |
|--------|---------|
| `pk.h` | Exposes `mbedtls_pk_type_t`, `MBEDTLS_PK_RSA`, `MBEDTLS_PK_ECDSA`, etc. Wraps `mbedtls_pk_parse_key()` (7→5 args) and `mbedtls_pk_sign()` (9→7 args). Defines `MBEDTLS_PK_RSA_ALT` and `MBEDTLS_PK_ECKEY_DH`. Redirects `mbedtls_pk_rsa()` and `mbedtls_pk_free()` to lazy RSA materialization helpers (see below). |
| `rsa.h` | Exposes `mbedtls_rsa_context` and RSA functions (`mbedtls_rsa_init`, `mbedtls_rsa_gen_key`, `mbedtls_rsa_export`, etc.) |
| `ecdsa.h` | Exposes `mbedtls_ecdsa_context` and ECDSA functions (`mbedtls_ecdsa_init`, `mbedtls_ecdsa_sign`, `mbedtls_ecdsa_verify`, `mbedtls_ecdsa_genkey`, etc.) |
| `ecdh.h` | Exposes `mbedtls_ecdh_context` and ECDH functions |
| `entropy.h` | Provides `mbedtls_entropy_context` stub and `mbedtls_entropy_func()` backed by PSA |
| `ctr_drbg.h` | Provides `mbedtls_ctr_drbg_context` stub, `mbedtls_ctr_drbg_random()` via PSA, no-op `mbedtls_ctr_drbg_reseed()`, and `MBEDTLS_CTR_DRBG_PR_ON/OFF` defines |
| `ssl_compat.h` | No-op `mbedtls_ssl_conf_rng()` (TLS now uses PSA RNG internally) |
| `md.h` | Exposes HMAC functions (`mbedtls_md_hmac_starts`, `mbedtls_md_hmac_update`, `mbedtls_md_hmac_finish`) |
| `cipher.h` | Exposes cipher types; defines removed 3DES types (`MBEDTLS_CIPHER_DES_EDE3_CBC`, etc.) as `MBEDTLS_CIPHER_NONE` |
| `chacha20.h` | Exposes ChaCha20 from private headers |
| `poly1305.h` | Exposes Poly1305 from private headers |

## ESP-IDF Port Headers

ESP-IDF's mbedTLS port (`components/mbedtls/port/include/mbedtls/`) already provides some compatibility headers that this component leverages:

- **`bignum.h`** - Exposes `mbedtls_mpi` and bignum functions
- **`ecp.h`** - Exposes `mbedtls_ecp_keypair`, `mbedtls_ecp_group`, `mbedtls_ecp_point`, and ECP functions

These port headers already define `MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS` and include the private headers, so our compatibility layer works seamlessly with them.

## Usage

### In Your Component's CMakeLists.txt

Add `mbedtls_v3_shim` as a dependency:

```cmake
idf_component_register(
    SRCS "your_source.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES mbedtls mbedtls_v3_shim
)
```

### Include Order

The compatibility headers must be found **before** the standard mbedTLS headers. This is handled by placing this component's include directory first in the include path. For libssh, this was done in its `CMakeLists.txt`:

```cmake
idf_component_register(
    SRCS ${libssh_SRCS}
    INCLUDE_DIRS ${MBEDTLS_V3_SHIM_INCLUDE_DIR} ${LIBSSH_DIR}/include
    PRIV_REQUIRES mbedtls mbedtls_v3_shim
)
```

### 5. Lazy RSA materialization (`src/pk_rsa.c`)

On mbedTLS v4, RSA private keys parsed via `mbedtls_pk_parse_key()` are stored in PSA and no longer expose a transparent `mbedtls_rsa_context` through `pk_ctx`. Legacy code such as libssh's `pki_key_dup()` still calls `mbedtls_pk_rsa()` followed by `mbedtls_rsa_export()`.

The shim intercepts `mbedtls_pk_rsa()` and, on first use, exports the key (DER via `mbedtls_pk_write_key_der()` or `psa_export_key()`), parses it into a heap-allocated `mbedtls_rsa_context`, and caches it by `pk_context` pointer until `mbedtls_pk_free()`.

## Limitations

1. **3DES operations will fail at runtime** - The cipher types are defined but map to `MBEDTLS_CIPHER_NONE`
2. **RSA cache memory** - Materialized RSA contexts duplicate key material alongside PSA until `mbedtls_pk_free()`
3. **`mbedtls_pk_ec()` is not materialized** - ECDSA paths that rely on `mbedtls_pk_ec()` may still need a similar bridge
4. **`mbedtls_pk_setup()`'s dummy-info handling is RSA-only** - a legacy caller that fetches `mbedtls_pk_info_from_type()` for a non-RSA type and feeds it back into `mbedtls_pk_setup()` will be set up as RSA regardless (see 5. Lazy RSA materialization)
5. **`mbedtls_pk_write_key_pem()`/`mbedtls_pk_write_pubkey_pem()` always emit an RSA PEM header** - both go through the RSA-only materialization path
6. **`mbedtls_pk_decrypt()`/`mbedtls_pk_encrypt()` are RSA only** - other pk types return `MBEDTLS_ERR_PK_TYPE_MISMATCH`; padding scheme (PKCS#1 v1.5 vs OAEP) follows whatever the materialized RSA context is configured with


## Arduino IDE 2.x

The arduino-esp32 core's `platform.txt` lists `{compiler.cpreprocessor.flags}` ahead of local library `{includes}` which can leave `#include_next` with nothing to chain to. Therefore the path is hardcoded in `MBEDTLS_V3_SHIM_REAL_PK_H`. It is overridable at build time from `sketch/build_opt.h` in case a different toolchain lays out headers differently.  
`{compiler.sdk.path}/{build.memory_type}/include` serves as the entry point, so the path must traverse two levels up:  
```c
-DMBEDTLS_V3_SHIM_REAL_PK_H=\"<../../include/mbedtls/mbedtls/tf-psa-crypto/include/mbedtls/pk.h>\"
```


## References

- [mbedTLS PSA Transition Guide](https://github.com/Mbed-TLS/mbedtls/blob/development/tf-psa-crypto/docs/psa-transition.md)
- [mbedTLS v4 ChangeLog](https://github.com/Mbed-TLS/mbedtls/blob/development/ChangeLog)
- [ESP-IDF mbedTLS Component](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/protocols/mbedtls.html)
