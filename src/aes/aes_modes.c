#include <wbcrypto/aes.h>

WBCRYPTO_gcm_context *WBCRYPTO_aes_gcm_init(WBCRYPTO_aes_context *key) {
    WBCRYPTO_gcm_context *ctx = WBCRYPTO_gcm_init(key, (block128_f) WBCRYPTO_aes_encrypt);
    return ctx;
}
