#include <wbcrypto/wbaes.h>
#include <wbcrypto/modes.h>

WBCRYPTO_gcm_context *WBCRYPTO_wbaes_gcm_init(WBCRYPTO_wbaes_context *key){
    WBCRYPTO_gcm_context *ctx=WBCRYPTO_gcm_init(key, (block128_f) WBCRYPTO_wbaes_encrypt);
    return ctx;
}



