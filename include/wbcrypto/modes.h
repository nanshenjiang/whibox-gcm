#ifndef WBCRYPTO_MODES_H
#define WBCRYPTO_MODES_H

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

static const uint64_t last4[16] = {
        0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
        0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0  };

// 4 bytes -> word
#define GET_UINT32_BE(n,b,i) {                      \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )         \
        | ( (uint32_t) (b)[(i) + 1] << 16 )         \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )         \
        | ( (uint32_t) (b)[(i) + 3]       ); }

// word -> 4 bytes
#define PUT_UINT32_BE(n,b,i) {                      \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );   \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );   \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );   \
    (b)[(i) + 3] = (unsigned char) ( (n)       ); }

#ifdef  __cplusplus
extern "C" {
#endif

    typedef int (*block128_f) (const unsigned char in[16], unsigned char out[16],
                               const void *key);

    /******************************************************************
    * GCM mode
    *****************************************************************/
    struct gcm128_context{
        uint64_t len;                   // cipher data length processed so far
        uint64_t add_len;               // total add data length
        uint64_t HL[16];                // precalculated lo-half HTable
        uint64_t HH[16];                // precalculated hi-half HTable
        unsigned char base_ectr[16];    // first counter-mode cipher output for tag
        unsigned char y[16];            // the current cipher-input IV|Counter value
        unsigned char buf[16];          // buf working value
        void *key;                      // cipher context used
        block128_f block;               //encryption algorithm
    };
    /**
    * gcm-mode context
    * If need to use GCM mode, the user must initialize context
    */
    typedef struct gcm128_context WBCRYPTO_gcm_context;

    /******************************************************************
    * GCM mode
    *****************************************************************/

    /**
     * init the gcm128 context
     * @param key the context of some-algorithm
     * @param block the enc/dec-function of some-algorithm, often use encryption function
     * @return NULL is fault, otherwise successful
     */
    WBCRYPTO_gcm_context *WBCRYPTO_gcm_init(void *key, block128_f block);

    /**
     * set initialization-vec
     * @param ctx the context of gcm-mode
     * @param iv initialization-vector
     * @param len the length of initialization-vec
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_gcm_setiv(WBCRYPTO_gcm_context *ctx,
                          const unsigned char *iv, size_t len);

    /**
     * set additional-info
     * @param ctx the context of gcm-mode
     * @param aad additional information
     * @param len the length of additional-info
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_gcm_aad(WBCRYPTO_gcm_context *ctx,
                          const unsigned char *aad, size_t len);

    /**
     * encryption of gcm mode
     * @param ctx the context of gcm-mode
     * @param in plaintext
     * @param inlen size of plaintext
     * @param out ciphertext
     * @param outlen size of ciphertext
     * @return 1 if success, 0 if error
     */
    int WBCRYPTO_gcm_encrypt(WBCRYPTO_gcm_context *ctx,
                            const unsigned char *in, size_t inlen,
                            unsigned char *out, size_t outlen);

    /**
    * decryption of gcm mode
    * @param ctx the context of gcm-mode
    * @param in ciphertext
    * @param inlen size of ciphertext
    * @param out plaintext
    * @param outlen size of plaintext
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_gcm_decrypt(WBCRYPTO_gcm_context *ctx,
                            const unsigned char *in, size_t inlen,
                            unsigned char *out, size_t outlen);

    /**
    * obtain the tag(MAC value)
    * @param ctx the context of gcm-mode
    * @param tag input tag
    * @param len the length of tag
    * @return 1 if success, 0 if error
    */
    int WBCRYPTO_gcm_finish(WBCRYPTO_gcm_context *ctx,
                               unsigned char *tag, size_t len);

    /**
     * release the context of gcm-mode
     * @param ctx
     */
    void WBCRYPTO_gcm_free(WBCRYPTO_gcm_context *ctx);

#ifdef  __cplusplus
}
#endif

#endif //WBCRYPTO_MODES_H