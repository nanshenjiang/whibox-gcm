#ifndef WHIBOX_GCM_WBAES_H
#define WHIBOX_GCM_WBAES_H

#include <wbcrypto/aes.h>
#include <wbcrypto/modes.h>
#include <WBMatrix/WBMatrix.h>

#ifdef __cplusplus
extern "C" {
#endif

    /******************************************************************
    * CHOW Whitebox-AES
    *****************************************************************/

    struct wbaes_context {
        uint32_t TypeII[10][16][256];
        uint32_t TypeIII[9][16][256];
        uint8_t TypeIV_II[9][4][3][8][16][16];
        uint8_t TypeIV_III[9][4][3][8][16][16];
        uint8_t TypeIa[16][256];
        uint8_t TypeIb[16][256];
    };

    typedef struct wbaes_context WBCRYPTO_wbaes_context;

    void WBCRYPTO_wbaes_gen_table(WBCRYPTO_wbaes_context *ctx, const uint8_t *key, size_t keylen);
    void WBCRYPTO_wbaes_encrypt(const uint8_t *input, uint8_t *output, WBCRYPTO_wbaes_context *ctx);
    WBCRYPTO_gcm_context *WBCRYPTO_wbaes_gcm_init(WBCRYPTO_wbaes_context *key);

    void genPermutation4(uint8_t *permutation, uint8_t *inverse);
    void genPermutation8(uint8_t *permutation, uint8_t *inverse);
    void MatrixcomM4to8(M4 m1, M4 m2, M8 *mat);

#ifdef __cplusplus
}
#endif

#endif //WHIBOX_GCM_WBAES_H
