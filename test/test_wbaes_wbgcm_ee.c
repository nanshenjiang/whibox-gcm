#include <wbcrypto/wbaes_wbgcm_ee.h>
#include "test_local.h"

static const unsigned char key[16]={0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

static const unsigned char msg[16]={0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

int test_wbaes_wbgcm_ee(){
    int i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char cipher[16] = {0};
    unsigned char msg1024[1024] = {0};
    unsigned char cipher1024[1024] = {0};
    unsigned char plain1024[1024] = {0};
    for(i=0;i<1024;i++){
        msg1024[i]=i & 0xff;
    }

    WBCRYPTO_wbaes_wbgcm_ee_context wbaes_ctx;
    WBCRYPTO_wbaes_wbgcm_ee_gen_table(&wbaes_ctx, key, sizeof(key));

//    aux_WBCRYPTO_wbaes_wbgcm_ee_encrypt(msg, cipher, &wbaes_ctx);
//    TEST_print_state(cipher, sizeof(cipher));

    WBCRYPTO_wbgcm_ee_context *wbgcm_enc;
    wbgcm_enc=WBCRYPTO_wbaes_wbgcm_ee_init(&wbaes_ctx);
    WBCRYPTO_wbaes_wbgcm_ee_setiv(wbgcm_enc,iv,sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_ee_aad(wbgcm_enc,aad,sizeof(aad));
    WBCRYPTO_wbaes_wbgcm_ee_encrypt(wbgcm_enc,msg1024,sizeof(msg1024),cipher1024,sizeof(cipher1024));
    TEST_print_state(cipher1024, sizeof(cipher1024));

    WBCRYPTO_wbgcm_ee_context *wbgcm_dec;
    wbgcm_dec=WBCRYPTO_wbaes_wbgcm_ee_init(&wbaes_ctx);
    WBCRYPTO_wbaes_wbgcm_ee_setiv(wbgcm_dec,iv,sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_ee_aad(wbgcm_dec,aad,sizeof(aad));
    WBCRYPTO_wbaes_wbgcm_ee_decrypt(wbgcm_dec,cipher1024,sizeof(cipher1024),plain1024,sizeof(plain1024));
    TEST_print_state(plain1024, sizeof(plain1024));

    WBCRYPTO_wbaes_wbgcm_ee_free(wbgcm_enc);
    WBCRYPTO_wbaes_wbgcm_ee_free(wbgcm_dec);
}

int main(){
    test_wbaes_wbgcm_ee();
}