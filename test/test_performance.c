#include "test_local.h"
#include <wbcrypto/aes.h>
#include <wbcrypto/wbaes.h>
#include <wbcrypto/wbaes_wbgcm_ee.h>
#include <wbcrypto/wbaes_wbgcm_ee2.h>
#include <wbcrypto/wbaes_wbgcm_mask.h>
#include <time.h>

#define TESTTIME 10

static const unsigned char key[16]={0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

void test_blackbox_aes_performance(){
    long long i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char *msg1M;
    unsigned char *cipher1M;
    clock_t program_start, program_end;
    double ts;

    msg1M = (unsigned char *) malloc(1024*1024*sizeof(unsigned char));
    cipher1M = (unsigned char *) malloc(1024*1024*sizeof(unsigned char));

    WBCRYPTO_aes_context aes_ctx;
    WBCRYPTO_aes_init_key(&aes_ctx, key, sizeof(key));

    WBCRYPTO_gcm_context *gcm_enc;
    gcm_enc=WBCRYPTO_aes_gcm_init(&aes_ctx);
    WBCRYPTO_gcm_setiv(gcm_enc,iv,sizeof(iv));
    WBCRYPTO_gcm_aad(gcm_enc,aad,sizeof(aad));
    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_gcm_encrypt(gcm_enc,msg1M,1024*1024,cipher1M,1024*1024);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts/CLOCKS_PER_SEC;
    printf("The gcm mode of BlackBox-AES encrypt 1MB spend: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME, 1/(ts/TESTTIME));
}

void test_wbaes_performance(){
    long long i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//    unsigned char *msg1M;
//    unsigned char *cipher1M;
    unsigned char msg1M[16];
    unsigned char cipher1M[16];
    clock_t program_start, program_end;
    double ts;

//    msg1M = (unsigned char *) malloc(1024*1024*sizeof(unsigned char));
//    cipher1M = (unsigned char *) malloc(1024*1024*sizeof(unsigned char));

    WBCRYPTO_wbaes_context wbaes_ctx;

    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_wbaes_gen_table(&wbaes_ctx, key, sizeof(key));
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts*1000/CLOCKS_PER_SEC;
    printf("The generate-table of WBAES spend: %lf ms\n", ts / TESTTIME);

    WBCRYPTO_gcm_context *gcm_enc;
    gcm_enc=WBCRYPTO_wbaes_gcm_init(&wbaes_ctx);
    WBCRYPTO_gcm_setiv(gcm_enc,iv,sizeof(iv));
    WBCRYPTO_gcm_aad(gcm_enc,aad,sizeof(aad));
    program_start = clock();
    for (i = 0; i < TESTTIME*64*1024; i++) {
        WBCRYPTO_gcm_encrypt(gcm_enc,msg1M,16,cipher1M,16);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts/CLOCKS_PER_SEC;
    printf("The gcm mode of WBAES encrypt 1MB spend: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME, 1/(ts/TESTTIME));

    WBCRYPTO_gcm_context *gcm_dec;
    gcm_dec=WBCRYPTO_wbaes_gcm_init(&wbaes_ctx);
    WBCRYPTO_gcm_setiv(gcm_dec,iv,sizeof(iv));
    WBCRYPTO_gcm_aad(gcm_dec,aad,sizeof(aad));
    program_start = clock();
    for (i = 0; i < TESTTIME*64*1024; i++) {
        WBCRYPTO_gcm_decrypt(gcm_dec,msg1M,16,cipher1M,16);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts/CLOCKS_PER_SEC;
    printf("The gcm mode of WBAES decrypt 1MB spend: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TESTTIME, 1/(ts/TESTTIME));
}

void test_wbaes_wbgcm_ee2_performance(){
    long long i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//    unsigned char *msg1M;
//    unsigned char *cipher1M;
    unsigned char msg1M[16];
    unsigned char cipher1M[16];
    clock_t program_start, program_end;
    double ts;

//    msg1M = (unsigned char *) malloc(1024*1024*sizeof(unsigned char));
//    cipher1M = (unsigned char *) malloc(1024*1024*sizeof(unsigned char));

    WBCRYPTO_wbaes_wbgcm_ee2_context wbaes_ctx;

    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_wbaes_wbgcm_ee2_gen_table(&wbaes_ctx, key, sizeof(key));
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts*1000/CLOCKS_PER_SEC;
    printf("The generate-table of WBAES-WBGCM-EE2 spend: %lf ms\n", ts / TESTTIME);

    WBCRYPTO_wbgcm_ee2_context *wbgcm_enc;
    wbgcm_enc=WBCRYPTO_wbaes_wbgcm_ee2_init(&wbaes_ctx);
    WBCRYPTO_wbaes_wbgcm_ee2_setiv(wbgcm_enc,iv,sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_ee2_aad(wbgcm_enc,aad,sizeof(aad));
    program_start = clock();
    for (i = 0; i < TESTTIME*64*1024; i++) {
        WBCRYPTO_wbaes_wbgcm_ee2_encrypt(wbgcm_enc,msg1M,16,cipher1M,16);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts/CLOCKS_PER_SEC;
    printf("The gcm mode of WBAES-WBGCM-EE2 encrypt 1MB spend: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME, 1/(ts/TESTTIME));

    WBCRYPTO_wbgcm_ee2_context *wbgcm_dec;
    wbgcm_dec=WBCRYPTO_wbaes_wbgcm_ee2_init(&wbaes_ctx);
    WBCRYPTO_wbaes_wbgcm_ee2_setiv(wbgcm_dec,iv,sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_ee2_aad(wbgcm_dec,aad,sizeof(aad));
    program_start = clock();
    for (i = 0; i < TESTTIME*64*1024; i++) {
        WBCRYPTO_wbaes_wbgcm_ee2_decrypt(wbgcm_dec,msg1M,16,cipher1M,16);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts/CLOCKS_PER_SEC;
    printf("The gcm mode of WBAES-WBGCM-EE2 decrypt 1MB spend: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TESTTIME, 1/(ts/TESTTIME));
}

void test_wbaes_wbgcm_mask_performance(){
    long long i;
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//    unsigned char *msg1M;
//    unsigned char *cipher1M;
    unsigned char msg1M[16];
    unsigned char cipher1M[16];
    clock_t program_start, program_end;
    double ts;

//    msg1M = (unsigned char *) malloc(1024*1024*sizeof(unsigned char));
//    cipher1M = (unsigned char *) malloc(1024*1024*sizeof(unsigned char));

    WBCRYPTO_wbaes_wbgcm_mask_context *wbaes_enc_ctx = WBCRYPTO_wbaes_wbgcm_mask_init_table();
    WBCRYPTO_wbaes_wbgcm_mask_context *wbaes_dec_ctx = WBCRYPTO_wbaes_wbgcm_mask_init_table();

    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        WBCRYPTO_wbaes_wbgcm_mask_gen_table(wbaes_enc_ctx, wbaes_dec_ctx, key, sizeof(key));
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts*1000/CLOCKS_PER_SEC;
    printf("The generate-table of WBAES-WBGCM-MASK spend: %lf ms\n", ts / TESTTIME /2);

    WBCRYPTO_wbgcm_mask_context *wbgcm_enc;
    wbgcm_enc=WBCRYPTO_wbaes_wbgcm_mask_init(wbaes_enc_ctx);
    WBCRYPTO_wbaes_wbgcm_mask_setiv(wbgcm_enc,iv,sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_mask_aad(wbgcm_enc,aad,sizeof(aad));
    program_start = clock();
    for (i = 0; i < TESTTIME*64*1024; i++) {
        WBCRYPTO_wbaes_wbgcm_mask_encrypt(wbgcm_enc,msg1M,sizeof(msg1M),cipher1M,sizeof(cipher1M));
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts/CLOCKS_PER_SEC;
    printf("The gcm mode of WBAES-WBGCM-MASK encrypt 1MB spend: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME, 1/(ts/TESTTIME));

    WBCRYPTO_wbgcm_mask_context *wbgcm_dec;
    wbgcm_dec=WBCRYPTO_wbaes_wbgcm_mask_init(wbaes_enc_ctx);
    WBCRYPTO_wbaes_wbgcm_mask_setiv(wbgcm_dec,iv,sizeof(iv));
    WBCRYPTO_wbaes_wbgcm_mask_aad(wbgcm_dec,aad,sizeof(aad));
    program_start = clock();
    for (i = 0; i < TESTTIME*64*1024; i++) {
        WBCRYPTO_wbaes_wbgcm_mask_decrypt(wbgcm_dec,msg1M,sizeof(msg1M),cipher1M,sizeof(cipher1M));
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts/CLOCKS_PER_SEC;
    printf("The gcm mode of WBAES-WBGCM-MASK decrypt 1MB spend: %lf s, it means that the decryption speed is: %f MByte/s\n", ts / TESTTIME, 1/(ts/TESTTIME));
}
int main(){
//    test_blackbox_aes_performance();
    test_wbaes_performance();
    test_wbaes_wbgcm_ee2_performance();
    test_wbaes_wbgcm_mask_performance();
}

