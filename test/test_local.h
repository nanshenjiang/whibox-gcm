#ifndef WBCRYPTO_TEST_LOCAL_H
#define WBCRYPTO_TEST_LOCAL_H

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

//number of test cycle
#define TEST_CYCLE_NUM 1

// #define WBCRYPTO_TEST_KEY_FPATH "/mnt/f/test/key.whibox"
#define WBCRYPTO_TEST_ENC_KEY_FPATH "./enckey.whibox"
#define WBCRYPTO_TEST_DEC_KEY_FPATH "./deckey.whibox"

/****************************test util**************************/
//print string in hexadecimal
void TEST_print_state(unsigned char * in, size_t len);

//compare two values, and return 1 if correct and 0 if error
int TEST_cmp_values(const unsigned char *value1,const unsigned char *value2, int len);

#endif //WBCRYPTO_TEST_LOCAL_H
