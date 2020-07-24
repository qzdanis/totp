#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <mbedtls/sha1.h>

#include "base32.h"

size_t uint2bytes(uint64_t in, unsigned char* out) {
    size_t ctr = 0;
    for (unsigned int i = sizeof(uint64_t); i > 0; --i) {
        unsigned char byte = (unsigned char) (in >> (8 * (i - 1)));
        out[ctr++] = byte;
    }
    return ctr;
}

int main(int argc, char** argv) {
    /* decode input key */
    unsigned char key[64];
    memset(key, 0, 64);
    size_t olen;
    base32_decode(key, 20, &olen, (const unsigned char*) argv[1], 32);

    /* get time value */
    time_t t = time(NULL);
    uint64_t time_step = (uint64_t) t / 30;

    /* hmac */
    /* step 1, create first hash digest */
    unsigned char in0[72];
    memcpy(in0, key, 64);
    for (size_t i = 0; i < 64; ++i) {
        in0[i] ^= 0x36;
    }
    size_t ilen = 64 + uint2bytes(time_step, &in0[64]);
    unsigned char out0[20];
    mbedtls_sha1_ret(in0, ilen, out0);

    /* step 2, create second hash digest */
    unsigned char in1[84];
    memcpy(in1, key, 64);
    for (size_t i = 0; i < 64; ++i) {
        in1[i] ^= 0x5C;
    }
    memcpy(&in1[64], out0, 20);
    unsigned char out1[20];
    mbedtls_sha1_ret(in1, 84, out1);
    
    /* step 3, create 31-bit string */
    uint8_t offset_bits = out1[19] & 0x0F;
    uint32_t p = (uint32_t) (out1[offset_bits] << 24)
        | (uint32_t) (out1[offset_bits + 1] << 16)
        | (uint32_t) (out1[offset_bits + 2] << 8 )
        | (uint32_t) (out1[offset_bits + 3]);
    p &= 0x7FFFFFFF;

    /* step 4, create 6-digit code */
    uint32_t code = p % 1000000;

    printf("%.6u\n", code);

    return 0;
}
