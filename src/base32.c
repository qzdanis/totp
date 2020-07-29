/* SPDX-License-Identifier: BSD-2-Clause */
#include "base32.h"

#include <errno.h>

static const unsigned char base32_dec_map[128] = {
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 26,  27,  28,  29,  30,  31,  127, 127, 127, 127,
    127, 32,  127, 127, 127, 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
    10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
    25,  127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127};

int base32_decode(unsigned char* dst, size_t dlen, size_t* olen,
                  const unsigned char* src, size_t slen) {
    size_t i = 0;
    size_t x0 = 0;
/* needed for 32-bit machines, they can't store all 5 bytes in a size_t */
#if (SIZE_MAX < UINT64_MAX)
    size_t x1 = 0;
#endif
    size_t n = 0;
    size_t j = 0;
    unsigned char* p;

    /* first pass: check for validity and get output length */
    for (; i < slen; ++i) {
        /* skip spaces before checking for EOL */
        while ((i < slen) && (src[i] == ' ')) {
            ++i;
            ++x0;
        }

        /* spaces at the end are okay */
        if (i == slen) {
            break;
        }
        if (((slen - i) > 2) && ((src[i] == '\r') && (src[i + 1] == '\n'))) {
            continue;
        }
        if (src[i] == '\n') {
            continue;
        }

        /* space inside line is an error */
        if (x0) {
            errno = EINVAL;
            return -errno;
        }
        /* more than 6 padding characters is an error */
        if ((src[i] == '=') && (++j > 6)) {
            errno = EINVAL;
            return -errno;
        }
        if ((src[i] > 127) || (base32_dec_map[src[i]] == 127)) {
            errno = EINVAL;
            return -errno;
        }
        if ((base32_dec_map[src[i]] < 32) && j) {
            errno = EINVAL;
            return -errno;
        }

        ++n;
    }

    /* we can't have 2 or 5 padding chars */
    if ((j == 5) || (j == 2)) {
        errno = EINVAL;
        return -errno;
    }

    if (!n) {
        *olen = 0;
        return 0;
    }

    /* base32 encodes 5 bytes into 8 characters
     * so we can multiply by 10 to get an even number and shift
     * by 4 to get the number of output bytes.
     * we aren't concerned about overflow here since that would take
     * about 4 billion characters to overflow a 32-bit integer
     */
    n = (10 * n) >> 4;
    if (j == 6) {
        n -= 4;
    } else if (j > 1) {
        n -= (j - 1);
    } else {
        n -= j;
    }

    if (!dst || (dlen < n)) {
        *olen = n;
        errno = ENOMEM;
        return -errno;
    }

    for (j = 7, n = 0, x0 = 0, p = dst; i > 0; --i, ++src) {
        if ((*src == '\r') || (*src == '\n') || (*src == ' ')) {
            continue;
        }

        j -= (base32_dec_map[*src] == 32);
#if (SIZE_MAX < UINT64_MAX)
        x1 = (x0 & 0xF8000000ul);
#endif
        x0 = (x0 << 5) | (base32_dec_map[*src] & 0x1F);

        if (++n == 8) {
            n = 0;
            if (j > 0) {
#if (SIZE_MAX < UINT64_MAX)
                *(p++) = (unsigned char)(x1);
#else
                *(p++) = (unsigned char)(x0 >> 32);
#endif
            }
            if (j > 1) {
                *(p++) = (unsigned char)(x0 >> 24);
            }
            if (j > 2) {
                *(p++) = (unsigned char)(x0 >> 16);
            }
            if (j > 3) {
                *(p++) = (unsigned char)(x0 >> 8);
            }
            if (j > 4) {
                *(p++) = (unsigned char)(x0);
            }
        }
    }

    *olen = (p - dst);

    return 0;
}
