/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BASE32_H_
#define _BASE32_H_ 1

/* decodes a base32 string into arbitrary binary data */
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int base32_decode(unsigned char* dst, size_t dlen, size_t* olen,
        const unsigned char* src, size_t slen);

#ifdef __cplusplus
}
#endif

#endif // _BASE32_H_
