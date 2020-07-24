/* SPDX-License-Identifier: BSD-2-Clause */
/* decodes a base32 string into arbitrary binary data */
#include <stddef.h>

int base32_decode(unsigned char* dst, size_t dlen, size_t* olen,
        const unsigned char* src, size_t slen);
