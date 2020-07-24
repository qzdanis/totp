/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _TOTP_H_
#define _TOTP_H_ 1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t totp_sha1(const unsigned char key[32], unsigned int digits,
        unsigned int timeslice);

#ifdef __cplusplus
}
#endif

#endif // _TOTP_H_
