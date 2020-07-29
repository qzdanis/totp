/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _TOTP_H_
#define _TOTP_H_ 1

/* generates variable digit codes per RFC 6238 */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t totp_sha1(const char key[32], unsigned int digits,
                   unsigned int timeslice);

#ifdef __cplusplus
}
#endif

#endif // _TOTP_H_
