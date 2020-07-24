/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdio.h>
#include <stdint.h>

#include "totp.h"

int main(int argc, char** argv) {
    printf("%u\n", totp_sha1((const unsigned char*) argv[1], 6, 30));
    return 0;
}
