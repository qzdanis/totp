/* SPDX-License-Identifier: BSD-2-Clause */
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

#include "totp.h"

enum modes { ADD, GEN };

static unsigned char mode = GEN;
static char* key = NULL;

static void usage() {
    fprintf(stderr, "Usage:\n"
                    " totp [-a key] site\n"
                    "Options:\n"
                    " -a\tadds the site with the given key\n"
                    " -h\tdisplay this help and exit\n");
}

static int handle_opt(int ch) {
    switch (ch) {
    case 'a':
        mode = ADD;
        key = optarg;
        break;
    case 'h':
        usage();
        exit(0);
    case '?':
    default:
        usage();
        return -1;
    }

    return 0;
}

int main(int argc, char** argv) {
    int fd;
    int ch;

    while ((ch = getopt(argc, argv, "a:h")) != -1) {
        if (handle_opt(ch) < 0) {
            return EX_USAGE;
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 1) {
        usage();
        return EX_USAGE;
    }

    struct stat st;
    char file_path[PATH_MAX];

    sprintf(file_path, "%s/.totp", getenv("HOME"));

    if (lstat(file_path, &st) < 0) {
        if (mkdir(file_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) <
            0) {
            fprintf(stderr, "ERROR: could not create storage directory\n");
            return EX_OSERR;
        }
    }

    sprintf(file_path, "%s/%s", file_path, argv[0]);

    int oflag = (mode == ADD) ? O_WRONLY | O_CREAT | O_TRUNC : O_RDONLY;

    if ((fd = open(file_path, oflag, 0660)) < 0) {
        fprintf(stderr, "ERROR: could not open %s\n", file_path);
        return EX_SOFTWARE;
    }

    if (mode == ADD) {
        size_t keylen = strlen(key);

        char keyline[33];
        memset(keyline, 0, 33);

        memcpy(keyline, key, keylen);
        keyline[keylen] = '\n';

        if (write(fd, keyline, keylen + 1) < keylen + 1) {
            fprintf(stderr, "ERROR: could not write key!\n");
            return EX_OSERR;
        }

        fprintf(stderr, "wrote key to %s\n", file_path);
    } else if (mode == GEN) {
        key = (char*)malloc(32);

        size_t i = 0;
        char c;

        while ((read(fd, &c, 1) > 0) || (i == 32)) {
            if ((c > 47) && (c < 91) && (c != '\n')) {
                key[i++] = c;
            } else if (c == '\n') {
                break;
            }
        }

        printf("%u\n", totp_sha1((const char*)key, 6, 30));
    }

    return 0;
}
