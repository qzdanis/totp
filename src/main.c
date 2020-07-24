/* SPDX-License-Identifier: BSD-2-Clause */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "totp.h"

#define USAGE "Usage:\n" \
    " totp [-a key] site\n" \
    "Options:\n" \
    " -a\tadds the site with the given key\n" \
    " -h\tdisplay this help and exit" \

enum modes {
    ADD,
    GEN
};

static unsigned char mode = GEN;
static char* key = NULL;

static void usage() {
    fprintf(stderr, "%s\n", USAGE);
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
    char totp_dir[PATH_MAX];
    sprintf(totp_dir, "%s/.totp", getenv("HOME"));
    if (lstat(totp_dir, &st) < 0) {
        if (mkdir(totp_dir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
                < 0) {
            fprintf(stderr, "ERROR: could not create storage directory\n");
            return EX_OSERR;
        }
    }

    char file_path[PATH_MAX];
    sprintf(file_path, "%s/.totp/%s", getenv("HOME"), argv[0]);

    int oflag = (mode == ADD) ? O_WRONLY | O_CREAT | O_TRUNC : O_RDONLY;
    if ((fd = open(file_path, oflag, 0660)) < 0) {
        fprintf(stderr, "ERROR: could not open %s\n", file_path);
        return EX_SOFTWARE;
    }

    if (mode == ADD) {
        char keyline[33];
        keyline[32] = '\n';
        memcpy(keyline, key, 32);
        if (write(fd, keyline, 33) < 33) {
            fprintf(stderr, "ERROR: could not write key!\n");
            return EX_OSERR;
        }
        fprintf(stderr, "wrote key to %s\n", file_path);
    } else if (mode == GEN) {
        key = (char*) malloc(32);
        if (read(fd, key, 32) < 32) {
            fprintf(stderr, "ERROR: could not read key!\n");
            return EX_SOFTWARE;
        }
        printf("%u\n", totp_sha1((const unsigned char*) key, 6, 30));
    }

    return 0;
}
