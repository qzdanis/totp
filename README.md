# totp - A simple \*nix CLI generator of TOTP/2FA codes

## Usage
`totp [-a key] sitename`

The program will attempt to read `$HOME/.totp/sitename` for the TOTP shared secret. The `-a` switch is provided to allow automatic creation of keyfiles.

## Dependencies
The only "real" dependency is mbedtls, as it provides the sha1 function. For convenience, a Python script (`configure.py`) is provided to generate a build.ninja file.

## Building
1. Either run `configure.py`, then `ninja`, or
2. `<compiler> -Iinclude -O -lmbedcrypto -o totp src/*.c`

## Caveats
* Only 6-digit codes will be generated with HMAC-SHA1 and a 30s interval
* `configure.py` assumes the compiler will be `clang`, though the following environment variables are supported:
    * `CC`
    * `LD`
    * `CFLAGS`
    * `LDFLAGS`
