# AES128

Assignment: AES-128 implementation
Course: Cryptography
Instructor: Dr. Moshier

## Source Files: 
* aes128.c
* aes128.h
* main.c

## Current state: 
* MixColumns method is causing a segfault. Attempted to implement in a way MixColumn and MixColumnInv is the same function, but ran     into issues.
* SubstBytes and shift_rows methods work well both ways
* KeyExpansion method is still generating incorrectly.
## References:
* https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
* https://en.wikipedia.org/wiki/Rijndael_MixColumns
* https://en.wikipedia.org/wiki/AES_key_schedule
