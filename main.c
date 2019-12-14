/*
Assignment: AES-128 implementation
Course: Cryptography
Instructor: Dr. Moshier
*/

//main.c to test the program

#include "aes128.h"

int main() {

  uint8_t cipherKey[] = {
   0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
   0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

  uint8_t ciphertext[NumB];
  uint8_t roundkeys[16];
  uint8_t** out = malloc ( 4 * sizeof *out);
  uint8_t** in = malloc ( 4 * sizeof *in);
  uint32_t* w = malloc ( 11 * sizeof *w);
  uint8_t** coefficient = malloc ( 4 * sizeof *coefficient);
  uint8_t** coefficientInv = malloc ( 4 * sizeof *coefficientInv);

  for (int c = 0; c < 4; ++c) {
    out[c] = malloc (4 * sizeof *out[c]);
    in[c] = malloc (4 * sizeof *in[c]);
    coefficient[c] = malloc (4 * sizeof *coefficient[c]);
    coefficientInv[c] = malloc (4 * sizeof *coefficientInv[c]);
  }

  uint8_t input[] = {0x32, 0x43, 0xf6, 0xa8,
                     0x88, 0x5a, 0x30, 0x8d,
                     0x31, 0x31, 0x98, 0xa2,
                     0xe0, 0x37, 0x07, 0x34};
  uint8_t const coeff[] = {2, 1, 1, 3,
                           3, 2, 1, 1,
                           1, 3, 2, 1,
                           1, 1, 3, 2};
  uint8_t const coeffInv[] = {0xe, 0xb, 0xd, 0x9,
                              0x9 ,0xe, 0xb, 0xd,
                              0xd, 0x9, 0xe, 0xb,
                              0xb, 0xd, 0x9, 0xe};

  for (int r = 0; r < 4; ++r) {
    for (int c = 0; c < 4; ++c) {
      coefficient[r][c] = coeff[4*r + c];
      coefficientInv[r][c] = coeffInv[4*r + c];
      in[r][c] = input[4*r + c];
    }
  }

  KeyExpansion(cipherKey, w);
  Cipher(in, out, w, coefficient);
  printf("\nafter cipher: \n");
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      printf("%x ", out[j][i]);
    }
    printf("\n");
  }
  return 0;
}
