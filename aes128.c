/*
Assignment: AES-128 implementation
Course: Cryptography
Instructor: Dr. Moshier
*/

//aes128.c file to implement necessary functions for aes-128.

#include "aes128.h"

uint8_t aes_mult(uint8_t a, uint8_t b) {
    uint8_t res = 0;
    uint8_t p = b;
    while (a != 0) {
      if (a%2 == 1)
        res ^= p;
      a >>= 1; //divide by x (discard constant coefficient)
      p <<= 1; //multiply by x
      if (p & 0x100)
        p ^= 0x11b;
    }
  return res;
}

uint8_t* aes_poly_mult (uint8_t* p, uint8_t* q) {
  static uint8_t res[] = {0, 0, 0, 0};
  for (int i = 0; i < 4; ++i) {
    for (int j =0; j < 4; ++j) {
      res[(i+j)%4] ^= aes_mult(p[i], q[j]);
    }
  }
  return res;
}


uint8_t timesN(int n, uint8_t Scr) {
  if (n==1)
    return Scr;
  else if (n==2)
    return (Scr<<1)^(0x1b&(Scr>>7));
  else if (n==3)
    return ((Scr<<1)^(0x1b&(Scr>>7)))^Scr;
  else if (n==9)
    return times2(times2(times2(Scr)))^Scr;
  else if (n==11)
    return times2(times2(times2(Scr))^Scr)^Scr;
  else if (n==13)
    return times2(times2(times3(Scr)))^Scr;
  else if (n==14)
    return times13(Scr)^Scr;
  else
    return Scr;
}
uint8_t times2(uint8_t Scr) {
  return (Scr<<1)^(0x1b&(Scr>>7));
}
uint8_t times3(uint8_t Scr) {
  return ((Scr<<1)^(0x1b&(Scr>>7)))^Scr;
}
uint8_t times9(uint8_t Scr) {
  return times2(times2(times2(Scr)))^Scr;
}
uint8_t times11(uint8_t Scr) {
 return times2(times2(times2(Scr))^Scr)^Scr;
}
uint8_t times13(uint8_t Scr) {
  return times2(times2(times3(Scr)))^Scr;
}
uint8_t times14(uint8_t Scr) {
  return times13(Scr)^Scr;
}

void SubstBytes(uint8_t** state, bool isInv) {
  for (int c = 0; c < 4; ++c) {
    for (int r = 0; r < 4; ++r) {
      if (!isInv) {
        state[c][r] = SBox[state[c][r]];
      }
      else {
        state[c][r] = SBoxInv[state[c][r]];
      }
    }
  }
}
void shift_rows(uint8_t** state , int shift_inc) { //shift_inc = 1 for shiftRows, 4 for shiftRowsInv
  uint8_t temp[4][4];
  for (int c = 0; c < 4; ++c) {
    for (int r = 0; r < 4; ++r) {
      temp[c][r] = state[c][r];
    }
  }
  /*
  {0x00, 0x10, 0x20, 0x30, 0x01 ,0x11, 0x21, 0x31, 0x02, 0x12, 0x22, 0x32, 0x03, 0x13, 0x23, 0x33} ==>

    [0][0]=0x00  [1][0]=0x01  [2][0]=0x02  [3][0]=0x03
    [0][1]=0x10  [1][1]=0x11  [2][1]=0x12  [3][1]=0x13
    [0][2]=0x20  [1][2]=0x21  [2][2]=0x22  [3][2]=0x23
    [0][3]=0x30  [1][3]=0x31  [2][3]=0x32  [3][3]=0x33
  */
  for (int r = 0; r < 4; ++r) { //we do nothing to the 0th row, so skip that
    state[r][1] = temp[(r+shift_inc)&0x3][1];
    state[r][2] = temp[(r+2*shift_inc)&0x3][2];
    state[r][3] = temp[(r+3*shift_inc)&0x3][3];
  }
}


void AddRoundKey(uint8_t** state, uint32_t w) {
  uint8_t t[4];
  t[0] = (w & 0xff000000)>>24;
  t[1] = (w & 0x00ff0000)>>16;
  t[2] = (w & 0x0000ff00)>>8;
  t[3] = (w & 0x000000ff);
    for (int c = 0; c < 4; ++c) {
      for (int r = 0; r < 4; ++r) {
        state[c][r] ^= t[r];
      }
    }
}

void MixColumns(uint8_t** state, uint8_t** coefficient) {
  uint8_t temp[4][4];
  for (int c = 0; c < 4; ++c) {
    for (int r = 0; r < 4; ++r) {
      temp[r][c] = state[r][c];
    }
    printf("\n");
  }
  for (int j=0; j < 4; ++j) {
    state[j][0] = (timesN(coefficient[0][0],temp[j][0]) ^ timesN(coefficient[1][0],temp[j][1]) ^ timesN(coefficient[2][0],temp[j][2]) ^ timesN(coefficient[3][0],temp[j][3]));
    state[j][1] = (timesN(coefficient[0][1],temp[j][0]) ^ timesN(coefficient[1][1],temp[j][1]) ^ timesN(coefficient[2][1],temp[j][2]) ^ timesN(coefficient[3][1],temp[j][3]));
    state[j][2] = (timesN(coefficient[0][2],temp[j][0]) ^ timesN(coefficient[1][2],temp[j][1]) ^ timesN(coefficient[2][2],temp[j][2]) ^ timesN(coefficient[3][2],temp[j][3]));
    state[j][3] = (timesN(coefficient[0][3],temp[j][0]) ^ timesN(coefficient[1][3],temp[j][1]) ^ timesN(coefficient[2][3],temp[j][2]) ^ timesN(coefficient[3][3],temp[j][3]));
  }
}

void KeyExpansion ( uint8_t key[4* NumK], uint32_t* w) { //generate key schedule for 11 addRoundKey() function calls
  uint32_t temp;
  int i = 0;
  while ( i < NumK) {
    w[i] = byteToColumn(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
    i++;
  }

  i = NumK;
  while (i < NumB * (NumR+1)) {
    temp = w[i-1];
    if (i%NumK == 0)
      temp = SubWord(RotWord(temp)) ^ RCons[i/NumK];
    w[i] = w[i-NumK] ^ temp;
    i++;
  }
}

uint32_t byteToColumn(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4) {
  return (((b1<<8 | b2)<<8 | b3)<<8 | b4);
}

uint32_t RotWord(uint32_t word) {
  return (word << 8|(word >> (32 - 8))); //rotate left by one byte
  //word = word >> 8|(word << (32 - 8)) & 0xFFFFFFFF; //rotate right by one byte
}

uint32_t SubWord(uint32_t word) {
  uint8_t t1, t2, t3, t4;
  t1 = (word & 0xff000000)>>24;
  t2 = (word & 0x00ff0000)>>16;
  t3 = (word & 0x0000ff00)>>8;
  t4 = (word & 0x000000ff);
  return (byteToColumn(SBox[t1], SBox[t2], SBox[t3], SBox[t4]));
}

void Cipher(uint8_t** in, uint8_t** out, uint32_t* w, uint8_t** coefficient) {
  uint8_t** state = malloc ( 4 * sizeof *state);
  for (int c = 0; c < 4; ++c) {
    state[c] = malloc (4 * sizeof *state[c]);
  }
  for (int r = 0; r < 4; ++r) {
    for (int c = 0; c < 4; ++c) {
      state[r][c] = in[r][c];
    }
  }
  AddRoundKey(state, w[0]);
  for (int round = 1; round < NumR; ++round) {
    SubstBytes(state, false);
    shift_rows(state, 1);
    //MixColumns(state, coefficient);
    AddRoundKey(state, w[round]);
  }

  SubstBytes(state, false);
  shift_rows(state, 1);
  AddRoundKey(state, w[NumR]);

  for (int r = 0; r < 4; ++r) {
    for (int c = 0; c < 4; ++c) {
      out[r][c] = state[r][c];
    }
  }
}
