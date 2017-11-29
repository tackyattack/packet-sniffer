//
//  WPA2_keying.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 11/29/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include "WPA2_keying.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "HMAC.h"
#include "SHA_1_hash.h"


// In WPA-PSK, the PMK is the PSK
// Page 3416 of IEEE 802.11-2016 gives a pass-phrase to PSK example. Annex J has test vectors.
// PSK = PBKDF2(passPhrase, ssid, 4096, 256/8)
// PBKDF2 is defined here: https://www.ietf.org/rfc/rfc2898.txt
// http://jorisvr.nl/wpapsk.html gives a good overview


//  hLen:    length in octets of pseudorandom function output, a positive integer

// PBKDF2
// https://www.ietf.org/rfc/rfc2898.txt


// XOR a long string
void xor_str(char *strA, char *strB, char *output, uint16_t length)
{
    for (uint16_t i = 0; i < length; i++)
    {
        output[i] = strA[i] ^ strB[i];
    }
}

// function F

//F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
//
//where
//
//U_1 = PRF (P, S || INT (i)) ,
//U_2 = PRF (P, U_1) ,
//...
//U_c = PRF (P, U_{c-1})

// My algorithm:
//
// input = salt || INT(i)
//
// B = input
// loop()
// {
//    A = hash(B)
//    B = A
//    if(first time around)
//    {
//       last_xor = A
//    }
//    else
//    {
//       last_xor = last_xor ^ A
//     }
// }
// end result: last_xor is the xor sum


void exclusive_or_sum(char *P, char *S, uint16_t c, uint16_t i)
{
    char U_1[20] = {0};
    char U_2[20] = {0};
    char U_last[20] = {0};
    char U_o[20] = {0}; // xor result
    char *S_cat = (char *)malloc(sizeof(char)*(strlen(S) + 4));
    strcpy(S_cat, S);
    uint16_t end_of_S_index = strlen(S_cat);
    S_cat[end_of_S_index]   = 0x00;
    S_cat[end_of_S_index+1] = 0x00;
    S_cat[end_of_S_index+2] = (i & 0xff00) >> 8;
    S_cat[end_of_S_index+3] = (i & 0x00ff);
    HMAC(P, S_cat, U_1);
    HMAC(P, U_1, U_2); // make sure strlen is working '\0'
    memcpy(U_last, U_2, 20);
    xor_str(U_1, U_2, U_o, 20);
    for(uint16_t i = 0; i < c; i++)
    {
        HMAC(P, U_last, U_1);
        xor_str(U_last, U_1, U_o, 20);
    }
}

void PBKDF2(char *P, char *S, uint16_t c, uint16_t dkLen)
{
    const uint16_t hLen = 20;
    
    uint16_t l = ceil(1.0 * dkLen / hLen); // number of hLen-octet blocks
    uint16_t r = dkLen - (l - 1)*hLen;   // r is the number of octets in the last block
    // example: if l=2 and r=12, that means there'll be 40 octets, hLen (20) in the first block, r in the second (12)
    //          which should come out to dkLen (32 in example)
}

void convert_WPA_to_PSK(char *password, char *SSID, uint8_t *output)
{
    PBKDF2(password, SSID, 4096, 256/8);
}

void test()
{
    char pw[] = "password";
    char ssid[] = "IEEE";
    convert_WPA_to_PSK(pw, ssid, NULL);
}
