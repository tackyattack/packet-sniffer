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

void xor_str_self(char *strA, char *strB, uint16_t length)
{
    for (uint16_t i = 0; i < length; i++)
    {
        strA[i] = strA[i] ^ strB[i];
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



//"f4 2c 6f c5 2d f0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
// http://anandam.name/pbkdf2/
void exclusive_or_sum(char *P, char *S, uint16_t c, uint16_t i, char *output)
{
    char U_x[20] = {0};
    char U_1[20] = {0};
    char U_2[20] = {0};
    char U_last[20] = {0};
    char U_o[20] = {0}; // xor result
    uint8_t sz = strlen(S) + 4 + 1;
    char *S_cat = (char *)malloc(sz);
    strcpy(S_cat, S);
    uint16_t end_of_S_index = strlen(S_cat);
    S_cat[end_of_S_index]   = 0x00 + 0;
    S_cat[end_of_S_index+1] = 0x00 + 0;
    S_cat[end_of_S_index+2] = ((i & 0xff00) >> 8) + 0;
    S_cat[end_of_S_index+3] = (i & 0x00ff)        + 0; // this will break down once >9
    S_cat[end_of_S_index+4] = '\0';
    uint8_t xx = strlen(S_cat);
    HMAC(P, strlen(P), S_cat, 8, U_x); // IEEE + 0001
    memcpy(U_last, U_x, 20);
    uint16_t cnt = 1;
    
    // !!!! I think you have the algorithm wrong. Each U_x is used for itself
    // in creating the new one. The XOR is completley separate and is not used
    // to feed the next U_x.
    
    for(uint16_t c_cnt = 0; c_cnt < (c-1); c_cnt++)
    { // check to see if all of this logic makes sense
        HMAC(P, strlen(P), U_last, sizeof(U_last), U_x);
        xor_str(U_x, U_last, U_o, 20);
        memcpy(U_last, U_x, 20);
        cnt++;
    }
    
//    HMAC(P, strlen(P), S_cat, strlen(S_cat), U_1);
//    HMAC(P, strlen(P), U_1, sizeof(U_1), U_2); // make sure strlen is working '\0'
//    memcpy(U_last, U_2, 20);
//    xor_str(U_1, U_2, U_o, 20);
//    for(uint16_t i = 0; i < c; i++) // start ahead because we aleady did first
//    {
//        HMAC(P, strlen(P), U_last, sizeof(U_last), U_1);
//        xor_str(U_last, U_1, U_o, 20); // should probably switch xor to modify the input instead of making an output variable
//    }
//
//    memcpy(output, U_o, sizeof(U_o));
}

void F(char *P, char *S, uint16_t c, uint16_t i, char *output)
{
    //char U_x[20] = {0};
}

void PBKDF2(char *P, char *S, uint16_t c, uint16_t dkLen, char *output)
{
    const uint16_t hLen = 20;
    
    uint16_t l = ceil(1.0 * dkLen / hLen); // number of hLen-octet blocks
    uint16_t r = dkLen - (l - 1)*hLen;   // r is the number of octets in the last block
    
    // example: if l=2 and r=12, that means there'll be 40 octets, hLen (20) in the first block, r in the second (12)
    //          which should come out to dkLen (32 in example)
    
    //    T_1 = F (P, S, c, 1) ,
    //    T_2 = F (P, S, c, 2) ,
    //    ...
    //    T_l = F (P, S, c, l) ,
    // Where F is the XOR sum
    // Iterate up to the l'th block
    
    // The derived key (DK) will be a concat of these blocks:
    // DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
    // With the last block being r bytes long
    
    uint16_t i = 1;
    char hBlock[hLen] = {0};
    //"f4 2c 6f c5 2d f0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
    for(; i <= l; i++)
    {
        exclusive_or_sum(P, S, c, i, hBlock);
        strcat(output, hBlock);
    }
    
    
}

// https://www.wireshark.org/tools/wpa-psk.html

void convert_WPA_to_PSK(char *password, char *SSID, char *output)
{
    PBKDF2(password, SSID, 4096, 256/8, output);
}
