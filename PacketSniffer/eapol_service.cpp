//
//  eapol_service.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 8/5/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//
// This is a service called from LLC that:
// 1. takes care of EAPOL frames
// 2. gives a temporal key mapped to a DA/SA MAC address pair (order doesn't matter, just that two MACs match)

// 802.11 standard: math functions
// x||y means the x and y, except in code, where it sometimes is the short-circuiting Boolean
// L (S, F, N) is bits F to F+N–1 of the bit string S starting from the left

// In WPA-PSK, the PMK is the PSK
// Page 3416 of IEEE 802.11-2016 gives a pass-phrase to PSK example. Annex J has test vectors.
// PSK = PBKDF2(passPhrase, ssid, 4096, 256/8)
// PBKDF2 is defined here: https://www.ietf.org/rfc/rfc2898.txt
// http://jorisvr.nl/wpapsk.html gives a good overview


#include "eapol_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "SHA_1_hash.h"
#include "HMAC.h"

struct key_info_t
{
    // -- OCTET MSB --
    uint16_t key_MIC:1; // set to 1 if a MIC is in this EAPOL-Key frame and is set to 0 if this message contains no MIC
    uint16_t secure:1;
    uint16_t error:1;
    uint16_t request:1;
    uint16_t encrypted_key_data:1;
    uint16_t SMK_message:1;
    uint16_t reserved_B:2;
    // --------------
    
    // --- OCTET LSB ---
    uint16_t key_descriptor_version:3; // needed for knowing key MIC length
    uint16_t key_type:1; // The value 0 (Group/SMK) indicates the message is not part of a PTK derivation.
    // The value 1 (Pairwise) indicates the message is part of a PTK derivation.
    uint16_t reserved_A:2;
    uint16_t install:1;
    uint16_t key_Ack:1;
    //------------------
};

struct EAPOL_key_frame_t
{
    uint8_t protocol_version;
    uint8_t packet_type;
    uint16_t packet_body_length;
    uint8_t descriptor_type;
    
    // octets are LSB right to left
    // how it comes through: 00    08
    //                       MSB   LSB
    // so copy MSB first
    
    key_info_t key_info;
    
    uint16_t key_length; // defines the length in octets of the pairwise temporal key
    
    uint8_t key_replay_counter[8];

    uint8_t key_nonce[32]; // conveys the ANonce from the Authenticator and the SNonce from the Supplicant.
    uint8_t eapol_key_IV[16]; // contains the IV used with the KEK
    uint8_t key_RSC[8];
    uint8_t reserved[8];
    // --- not variable up until this point ---
    const u_char *key_MIC; // The length of this field depends on the negotiated AKM
    uint16_t key_data_length; // represents the length of the Key Data field in octets
    const u_char *key_data;
};

struct key_data_t
{
    uint8_t type;
    uint8_t length;
    uint8_t OUI[3];
    uint8_t data_type;
    const u_char *data;
};

void process_EAPOL_frame(const u_char *data_frame, uint16_t length)
{
    EAPOL_key_frame_t key_frame;
    
    
    // since the struct has a combination of different sizes
    // it is not packed, therefore you need to be careful
    // in making sure the memory is where you want it
    key_frame.protocol_version = data_frame[0];
    key_frame.packet_type = data_frame[1];
    key_frame.packet_body_length = (data_frame[2] << 8) | data_frame[3];
    key_frame.descriptor_type = data_frame[4];
    memcpy(&(key_frame.key_info), &(data_frame[5]), 2);
    key_frame.key_length = (data_frame[7] << 8) | data_frame[8];
    memcpy(key_frame.key_replay_counter, &(data_frame[9]), 8);
    memcpy(key_frame.key_nonce, &(data_frame[17]), 32);
    memcpy(key_frame.eapol_key_IV, &(data_frame[49]), 16);
    memcpy(key_frame.key_RSC, &(data_frame[65]), 8);
    memcpy(key_frame.reserved, &(data_frame[73]), 8);
    
    uint8_t key_descriptor_version = key_frame.key_info.key_descriptor_version;
    uint8_t key_MIC_octet_length = 0;
    
    if(key_descriptor_version == 1)
    {
        key_MIC_octet_length = 16;
    }
    else if(key_descriptor_version == 2)
    {
        key_MIC_octet_length = 16;
    }
    else if(key_descriptor_version == 3)
    {
        key_MIC_octet_length = 16;
    }
    
    const u_char *after_MIC_ptr;
    if(key_frame.key_info.key_MIC)
    { // has MIC
        key_frame.key_MIC = data_frame + 81;
        after_MIC_ptr = data_frame + 81 + key_MIC_octet_length;
    }
    else
    {
        key_frame.key_MIC = data_frame + 81;
        after_MIC_ptr = data_frame + 81 + key_MIC_octet_length;
    }
    
    memcpy(&(key_frame.key_data_length), after_MIC_ptr, 2);
    key_frame.key_data_length = (key_frame.key_data_length>>8) | (key_frame.key_data_length<<8); // correct endian to LSB
    
    key_frame.key_data = after_MIC_ptr + 2;
    
    
    key_data_t key_data;
    
    key_data.type = (key_frame.key_data)[0];
    key_data.length = (key_frame.key_data)[1];
    key_data.OUI[0] = (key_frame.key_data)[2];
    key_data.OUI[1] = (key_frame.key_data)[3];
    key_data.OUI[2] = (key_frame.key_data)[4];
    key_data.data_type = (key_frame.key_data)[5];
    key_data.data = key_frame.key_data + 6;
    

    uint8_t key_type = 0;
    
    if(key_data.OUI[0] == 0x00 && key_data.OUI[1] == 0x0F && key_data.OUI[2] == 0xAC)
    {
        if(key_data.data_type == 1 || key_data.data_type == 2)
        {
            key_type = ENCRYPT_TYPE_HMAC_SHA_1_128;
        }
        else if(key_data.data_type > 2 && key_data.data_type < 10)
        {
            key_type = ENCRYPT_TYPE_AES_128_CMAC;
        }
        else if(key_data.data_type == 11)
        {
            key_type = ENCRYPT_TYPE_HMAC_SHA_256;
        }
        else if(key_data.data_type == 12 || key_data.data_type == 13)
        {
            key_type = ENCRYPT_TYPE_HMAC_SHA_384;
        }
        else
        {
            key_type = ENCRYPT_TYPE_UNKNOWN;
        }
    }
    else
    {
        key_type = ENCRYPT_TYPE_UNKNOWN;
    }
    
}

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

void EAPOL_test()
{
//    char hex[2] = {0};
//    byte_to_hex_str(0x0f,hex);
//    printf("%c%c",hex[0],hex[1]);
//    printf("\n");
//    while(1);
    
    char pw[] = "password";
    char ssid[] = "IEEE";
    convert_WPA_to_PSK(pw, ssid, NULL);
    
    while(1);
    
    char key[] = "key";
    char msg[] = "The quick brown fox jumps over the lazy dog";
    //HMAC(key,msg);
    
    while(1);
    
    char test_hash[] = "The quick brown fox jumps over the lazy dog";
    // should get: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
    char test_hash2[] = "abc";
    // should get: a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
    char test_hash3[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    // should get: a49b2446 a02c645b f419f995 b6709125 3a04a259
    
    char output[40] = {0};
    char output_bytes[20] = {0};
    SHA_1_hash(test_hash, output, output_bytes, strlen(test_hash));
    while(1);
}



