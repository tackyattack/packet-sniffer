//
//  security.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 8/5/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include "security.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

#include "aes.h"

#define CCMP_TYPE_128 1
#define CCMP_TYPE_256 2

struct CCMP_key_id_t
{
    uint16_t rsvd:5;
    uint16_t ext_IV:1;
    uint16_t key_ID:2;
};

struct CCMP_header_t
{
    uint8_t PN[6];
    CCMP_key_id_t key_id;
};


// PN: packet number or pseudonoise (code sequence)
// TK: temporal key (16 octets)
// AAD: additional authentication data

// Test data:
// AES key would be the TK in 802.11

//AES Key =  C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF
//Nonce =    00 00 00 03  02 01 00 A0  A1 A2 A3 A4  A5
//Total packet length = 31. [Input with 8 cleartext header octets]
//00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F
//10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E
//CBC IV in: 59 00 00 00  03 02 01 00  A0 A1 A2 A3  A4 A5 00 17
//CBC IV out:EB 9D 55 47  73 09 55 AB  23 1E 0A 2D  FE 4B 90 D6
//After xor: EB 95 55 46  71 0A 51 AE  25 19 0A 2D  FE 4B 90 D6   [hdr]
//After AES: CD B6 41 1E  3C DC 9B 4F  5D 92 58 B6  9E E7 F0 91
//After xor: C5 BF 4B 15  30 D1 95 40  4D 83 4A A5  8A F2 E6 86   [msg]
//After AES: 9C 38 40 5E  A0 3C 1B C9  04 B5 8B 40  C7 6C A2 EB
//After xor: 84 21 5A 45  BC 21 05 C9  04 B5 8B 40  C7 6C A2 EB   [msg]
//After AES: 2D C6 97 E4  11 CA 83 A8  60 C2 C4 06  CC AA 54 2F
//CBC-MAC  : 2D C6 97 E4  11 CA 83 A8
//*************************************************************
//CTR Start: 01 00 00 00  03 02 01 00  A0 A1 A2 A3  A4 A5 00 01 <- here is what the stream key looks like
//CTR[0001]: 50 85 9D 91  6D CB 6D DD  E0 77 C2 D1  D4 EC 9F 97 <- stream key 01 encrypted
//CTR[0002]: 75 46 71 7A  C6 DE 9A FF  64 0C 9C 06  DE 6D 0D 8F <- stream key 02 encrypted
//CTR[MAC ]: 3A 2E 46 C8  EC 33 A5 48 <- MIC
//Total packet length = 39. [Authenticated and Encrypted Output]
//00 01 02 03  04 05 06 07  58 8C 97 9A  61 C6 63 D2 <- first two octets are not encrypted (stream key 00 not used)
//F0 66 D0 C2  C0 F9 89 80  6D 5F 6B 61  DA C3 84 17    XOR packet msg (after first two octets) with stream key octets as a "stream"
//E8 D1 2C FD  F9 26 E0                                 starting at stream key 01 first octet


// CCMP 256 isn't really used yet because most clients only support 128.
// EAPOL will tell you what key type it is.
// The 802.1X layer should have a functions that can be called from here
// to get key type (CCMP-128, CCMP-256, etc), get the PTK, etc for
// a set of MAC addresses (i.e. from iPhone to ASUS router)

// Encrypt and decrypt are very similar. The only difference is the block cipher function.

// CCMP-128:
// M = 8 (MIC is 8 octets)
// L = 2 (length field is 2 octets)

// CCMP-256:
// M = 16
// L = 2

// Nonce size: 15-L octets

//***************************************************************
//Additional authenticated data a, consisting of a string of l(a)
//octets where 0 <= l(a) < 2^64.  This additional data is
//authenticated but not encrypted, and is not included in the
//output of this mode.  It can be used to authenticate plaintext
//packet headers, or contextual information that affects the
//interpretation of the message.  Users who do not wish to
//authenticate additional data can provide a string of length zero.

// My summary of CCM:
// CCM has both encrypted message and authenticated data (802.11 uses most of MAC header)
// The first thing CCM does is combine the auth data with the message then run through
// an algorithm [rfc3610] to create a T value (authentication field T). Basically, it does some XOR'ing
// of all those auth + mssg blocks to get a value of length M (CCMP-128 is 8 octets).

// Next, CCM encrypts the message by creating key stream blocks and XOR'ing with the message. Then at the
// very end it appends the U value (authentication value U), which is created by XOR'ing T with the first
// M (CCMP-128 is 8 octets) octets of the first key stream. This is the MIC.

// In our application, we don't really care about the MIC since we're just decoding the message. If the integrity
// has been compromised, then the router will know it and deal with it. For us, we can just set the message length
// from start up to J. (J = end of data - MIC length).

//***************************************************************

void CCMP_crypt_key_stream(uint8_t type, uint8_t *TK, uint8_t *nonce, uint8_t L, uint8_t M, uint16_t length)
{
    
    //********** construct key stream blocks **********//
    
    // key stream block length: 16 octets (128bit for CCMP-128)
    
    //    Octet Number   Contents
    //    ------------   ---------
    //    0              Flags
    //    1 ... 15-L     Nonce N
    //    16-L ... 15    Counter i
    
    const uint8_t key = *TK;
    const uint8_t counter_i_octet_cnt = 15 - (16 - L)  +1;
    const uint8_t nonce_octet_cnt     = (15-L) - 1     +1;
    
    uint8_t flags = 0;
    uint8_t L_prime = L - 1;
    flags = L_prime; // set bits 0 - 2 (because L' is 3 bits max)
    
    // IMPORTANT: Use an AES BLOCK CIPHER, not CBC since CBC already does XOR'ing and block cipher.
    //            That way you don't need the IV for CBC. The AES ECB is the most basic form, which
    //            is what we will use since it's a clean slate to create our own mode. It is very
    //            similar to CTR mode.
    
    // Only the stream key is ever put through the AES. And, it's always AES encryption because
    // it's the same process on decryption.
    
    // message is split into 16 octet blocks
    
    // the first key stream (0) is not (so the first two octets are not encrypted)
    
    uint8_t key_stream_block_cnt = (length / 16) + 1; // how many stream blocks to cover all the length octets?
    uint8_t key_stream_block[16] = {0};
    uint8_t *key_stream_blocks = (uint8_t *)malloc(sizeof(uint8_t)*key_stream_block_cnt);
    
    for(uint16_t i = 0; i < key_stream_block_cnt; i++)
    {
        key_stream_block[0] = flags; // 0
        memcpy(&key_stream_block[1], nonce, nonce_octet_cnt); // 1 - 13
        // MSB!
        key_stream_block[15] = i & 0xff; // 15
        key_stream_block[14] = i >> 8;   // 14
        
        memcpy(key_stream_blocks + 16*i, &key_stream_block, 16);
    }
    //*************************************************//
    
    
    free(key_stream_blocks);

}

void decrypt_CCMP_MPDU(const u_char *buffer, uint8_t *A2, uint8_t *PN, uint16_t length)
{ // buffer starts with CCMP header
    
    CCMP_header_t CCMP_header;
    
    CCMP_header.PN[0] = (uint8_t)buffer[0];
    CCMP_header.PN[1] = (uint8_t)buffer[1];
    CCMP_header.PN[2] = (uint8_t)buffer[4];
    CCMP_header.PN[3] = (uint8_t)buffer[5];
    CCMP_header.PN[4] = (uint8_t)buffer[6];
    CCMP_header.PN[5] = (uint8_t)buffer[7];
    
    memcpy(&(CCMP_header.key_id), &buffer[3], 1);
    
}

void testSecurity()
{
    
//    uint8_t key_stream_block[16] = {0};
//    uint16_t i = 259;
//    key_stream_block[15] = i & 0xff;
//    key_stream_block[14] = i >> 8;
//    while(1);

    uint8_t input[]      = {0x9C,0x38,0x40,0x5E,0xA0,0x3C,0x1B,0xC9,0x04,0xB5,0x8B,0x40,0xC7,0x6C,0xA2,0xEB};
    uint8_t key[]        = {0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF};
    uint8_t msg[]        = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    uint8_t key_stream[] = {0x01,0x00,0x00,0x00,0x04,0x03,0x02,0x01,0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0x00,0x01};
    uint8_t output[16]   = {0};
    // input key output
    AES_ECB_encrypt(key_stream, key, output, 16);
    // the first key stream (0) is not (so the first two octets are not encrypted)
    
    //AES_ECB_encrypt(output, key, key_stream, 16);
    //
    uint8_t t = 0x72 ^ 0x7A;
    
    while(1);
}







