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

uint32_t leftrotate(uint32_t input, uint32_t cnt)
{
    return (input << cnt) | (input >> (32 -cnt));
}

void SHA_1_hash(char *message)
{
    uint8_t output[20] = {0}; // 160 bit output
    
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    
    uint32_t ml = (uint32_t)strlen(message)*8;
    
    uint32_t message_bit_len = ml + 1 + 64; // adding the '1' bit and 64 bit message length variable
    uint32_t message_block_cnt = ceil(message_bit_len / 512.0);
    //uint32_t padding_bit_cnt = message_block_cnt*512 - message_bit_len - 64; // find the gap to fill
    uint32_t message_block_cnt_byte_cnt = message_block_cnt*512/8;
    uint8_t *message_container = (uint8_t *)malloc(sizeof(uint8_t)*message_block_cnt_byte_cnt);
    
    memcpy(message_container, message, ml/8);
    message_container[ml/8] = 0b10000000; // add in a '1' bit closest to previous byte
    
    for(uint32_t i = ml/8 + 1; i < message_block_cnt_byte_cnt; i++)
    {
        message_container[i] = 0x00; // pad rest of it
    }
    
    // ml is LSB so it counts like this:
    // [msg] [padding] 00 00 00 00 00 00 00 01
    // [msg] [padding] 00 00 00 00 00 00 00 02
    
    message_container[message_block_cnt_byte_cnt-1 - 3] |= (ml & 0xff000000) >> 24;
    message_container[message_block_cnt_byte_cnt-1 - 2] |= (ml & 0x00ff0000) >> 16;
    message_container[message_block_cnt_byte_cnt-1 - 1] |= (ml & 0x0000ff00) >> 8;
    message_container[message_block_cnt_byte_cnt-1 - 0] |= (ml & 0x000000ff); // OR with the one closest to the padding incase
                                                                              // there's none, in which case it might need to cut
                                                                              // into byte with the appended '1' bit
    for(uint32_t m = 0; m < message_block_cnt_byte_cnt;)
    { // deal with data in 512 bit chunks
        uint32_t w[80];
        uint8_t chunk[64];
        
        // get message chunk
        for(uint32_t n = 0; n < 64; n++)
        {
            chunk[n] = message_container[m];
            m++;
        }
        
        // copy to word chunk in 32 bit MSB
        uint32_t j = 0;
        for(uint32_t n = 0; n < 16; n++)
        {
            w[n] = chunk[j] << 24 | chunk[j+1] << 16 | chunk[j+2] << 8 | chunk[j+3];
            j = j + 4;
        }
        
        //extend to 80 words
        for(uint32_t n = 16; n < 80; n++)
        {
            w[n] = (w[n-3] ^ w[n-8] ^ w[n-14] ^ w[n-16]);
            w[n] = leftrotate(w[n],1);
        }
        
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        
        uint32_t temp;
        
        for(uint32_t n = 0; n < 20; n++)
        {
            temp = leftrotate(a, 5) + ((b & c) | ((~b) & d)) + e + w[n] + 0x5A827999;
            e = d;
            d = c;
            c = leftrotate(b, 30);
            b = a;
            a = temp;
        }
        
        for(uint32_t n = 20; n < 40; n++)
        {
            temp = leftrotate(a,5) + (b ^ c ^ d) + e + w[n] + 0x6ED9EBA1;
            e = d;
            d = c;
            c = leftrotate(b,30);
            b = a;
            a = temp;
        }
        
        for(uint32_t n = 40; n < 60; n++)
        {
            temp = leftrotate(a,5) + ((b & c) | (b & d) | (c & d)) + e + w[n] + 0x8F1BBCDC;
            e = d;
            d = c;
            c = leftrotate(b,30);
            b = a;
            a = temp;
        }
        
        for(uint32_t n = 60; n < 80; n++)
        {
            temp = leftrotate(a,5) + (b ^ c ^ d) + e + w[n] + 0xCA62C1D6;
            e = d;
            d = c;
            c = leftrotate(b,30);
            b = a;
            a = temp;
        }
        
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
        
        
    }
    
    printf("%x%x%x%x%x\n",h0,h1,h2,h3,h4);
    printf("done\n");
    
    
    
}

// SHA-1 hash:
// https://en.wikipedia.org/wiki/SHA-1
// more info: https://www.ipa.go.jp/security/rfc/RFC3174EN.html

//  Note 1: All variables are unsigned 32-bit quantities and wrap modulo 2^32 when calculating, except for
//  ml, the message length, which is a 64-bit quantity, and
//  hh, the message digest, which is a 160-bit quantity.
//  Note 2: All constants in this pseudo code are in big endian.
//  Within each word, the most significant byte is stored in the leftmost byte position
//
//  Initialize variables:
//
//  h0 = 0x67452301
//  h1 = 0xEFCDAB89
//  h2 = 0x98BADCFE
//  h3 = 0x10325476
//  h4 = 0xC3D2E1F0
//
//  ml = message length in bits (always a multiple of the number of bits in a character).
//-
//  Pre-processing:
//  1. append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
//  2. append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
//  is congruent to −64 ≡ 448 (mod 512)
//  -> means pad the end of the message with   0 ≤ k < 512  '0' bits so that it reaches it can be broken into 512 chunks including the
//     64 bit message size at the very end (next step below)
//  3. append ml, the original message length, as a 64-bit big-endian integer.
//     Thus, the total length is a multiple of 512 bits.
//
//  Process the message in successive 512-bit chunks:
//  break message into 512-bit chunks
//  for each chunk
//  break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
//
//  Extend the sixteen 32-bit words into eighty 32-bit words:
//  for i from 16 to 79
//  w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
//
//  Initialize hash value for this chunk:
//  a = h0
//  b = h1
//  c = h2
//  d = h3
//  e = h4
//
//  Main loop:[3][53]
//  for i from 0 to 79
//  if 0 ≤ i ≤ 19 then
//  f = (b and c) or ((not b) and d)
//  k = 0x5A827999
//  else if 20 ≤ i ≤ 39
//  f = b xor c xor d
//  k = 0x6ED9EBA1
//  else if 40 ≤ i ≤ 59
//  f = (b and c) or (b and d) or (c and d)
//  k = 0x8F1BBCDC
//  else if 60 ≤ i ≤ 79
//  f = b xor c xor d
//  k = 0xCA62C1D6
//
//  temp = (a leftrotate 5) + f + e + k + w[i]
//  e = d
//  d = c
//  c = b leftrotate 30
//  b = a
//  a = temp
//
//  Add this chunk's hash to result so far:
//  h0 = h0 + a
//  h1 = h1 + b
//  h2 = h2 + c
//  h3 = h3 + d
//  h4 = h4 + e
//
//  Produce the final hash value (big-endian) as a 160-bit number:
//  hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4

// HMAC:

//function hmac (key, message) {
//    if (length(key) > blocksize) {
//        key = hash(key) // keys longer than blocksize are shortened
//    }
//    if (length(key) < blocksize) {
//        // keys shorter than blocksize are zero-padded (where ∥ is concatenation)
//        key = key ∥ [0x00 * (blocksize - length(key))] // Where * is repetition.
//    }
//    
//    o_key_pad = [0x5c * blocksize] ⊕ key // Where blocksize is that of the underlying hash function
//    i_key_pad = [0x36 * blocksize] ⊕ key // Where ⊕ is exclusive or (XOR)
//    
//    return hash(o_key_pad ∥ hash(i_key_pad ∥ message)) // Where ∥ is concatenation
//}


//  hLen:    length in octets of pseudorandom function output, a positive integer

void PBKDF2(char *P, char *S, uint16_t c, uint16_t dkLen)
{
    uint16_t hlen = 0;
    if( dkLen > ( 0xffffffff - 1)*hlen )
    {
        return;
    }
}

void convert_WPA_to_PSK(char *password, char *SSID, uint8_t *output)
{
    PBKDF2(password, SSID, 4096, 256/8);
}

void EAPOL_test()
{
    char test_hash[] = "The quick brown fox jumps over the lazy dog";
    // should get: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
    char test_hash2[] = "abc";
    // should get: a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
    char test_hash3[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    // should get: a49b2446 a02c645b f419f995 b6709125 3a04a259
    SHA_1_hash(test_hash);
    while(1);
    
    char pw[] = "password";
    char ssid[] = "IEEE";
    convert_WPA_to_PSK(pw, ssid, NULL);
}



