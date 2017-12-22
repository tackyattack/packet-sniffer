//
//  crypto_testing.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 11/10/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include "btest.h"
#include <stdio.h>
#include <string.h>
#include "SHA_1_hash.h"
#include "HMAC.h"
#include "WPA2_keying.h"

void clear_str(char *output, uint16_t sz)
{
    for(uint32_t i = 0; i < sz; i++)
    {
        output[i] = 0;
    }
}

TEST(crypto, SHA_1_hash)
{
    char output[40] = {0};
    char output_bytes[20] = {0};
    
    const char test_hash1[] = "The quick brown fox jumps over the lazy dog";
    // should get: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
    const char test_vec_1[] = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";
    
    const char test_hash2[] = "abc";
    // should get: a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
    const char test_vec_2[] = "a9993e364706816aba3e25717850c26c9cd0d89d";
    
    const char test_hash3[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    // should get: a49b2446 a02c645b f419f995 b6709125 3a04a259
    const char test_vec_3[] = "a49b2446a02c645bf419f995b67091253a04a259";
    
    const char test_hash4[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    // should get: 84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1
    const char test_vec_4[] = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
    
    SHA_1_hash(test_hash1, output, output_bytes, (uint32_t)strlen(test_hash1));
    EXPECT_EQ_STR(output, test_vec_1, strlen(test_vec_1));
    EXPECT_EQ_INT((uint16_t)strlen(output), (uint16_t)strlen(test_vec_1));
    clear_str(output, 40);
    
    SHA_1_hash(test_hash2, output, output_bytes, (uint32_t)strlen(test_hash2));
    EXPECT_EQ_STR(output, test_vec_2, strlen(test_hash2));
    EXPECT_EQ_INT((uint16_t)strlen(output), (uint16_t)strlen(test_vec_2));
    clear_str(output, 40);
    
    SHA_1_hash(test_hash3, output, output_bytes, (uint32_t)strlen(test_hash3));
    EXPECT_EQ_STR(output, test_vec_3, strlen(test_vec_3));
    EXPECT_EQ_INT((uint16_t)strlen(output), (uint16_t)strlen(test_vec_3));
    clear_str(output, 40);
    
    SHA_1_hash(test_hash4, output, output_bytes, (uint32_t)strlen(test_hash4));
    EXPECT_EQ_STR(output, test_vec_4, strlen(test_vec_4));
    EXPECT_EQ_INT((uint16_t)strlen(output), (uint16_t)strlen(test_vec_4));
    clear_str(output, 40);
    
    
}

TEST(crypto, HMAC)
{
    const char test_vec_1_key[]     = "key";
    const char test_vec_1_msg[]     = "The quick brown fox jumps over the lazy dog";
    char test_vec_1_output[20] = {0};
    test_vec_1_output[0] = 0xde;
    test_vec_1_output[1] = 0x7c;
    test_vec_1_output[2] = 0x9b;
    test_vec_1_output[3] = 0x85;
    test_vec_1_output[4] = 0xb8;
    test_vec_1_output[5] = 0xb7;
    test_vec_1_output[6] = 0x8a;
    test_vec_1_output[7] = 0xa6;
    test_vec_1_output[8] = 0xbc;
    test_vec_1_output[9] = 0x8a;
    test_vec_1_output[10] = 0x7a;
    test_vec_1_output[11] = 0x36;
    test_vec_1_output[12] = 0xf7;
    test_vec_1_output[13] = 0x0a;
    test_vec_1_output[14] = 0x90;
    test_vec_1_output[15] = 0x70;
    test_vec_1_output[16] = 0x1c;
    test_vec_1_output[17] = 0x9d;
    test_vec_1_output[18] = 0xb4;
    test_vec_1_output[19] = 0xd9;
    
    char output[40] = {0};
    HMAC(test_vec_1_key, strlen(test_vec_1_key), test_vec_1_msg, strlen(test_vec_1_msg), output);
    EXPECT_EQ_STR(output, test_vec_1_output, sizeof(test_vec_1_output));
}

TEST(crypto, HMAC_STR)
{
    const char test_vec_1_key[]     = "key";
    const char test_vec_1_msg[]     = "The quick brown fox jumps over the lazy dog";
    const char test_vec_1_output[]  = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9";
    
    char output[41] = {0};
    HMAC_str(test_vec_1_key, test_vec_1_msg, output);
    EXPECT_EQ_STR(output, test_vec_1_output, strlen(output));
}

TEST(crypto, WPA2_PSK)
{
    char pw[] = "password";
    char ssid[] = "IEEE";
    // "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
    uint8_t test_vec_hex[] = {0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb,
                              0x4b, 0x90, 0xb3, 0x8a, 0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13,
                              0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10, 0xa1, 0x2e};
    // DK (derived key) length is always 32 bytes for WPA2
    char output[32] = {0};
    convert_WPA_to_PSK(pw, ssid, output);
    for(uint8_t i = 0; i < 32; i++)
    {
        EXPECT_EQ_INT(test_vec_hex[i], (uint8_t)output[i]);
    }
    
}

void init_crypto_testing()
{
    ADD_TEST(crypto, SHA_1_hash);
    ADD_TEST(crypto, HMAC);
    ADD_TEST(crypto, HMAC_STR);
    ADD_TEST(crypto, WPA2_PSK);
}
