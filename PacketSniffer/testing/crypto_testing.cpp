//
//  crypto_testing.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 11/10/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "SHA_1_hash.h"
#include "btest.h"

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

void init_crypto_testing()
{
    ADD_TEST(crypto, SHA_1_hash);
}
