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


TEST(crypto, SHA_1_hash)
{
    char test_hash[] = "The quick brown fox jumps over the lazy dog";
    // should get: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
    char test_hash2[] = "abc";
    // should get: a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
    char test_hash3[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    // should get: a49b2446 a02c645b f419f995 b6709125 3a04a259
    
    char output[40] = {0};
    char output_bytes[20] = {0};
    SHA_1_hash(test_hash, output, output_bytes, strlen(test_hash));
}

void init_crypto_testing()
{
    ADD_TEST(crypto, SHA_1_hash);
}
