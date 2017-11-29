//
//  HMAC.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 11/28/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include "HMAC.h"
#include "SHA_1_hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// HMAC: https://tools.ietf.org/html/rfc2104

void HMAC(const char *input_key, const char *input_message, char *output)
{
    // if it's not working, could be dynamic memory
    
    const uint16_t blocksize = 64;
    
    uint32_t key_size;
    if(strlen(input_key)+1 < 64)
    { // make sure it's big enough to pad with zeros
        key_size = 64;
    }
    else
    {
        key_size = uint32_t(strlen(input_key) + 1);
    }
    char *key = (char *)malloc(sizeof(char)*key_size);
    for(uint32_t i = 0; i < key_size; i ++)
    {
        key[i] = input_key[i]; // copy
    }
    
    char buf[40]; // capture the hex
    
    if(strlen(key) > blocksize)
    { // is the original key greater than the block size?
        SHA_1_hash(input_key, buf, key,(uint32_t)strlen(input_key)); // hash the key to make it shorter
    }
    
    if(strlen(key) < blocksize)
    { // pad with zeros if the key is now less than the block size
        for(uint16_t i = strlen(key); i < blocksize; i++)
        { // k e y e x a m p l e \0
            key[i] = 0x00;
        }
    }
    
    char o_key_pad[blocksize] = {0};
    char i_key_pad[blocksize] = {0};
    
    char o_xor[20 + 64] = {0};
    char *i_xor = (char *)malloc(sizeof(char)*(64+strlen(input_message)));
    //char o_xor[1000] = {0};
    //char i_xor[1000] = {0};
    
    for(uint16_t i = 0; i < blocksize; i++)
    {
        o_key_pad[i] = 0x5c;
        i_key_pad[i] = 0x36;
    }
    
    for(uint16_t i = 0; i < 64; i++)
    {
        i_xor[i] = key[i] ^ i_key_pad[i];
    }
    for(uint16_t i = 0; i < strlen(input_message); i++)
    {
        i_xor[i+64] = input_message[i];
    }
    char i_xor_out[20] = {0};
    SHA_1_hash(i_xor, buf, i_xor_out, (uint32_t)(64 + strlen(input_message)));
    
    for(uint16_t i = 0; i < 64; i++)
    {
        o_xor[i] = key[i] ^ o_key_pad[i];
    }
    
    for(uint16_t i = 0; i < 20; i++)
    { // append SHA1 output
        o_xor[i+64] = i_xor_out[i];
    }
    
    char o_xor_out[20] = {0};
    SHA_1_hash(o_xor, buf, o_xor_out, 64 + 20);
    
    free(key);
    free(i_xor);
    
    for(uint16_t i = 0; i < 20; i++)
    {
        output[i] = o_xor_out[i];
    }
    
    //while(1);
    
    
    //    uint16_t inner_hash_size = strlen(i_key_pad) + strlen(input_message);
    //    char *inner_hash = (char *)malloc(sizeof(char)*inner_hash_size);
    //    strcpy(inner_hash, i_key_pad);
    //    strcat(inner_hash, input_message);
    //    char inner_hash_output[40] = {0};
    //    SHA_1_hash(inner_hash, buf, inner_hash_output);
    //
    //    uint16_t outer_hash_size = strlen(o_key_pad) + strlen(inner_hash);
    //    char *outer_hash = (char *)malloc(sizeof(char)*outer_hash_size);
    //    strcpy(outer_hash, o_key_pad);
    //    strcat(outer_hash, inner_hash);
    //    char outer_hash_output[40] = {0};
    //    SHA_1_hash(outer_hash, buf, outer_hash_output);
    //
    //
    //    char output[40] = {0};
    //
    //    strcpy(output, outer_hash_output);
    //
    //    free(inner_hash);
    //    free(outer_hash);
}

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



// HMAC:
// https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
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
