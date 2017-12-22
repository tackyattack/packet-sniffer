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

void byte_to_hex_str_x(uint8_t input, char *output)
{
    output[0] = '0';
    output[1] = '0';
    
    uint32_t decimalNumber,quotient;
    uint32_t i=0,temp;
    decimalNumber = input;
    quotient = decimalNumber;
    while(quotient!=0)
    {
        temp = quotient % 16;
        //To convert integer into character
        if( temp < 10)
        {
            temp = temp + 48; // 0-9
        }
        else
        {
            temp = temp + 87; // a-f
        }
        output[i++]= temp;
        quotient = quotient / 16;
    }
    
    // switch order
    temp = output[0];
    output[0] = output[1];
    output[1] = temp;
    
    if(output[0] == 0) output[0] = '0';
    if(output[1] == 0) output[1] = '0';
}

void HMAC(const char *input_key, uint16_t IK_len, const char *input_message, uint16_t IM_len, char *output)
{
    // if it's not working, could be dynamic memory
    
    //uint16_t IM_len = strlen(input_message);
    //uint16_t IK_len = strlen(input_key);
    
    const uint16_t blocksize = 64;
    
    uint32_t key_size;
    if(IK_len+1 < 64)
    { // make sure it's big enough to pad with zeros
        key_size = 64;
    }
    else
    {
        key_size = uint32_t(IK_len + 1);
    }
    char *key = (char *)malloc(sizeof(char)*key_size);
    for(uint32_t i = 0; i < key_size; i ++)
    {
        key[i] = input_key[i]; // copy
    }
    
    char buf[40]; // capture the hex
    
    if(IK_len > blocksize)
    { // is the original key greater than the block size?
        SHA_1_hash(input_key, buf, key,(uint32_t)IK_len); // hash the key to make it shorter
    }
    
    if(IK_len < blocksize)
    { // pad with zeros if the key is now less than the block size
        for(uint16_t i = IK_len; i < blocksize; i++)
        { // k e y e x a m p l e \0
            key[i] = 0x00;
        }
    }
    
    char o_key_pad[blocksize] = {0};
    char i_key_pad[blocksize] = {0};
    
    char o_xor[20 + 64] = {0};
    char *i_xor = (char *)malloc(sizeof(char)*(64+IM_len));
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
    for(uint16_t i = 0; i < IM_len; i++)
    {
        i_xor[i+64] = input_message[i];
    }
    char i_xor_out[20] = {0};
    SHA_1_hash(i_xor, buf, i_xor_out, (uint32_t)(64 + IM_len));
    
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
    
}

void HMAC_str(const char *input_key, const char *input_message, char *output)
{
    char output_bytes[20] = {0};
    HMAC(input_key, strlen(input_key), input_message, strlen(input_message), output_bytes);
    char hex_out[2];
    for(uint16_t i = 0; i < 40;)
    {
        byte_to_hex_str_x(output_bytes[i/2], hex_out);
        output[i] = hex_out[0];
        i++;
        output[i] = hex_out[1];
        i++;
        
    }
    output[40] = '\0';
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
