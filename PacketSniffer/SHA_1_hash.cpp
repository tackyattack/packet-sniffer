//
//  SHA_1_hash.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 11/10/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

// SHA_1_hash test vectors can be found at: https://www.di-mgt.com.au/sha_testvectors.html

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

void byte_to_hex_str(uint8_t input, char *output)
{
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

uint32_t leftrotate(uint32_t input, uint32_t cnt)
{
    return (input << cnt) | (input >> (32 - cnt));
}

// output should be able to contain the 40 character hex string (160 bits, 4 bits per hex char)
void SHA_1_hash(const char *message, char *output_char, char *output_byte , uint32_t byte_length)
{
    
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    
    //uint32_t ml = (uint32_t)strlen(message)*8;
    uint32_t ml = byte_length*8;
    
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
    
    // <-----------------(512 bits)*N---------------->
    // [msg] ['1'] [padding] [00 00 00 00 00 00 00 01]
    // [msg] ['1'] [padding] [00 00 00 00 00 00 00 02]
    // padding is 0 to 512 bits so that the whole thing
    // becomes a multiple of 512
    
    message_container[message_block_cnt_byte_cnt-1 - 3] |= (ml & 0xff000000) >> 24;
    message_container[message_block_cnt_byte_cnt-1 - 2] |= (ml & 0x00ff0000) >> 16;
    message_container[message_block_cnt_byte_cnt-1 - 1] |= (ml & 0x0000ff00) >> 8;
    message_container[message_block_cnt_byte_cnt-1 - 0] |= (ml & 0x000000ff); // OR with the one closest to the padding incase
    // there's none, in which case it might need to cut
    // into byte with the appended '1' bit
    // but it would have to be a message length of
    // 2^(64-1) / 8 bytes long, which is crazy
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
    
    uint32_t current_word = 0;
    uint8_t word_cnt = 0;
    
    uint8_t hex_holder[20] = {0};
    
    for(uint16_t i = 0; i < 20;)
    {
        if(word_cnt == 0)
        {
            current_word = h0;
        }
        else if(word_cnt == 1)
        {
            current_word = h1;
        }
        else if(word_cnt == 2)
        {
            current_word = h2;
        }
        else if(word_cnt == 3)
        {
            current_word = h3;
        }
        else if(word_cnt == 4)
        {
            current_word = h4;
        }
        
        hex_holder[i++] = (current_word & 0xff000000) >> 24;
        hex_holder[i++] = (current_word & 0x00ff0000) >> 16;
        hex_holder[i++] = (current_word & 0x0000ff00) >> 8;
        hex_holder[i++] = (current_word & 0x000000ff);
        word_cnt++;
    }
    
    char hex_char[2];
    
    for(uint16_t i = 0; i < 40;)
    {
        byte_to_hex_str(hex_holder[i/2], hex_char);
        output_char[i++] = hex_char[0];
        output_char[i++] = hex_char[1];
    }
    
    memcpy(output_byte, hex_holder, 20);
    
    //printf("%x%x%x%x%x\n",h0,h1,h2,h3,h4);
    //printf("done\n");
    
    
    free(message_container);
}
