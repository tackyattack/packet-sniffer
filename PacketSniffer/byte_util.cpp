//
//  byte_util.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 12/21/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include <stdio.h>
#include "byte_util.h"

void byte_to_hex_str(uint8_t input, char *output)
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
