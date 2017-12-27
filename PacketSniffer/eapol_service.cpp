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
// x||y means the concat of x and y, except in code, where it sometimes is the short-circuiting Boolean
// L (S, F, N) is bits F to F+N–1 of the bit string S starting from the left

#include "eapol_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "SHA_1_hash.h"
#include "HMAC.h"

//---- KEY ARRAY ----
struct temporal_key_t
{
    uint8_t SA[6];
    uint8_t DA[6];
    uint8_t TK[32];
};
temporal_key_t key_array[KEY_STORAGE_SIZE];
//-------------------

void process_handshake(EAPOL_key_frame_t key_frame, MAC_header_frame_t MAC_header);

void process_EAPOL_frame(const u_char *data_frame, uint16_t length, MAC_header_frame_t MAC_header)
{
    EAPOL_key_frame_t key_frame;
    
    
    // since the struct has a combination of different sizes
    // it is not packed, therefore you need to be careful
    // in making sure the memory is where you want it
    uint16_t data_pos = 0;
    key_frame.protocol_version = data_frame[data_pos];
    data_pos += PROTOCOL_VERSION_SIZE;
    key_frame.packet_type = data_frame[data_pos];
    data_pos += PACKET_TYPE_SIZE;
    key_frame.packet_body_length = (data_frame[data_pos] << 8) | data_frame[data_pos+1];
    data_pos += PACKET_BODY_LENGTH_SIZE;
    key_frame.descriptor_type = data_frame[data_pos];
    data_pos += DESCRIPTOR_TYPE_SIZE;
    memcpy(&(key_frame.key_info), &(data_frame[data_pos]), KEY_INFO_SIZE);
    data_pos += KEY_INFO_SIZE;
    key_frame.key_length = (data_frame[data_pos] << 8) | data_frame[data_pos+1];
    data_pos += KEY_LENGTH_SIZE;
    memcpy(key_frame.key_replay_counter, &(data_frame[data_pos]), KEY_REPLAY_COUNTER_SIZE);
    data_pos += KEY_REPLAY_COUNTER_SIZE;
    memcpy(key_frame.key_nonce, &(data_frame[data_pos]), KEY_NONCE_SIZE);
    data_pos += KEY_NONCE_SIZE;
    memcpy(key_frame.eapol_key_IV, &(data_frame[data_pos]), EAPOL_KEY_IV_SIZE);
    data_pos += EAPOL_KEY_IV_SIZE;
    memcpy(key_frame.key_RSC, &(data_frame[data_pos]), KEY_RSC_SIZE);
    data_pos += KEY_RSC_SIZE;
    memcpy(key_frame.reserved, &(data_frame[data_pos]), RESERVED_SIZE);
    data_pos += RESERVED_SIZE;
    
    uint8_t key_descriptor_version = key_frame.key_info.key_descriptor_version;
    uint8_t key_MIC_octet_length = 0;
    
    switch (key_descriptor_version)
    {
        case 1:
            key_MIC_octet_length = 16;
            break;
        case 2:
            key_MIC_octet_length = 16;
            break;
        case 3:
            key_MIC_octet_length = 16;
            break;
            
        default:
            break;
    }
    
    const u_char *after_MIC_ptr;
    if(key_frame.key_info.key_MIC)
    { // has MIC
        key_frame.key_MIC = data_frame + data_pos;
        after_MIC_ptr = data_frame + data_pos + key_MIC_octet_length;
    }
    else
    {
        key_frame.key_MIC = data_frame + data_pos;
        after_MIC_ptr = data_frame + data_pos + key_MIC_octet_length;
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
            process_handshake(key_frame, MAC_header);
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

void process_handshake(EAPOL_key_frame_t key_frame, MAC_header_frame_t MAC_header)
{
    // Each key pair should just use the SA/DA. Either SA or DA should give
    // back the temporal key since traffic either way will use the same one
    
    // To get the DA/SA, just walk through each type in the MAC_address type
    // to find which one is the DA and SA
    
    if(!key_frame.key_info.secure)
    {   // secure implies keys are installed
        // key not installed means it is message 1 or 2
        
        if(key_frame.key_info.key_MIC)
        {
            // Message 2 has a MIC, message 1 does not
        }
        else
        {
            // No MIC, therefore message 1
        }
        
    }
    
    
}

void add_key_to_table(temporal_key_t TK)
{
    static uint16_t key_array_index = 0;
    
    key_array[key_array_index] = TK;
    key_array_index++;
    if(key_array_index >= KEY_STORAGE_SIZE)
    {
        key_array_index = 0; // loop back around (first in last out)
    }
}




