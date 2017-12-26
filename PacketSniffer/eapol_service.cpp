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

#define PROTOCOL_VERSION_SIZE       1
#define PACKET_TYPE_SIZE            1
#define PACKET_BODY_LENGTH_SIZE     2
#define DESCRIPTOR_TYPE_SIZE        1
#define KEY_INFO_SIZE               2
#define KEY_LENGTH_SIZE             2
#define KEY_REPLAY_COUNTER_SIZE     8
#define KEY_NONCE_SIZE              32
#define EAPOL_KEY_IV_SIZE           16
#define KEY_RSC_SIZE                8
#define RESERVED_SIZE               8

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
    
    uint8_t key_replay_counter[KEY_REPLAY_COUNTER_SIZE];

    uint8_t key_nonce[KEY_NONCE_SIZE]; // conveys the ANonce from the Authenticator and the SNonce from the Supplicant.
    uint8_t eapol_key_IV[EAPOL_KEY_IV_SIZE]; // contains the IV used with the KEK
    uint8_t key_RSC[KEY_RSC_SIZE];
    uint8_t reserved[RESERVED_SIZE];
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


void EAPOL_test()
{
    

}



