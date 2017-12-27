//
//  eapol_service.h
//  PacketSniffer
//
//  Created by HENRY BERGIN on 8/5/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#ifndef eapol_service_h
#define eapol_service_h

#include <sys/types.h>
#include "_types/_uint32_t.h"
#include "_types/_uint16_t.h"
#include "_types/_uint8_t.h"
#include "80211.h"

#define ENCRYPT_TYPE_HMAC_SHA_1_128 1
#define ENCRYPT_TYPE_AES_128_CMAC   2
#define ENCRYPT_TYPE_HMAC_SHA_256   3
#define ENCRYPT_TYPE_HMAC_SHA_384   4
#define ENCRYPT_TYPE_UNKNOWN        5

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

void process_EAPOL_frame(const u_char *data_frame, uint16_t length, MAC_header_frame_t MAC_header);

void EAPOL_test();

#endif /* eapol_service_h */
