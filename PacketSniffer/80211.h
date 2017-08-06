//
//  80211.h
//  PacketSniffer
//
//  Created by HENRY BERGIN on 8/3/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#ifndef _0211_h
#define _0211_h

#include <sys/types.h>
#include "_types/_uint16_t.h"
#include "_types/_uint8_t.h"

struct MAC_header_frame_control_t
{ // 2 bytes
    uint16_t fc_protocol_version:2;     // protocol version
    uint16_t fc_typeb1:1;               // type
    uint16_t fc_typeb2:1;               // type
    uint16_t fc_subtype:4;              // subtype
    uint16_t fc_toDS:1;                 // to DS flag
    uint16_t fc_fromDS:1;               // from DS flag
    uint16_t fc_moreFrag:1;             // more fragmentation
    uint16_t fc_retry:1;                // retry flag
    uint16_t fc_power_management:1;     // power management flag
    uint16_t fc_more_data:1;            // more data flag
    uint16_t fc_protected:1;            // protected flag to show packet is encrypted
    uint16_t fc_order:1;                // order flag / HTC+
};

struct MAC_header_duration_t
{ // 2 bytes
    uint8_t duration_ID_b1;
    uint8_t duration_ID_b2;
};

struct MAC_header_address_t
{ // 4 octets
    uint8_t addr1[6];
    uint8_t addr1_type;
    
    uint8_t addr2[6];
    uint8_t addr2_type;
    
    uint8_t addr3[6];
    uint8_t addr3_type;
    
    uint8_t addr4[6];
    uint8_t addr4_type;
};

struct MAC_header_sequence_control_t
{ // 2 bytes
    uint8_t sequence_b1;
    uint8_t sequence_b2;
};

struct MAC_header_qos_control_t
{ // 2 bytes
    uint16_t qos_TID:4;
    uint16_t qos_EOSP:1;
    uint16_t qos_ack_policy:2;
    uint16_t qos_A_MSDU_present:1;
    uint16_t qos_A_MSDU_type:1;
    uint16_t qos_more_PPDU:1;
    uint16_t qos_buffered_AC:4;
    uint16_t qos_reserved:1;
    uint16_t qos_AC_constraint:1;
};

struct MAC_header_ht_control_t
{ // 2 bytes
    uint8_t duration_ID_b1;
    uint8_t duration_ID_b2;
    uint8_t duration_ID_b3;
    uint8_t duration_ID_b4;
};

struct MAC_header_frame_t

{
    MAC_header_frame_control_t    frame_control;
    MAC_header_duration_t         duration_id;
    MAC_header_address_t          address;
    MAC_header_sequence_control_t sequence_control;
    MAC_header_qos_control_t      qos_control;
    MAC_header_ht_control_t       ht_control;
    
    bool qos_present;
    bool ht_present;
    
    uint8_t frame_type;
    const u_char *frame_body_start;
    const u_char *FCS;
};

void process_80211(const u_char *buffer, uint16_t length);

#endif /* _0211_h */
