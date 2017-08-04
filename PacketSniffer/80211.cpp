//
//  80211.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 8/3/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

// todo:
// 1. read MAC service defintion
// 2. read layer management
// 3. read MAC sublayer functional desc
// 4. See if MLME applies
// 5. once you have MPDU packets, pass them to security

#include <stdio.h>
#include <sys/types.h>  // useful system types
#include <iostream>


#define FRAME_CONTROL_SIZE 2
#define DURATION_SIZE      2
#define OCTET_ADDRESS_SIZE 6
#define SEQ_SIZE           2
#define QOS_SIZE           2
#define HT_SIZE            4

#define MAC_ADDR_TYPE_DESTINATION    1
#define MAC_ADDR_TYPE_SOURCE         2
#define MAC_ADDR_TYPE_BSSID          3
#define MAC_ADDR_TYPE_RECEIVER       4
#define MAC_ADDR_TYPE_TRANSMITTER    5
#define MAC_ADDR_TYPE_NONE           6

#define MAC_FRAME_TYPE_CONTROL       1
#define MAC_FRAME_TYPE_MANAGEMENT    2
#define MAC_FRAME_TYPE_DATA          3

char MAC_msg[100];


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
    uint8_t duration_ID_b1;
    uint8_t duration_ID_b2;
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
    
    uint8_t frame_type;
    const u_char *frame_body_start;
};


char *getSubtype(uint16_t subtype, uint8_t type)
{
    if( (subtype & 0b1111) == 0b0111 && type == MAC_FRAME_TYPE_MANAGEMENT )
    {
        strcpy(MAC_msg, "Reserved");
    }
    else if( (subtype & 0b1111) == 0b1000 && type == MAC_FRAME_TYPE_MANAGEMENT )
    {
        strcpy(MAC_msg, "Beacon");
    }
    else if( (subtype & 0b1111) == 0b1001 && type == MAC_FRAME_TYPE_MANAGEMENT )
    {
        strcpy(MAC_msg, "ATIM");
    }
    else if( (subtype & 0b1111) == 0b1010 && type == MAC_FRAME_TYPE_MANAGEMENT )
    {
        strcpy(MAC_msg, "Disassociation");
    }
    else if( (subtype & 0b1111) == 0b1011 && type == MAC_FRAME_TYPE_MANAGEMENT )
    {
        strcpy(MAC_msg, "Authentication");
    }
    else if( (subtype & 0b1111) == 0b1100 && type == MAC_FRAME_TYPE_MANAGEMENT )
    {
        strcpy(MAC_msg, "Deauthentication");
    }
    else if( (subtype & 0b1111) == 0b1101 && type == MAC_FRAME_TYPE_MANAGEMENT )
    {
        strcpy(MAC_msg, "Action");
    }
    else if( (subtype & 0b1111) == 0b1110 && type == MAC_FRAME_TYPE_MANAGEMENT )
    {
        strcpy(MAC_msg, "Action No Ack");
    }
    else if( (subtype & 0b1111) == 0b1111 && type == MAC_FRAME_TYPE_MANAGEMENT )
    {
        strcpy(MAC_msg, "Reserved");
    }
    else if( (subtype & 0b1111) == 0b0000 && type == MAC_FRAME_TYPE_CONTROL )
    {
        strcpy(MAC_msg, "Reserved");
    }
    else if( (subtype & 0b1111) == 0b0111 && type == MAC_FRAME_TYPE_CONTROL )
    {
        strcpy(MAC_msg, "Control Wrapper");
    }
    else if( (subtype & 0b1111) == 0b1000 && type == MAC_FRAME_TYPE_CONTROL )
    {
        strcpy(MAC_msg, "Block Ack Request (BlockAckReq)");
    }
    else if( (subtype & 0b1111) == 0b1001 && type == MAC_FRAME_TYPE_CONTROL )
    {
        strcpy(MAC_msg, "Block Ack (BlockAck)");
    }
    else if( (subtype & 0b1111) == 0b1010 && type == MAC_FRAME_TYPE_CONTROL )
    {
        strcpy(MAC_msg, "PS-Poll");
    }
    else if( (subtype & 0b1111) == 0b1011 && type == MAC_FRAME_TYPE_CONTROL )
    {
        strcpy(MAC_msg, "RTS");
    }
    else if( (subtype & 0b1111) == 0b1100 && type == MAC_FRAME_TYPE_CONTROL )
    {
        strcpy(MAC_msg, "CTS");
    }
    else if( (subtype & 0b1111) == 0b1101 && type == MAC_FRAME_TYPE_CONTROL )
    {
        strcpy(MAC_msg, "ACK");
    }
    else if( (subtype & 0b1111) == 0b1110 && type == MAC_FRAME_TYPE_CONTROL )
    {
        strcpy(MAC_msg, "CF-End");
    }
    else if( (subtype & 0b1111) == 0b1111 && type == MAC_FRAME_TYPE_CONTROL )
    {
        strcpy(MAC_msg, "CF-End + CF-Ack");
    }
    else if( (subtype & 0b1111) == 0b0000 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "Data");
    }
    else if( (subtype & 0b1111) == 0b0001 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "Data + CF-Ack");
    }
    else if( (subtype & 0b1111) == 0b0010 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "Data + CF-Poll");
    }
    else if( (subtype & 0b1111) == 0b0011 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "Data + CF-Ack + CF-Poll");
    }
    else if( (subtype & 0b1111) == 0b0100 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "Null (no data)");
    }
    else if( (subtype & 0b1111) == 0b0101 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "CF-Ack (no data)");
    }
    else if( (subtype & 0b1111) == 0b0110 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "CF-Poll (no data)");
    }
    else if( (subtype & 0b1111) == 0b0111 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "CF-Ack + CF-Poll (no data)");
    }
    else if( (subtype & 0b1111) == 0b1000 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "QoS Data");
    }
    else if( (subtype & 0b1111) == 0b1001 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "QoS Data + CF-Ack");
    }
    else if( (subtype & 0b1111) == 0b1010 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "QoS Data + CF-Poll");
    }
    else if( (subtype & 0b1111) == 0b1011 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "QoS Data + CF-Ack + CF-Poll");
    }
    else if( (subtype & 0b1111) == 0b1100 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "QoS Null (no data)");
    }
    else if( (subtype & 0b1111) == 0b1101 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "Reserved");
    }
    else if( (subtype & 0b1111) == 0b1110 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "QoS CF-Poll (no data)");
    }
    else if( (subtype & 0b1111) == 0b1111 && type == MAC_FRAME_TYPE_DATA )
    {
        strcpy(MAC_msg, "QoS CF-Ack + CF-Poll (no data)");
    }
    else
    {
        strcpy(MAC_msg, "Reserved");
    }
    
    return MAC_msg;
}

// Address field table 802.11:
//------------------------------------------------------------------------
// To DS    From DS    Address 1    Address 2    Address 3    Address 4

//   0         0          Dest         Src         BSSID         N/A
//   0         1          Dest         BSSID       Src           N/A
//   1         0          BSSID        Src         Dest          N/A
//   1         1          Recv         Trans       Dest          Src
//------------------------------------------------------------------------

void set_MAC_header(MAC_header_frame_t *frame, const u_char *buffer)
{
    // radio tap format
    //-----------------
    // version       : 1 bytes
    // padding       : 1 bytes
    // header length : 2 bytes
    //-----------------
    
    uint16_t radio_tap_len = 0;
    
    memcpy(&radio_tap_len, buffer + 2, sizeof(radio_tap_len));
    
    const u_char *MAC_offset = buffer + radio_tap_len; // skip radiotap
    
    memcpy(&(frame->frame_control), MAC_offset, sizeof(frame->frame_control)); // copy in the frame control
    
    
    // note : careful, in the docs format is b3b2
    if(!frame->frame_control.fc_typeb1 && !frame->frame_control.fc_typeb2)
    { // 0 0
        frame->frame_type = MAC_FRAME_TYPE_MANAGEMENT;
    }
    else if(frame->frame_control.fc_typeb1 && !frame->frame_control.fc_typeb2)
    { // 1 0
        frame->frame_type = MAC_FRAME_TYPE_CONTROL;
    }
    else if(!frame->frame_control.fc_typeb1 && frame->frame_control.fc_typeb2)
    { // 0 1
        frame->frame_type = MAC_FRAME_TYPE_DATA;
    }
    
    bool addr_4_present = false;
    
    // process only data frames for now (really the most important ones)
    if(frame->frame_type == MAC_FRAME_TYPE_DATA)
    {
        
        if(!frame->frame_control.fc_toDS && !frame->frame_control.fc_fromDS)
        { // 0 0
            memcpy(frame->address.addr1, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE, OCTET_ADDRESS_SIZE);
            memcpy(frame->address.addr2, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE, OCTET_ADDRESS_SIZE);
            memcpy(frame->address.addr3, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE, OCTET_ADDRESS_SIZE);
            
            frame->address.addr1_type = MAC_ADDR_TYPE_DESTINATION;
            frame->address.addr2_type = MAC_ADDR_TYPE_SOURCE;
            frame->address.addr3_type = MAC_ADDR_TYPE_BSSID;
            frame->address.addr4_type = MAC_ADDR_TYPE_NONE;
            
            addr_4_present = false;
        }
        else if(!frame->frame_control.fc_toDS && frame->frame_control.fc_fromDS)
        { // 0 1
            memcpy(frame->address.addr1, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE, OCTET_ADDRESS_SIZE);
            memcpy(frame->address.addr2, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE+ OCTET_ADDRESS_SIZE, OCTET_ADDRESS_SIZE);
            memcpy(frame->address.addr3, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE, OCTET_ADDRESS_SIZE);
            
            frame->address.addr1_type = MAC_ADDR_TYPE_DESTINATION;
            frame->address.addr2_type = MAC_ADDR_TYPE_BSSID;
            frame->address.addr3_type = MAC_ADDR_TYPE_SOURCE;
            frame->address.addr4_type = MAC_ADDR_TYPE_NONE;
            
            addr_4_present = false;
        }
        else if(frame->frame_control.fc_toDS && !frame->frame_control.fc_fromDS)
        { // 1 0
            memcpy(frame->address.addr1, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE, OCTET_ADDRESS_SIZE);
            memcpy(frame->address.addr2, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE, OCTET_ADDRESS_SIZE);
            memcpy(frame->address.addr3, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE, OCTET_ADDRESS_SIZE);
            
            frame->address.addr1_type = MAC_ADDR_TYPE_BSSID;
            frame->address.addr2_type = MAC_ADDR_TYPE_SOURCE;
            frame->address.addr3_type = MAC_ADDR_TYPE_DESTINATION;
            frame->address.addr4_type = MAC_ADDR_TYPE_NONE;
            
            addr_4_present = false;
        }
        else if(frame->frame_control.fc_toDS && frame->frame_control.fc_fromDS)
        { // 1 1
            
            //The presence of the Address 4 field is determined by the setting of the To DS and From DS subfields of the Frame Control field
            
            memcpy(frame->address.addr1, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE, OCTET_ADDRESS_SIZE);
            memcpy(frame->address.addr2, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE, OCTET_ADDRESS_SIZE);
            memcpy(frame->address.addr3, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE, OCTET_ADDRESS_SIZE);
            memcpy(frame->address.addr4, MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE + SEQ_SIZE, OCTET_ADDRESS_SIZE); // skip sequence bytes (2)
            
            frame->address.addr1_type = MAC_ADDR_TYPE_RECEIVER;
            frame->address.addr2_type = MAC_ADDR_TYPE_TRANSMITTER;
            frame->address.addr3_type = MAC_ADDR_TYPE_DESTINATION;
            frame->address.addr4_type = MAC_ADDR_TYPE_SOURCE;
            
            addr_4_present = true;
        }
        
        const u_char *end_of_addr;
        const u_char *seq_ptr;
        
        if(addr_4_present)
        {
            end_of_addr = MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE +
            OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE + SEQ_SIZE + OCTET_ADDRESS_SIZE;
            seq_ptr = MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE;
        }
        else
        {
            end_of_addr = MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE;
            seq_ptr = MAC_offset + FRAME_CONTROL_SIZE + DURATION_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE + OCTET_ADDRESS_SIZE;
        }
        
        
        
        memcpy(&(frame->sequence_control), seq_ptr, SEQ_SIZE);
        
        bool QoS_presnet = false;
        
        // check to make sure QoS and HT checks are correct -- might need to instead base it off frame control bits
        if(strstr(getSubtype(frame->frame_control.fc_subtype, frame->frame_type), "QoS") != NULL)
        {
            QoS_presnet = true;
        }
        else
        {
            QoS_presnet = false;
        }
        
        if(QoS_presnet)
        {
            const u_char *qos_ptr = seq_ptr; // get to start of variation
            if(addr_4_present) qos_ptr = qos_ptr + OCTET_ADDRESS_SIZE;
            memcpy(&(frame->qos_control), qos_ptr, QOS_SIZE);
        }
        
        const u_char *ht_ptr = seq_ptr; // get to start of variation
        if(QoS_presnet)
        {
            ht_ptr = ht_ptr + QOS_SIZE;
        }
        if(addr_4_present)
        {
            ht_ptr = ht_ptr + OCTET_ADDRESS_SIZE;
        }
        
        bool HT_present = false;
        
        // order/HTC+ is set to 1 in a QoS Data or Management frame transmitted with a value of HT_GF, HT_MF,
        // or VHT for the FORMAT parameter of the TXVECTOR to indicate that the frame contains an HT Control field
        if(frame->frame_control.fc_order)
        {
            memcpy(&(frame->ht_control), ht_ptr, HT_SIZE);
            HT_present = true;
        }
        
        const u_char *frame_ptr = seq_ptr; // get to start of variation
        
        if(HT_present)
        {
            frame_ptr = frame_ptr + HT_SIZE;
        }
        if(QoS_presnet)
        {
            frame_ptr = frame_ptr + QOS_SIZE;
        }
        if(addr_4_present)
        {
            frame_ptr = frame_ptr + OCTET_ADDRESS_SIZE;
        }
        
        frame->frame_body_start = frame_ptr;
        
    }
    else
    { // this wasn't a data frame
        frame->address.addr1_type = MAC_ADDR_TYPE_NONE;
        frame->address.addr2_type = MAC_ADDR_TYPE_NONE;
        frame->address.addr3_type = MAC_ADDR_TYPE_NONE;
        frame->address.addr4_type = MAC_ADDR_TYPE_NONE;
        
        frame->address.addr1[0] = 0;
        frame->address.addr1[1] = 0;
        frame->address.addr1[2] = 0;
        frame->address.addr1[3] = 0;
        frame->address.addr1[4] = 0;
        frame->address.addr1[5] = 0;
        
        frame->address.addr2[0] = 0;
        frame->address.addr2[1] = 0;
        frame->address.addr2[2] = 0;
        frame->address.addr2[3] = 0;
        frame->address.addr2[4] = 0;
        frame->address.addr2[5] = 0;
        
        frame->address.addr3[0] = 0;
        frame->address.addr3[1] = 0;
        frame->address.addr3[2] = 0;
        frame->address.addr3[3] = 0;
        frame->address.addr3[4] = 0;
        frame->address.addr3[5] = 0;
        
        frame->address.addr4[0] = 0;
        frame->address.addr4[1] = 0;
        frame->address.addr4[2] = 0;
        frame->address.addr4[3] = 0;
        frame->address.addr4[4] = 0;
        frame->address.addr4[5] = 0;
        
    }
    
}

void print_MAC_type(uint8_t type)
{
    if(type == MAC_ADDR_TYPE_DESTINATION)
    {
        printf("MAC type: DESTINATION");
    }
    else if (type == MAC_ADDR_TYPE_SOURCE)
    {
        printf("MAC type: SOURCE");
    }
    else if(type == MAC_ADDR_TYPE_BSSID)
    {
        printf("MAC type: BSSID");
    }
    else if(type == MAC_ADDR_TYPE_RECEIVER)
    {
        printf("MAC type: RECEIVER");
    }
    else if(type == MAC_ADDR_TYPE_TRANSMITTER)
    {
        printf("MAC type: TRANSMITTER");
    }
    else if(type == MAC_ADDR_TYPE_NONE)
    {
        printf("MAC type: NONE");
    }
}

void print_MAC_address(uint8_t *addr)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X",addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
}

void print_MAC_header_addresses(MAC_header_frame_t frame)
{
    print_MAC_type(frame.address.addr1_type);
    printf("\n");
    print_MAC_address(frame.address.addr1);
    printf("\n");
    
    print_MAC_type(frame.address.addr2_type);
    printf("\n");
    print_MAC_address(frame.address.addr2);
    printf("\n");
    
    print_MAC_type(frame.address.addr2_type);
    printf("\n");
    print_MAC_address(frame.address.addr2);
    printf("\n");
    
    print_MAC_type(frame.address.addr1_type);
    printf("\n");
    print_MAC_address(frame.address.addr2);
    printf("\n");
}

void process_80211(const u_char *buffer, uint16_t length)
{
    // notes:
    
    // radio tap + WLAN (actual 802.11 frame)
    
    MAC_header_frame_t MAC_header;
    set_MAC_header(&MAC_header,buffer);
    
    if(MAC_header.frame_type == MAC_FRAME_TYPE_DATA)
    {
        uint16_t data_start = MAC_header.frame_body_start - buffer;
        
        printf("----------------\n");
        printf("packet of length: %d\n",length);
        for(int i = 0; i < length; i++)
        {
            if(i%10 == 0) printf("\n");
            printf(" %02X ",buffer[i]);
            if(i == data_start) printf("  \n FRAME DATA:\n");
        }
        printf("\n\n");
        
        print_MAC_header_addresses(MAC_header);
        printf("----------------\n");
        printf("\n\n");
    }
}