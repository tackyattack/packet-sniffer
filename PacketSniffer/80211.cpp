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

// See if you need a ring buffer to process 802.11 packets, or if layers 3 and above need one.

// MSDU -> MPDU -> (security) -> LLC -> upper layers
// The MSDU (can be A-MSDU) are encapsulated by MPDU (can be A-MPDU) which then
// has security [MAC HEADER | CCMP | DATA (encrypted) | FCS]. After decryption (if secure),
// then the MSDU is passed up to the Logical Link Control, which reads the LLC header and determines
// which layer to pass the packet to (probably after stripping the LLC)

// Authenticaion should be a layer that LLC passes to since EAPOL contains an LLC header


#include <stdio.h>
#include <sys/types.h>  // useful system types
#include <iostream>

#include "LLC.h"
#include "80211.h"
#include "security.h"

#include "eapol_service.h"


#define FRAME_CONTROL_SIZE 2
#define DURATION_SIZE      2
#define OCTET_ADDRESS_SIZE 6
#define SEQ_SIZE           2
#define QOS_SIZE           2
#define HT_SIZE            4
#define FCS_SIZE           4

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

void set_MAC_header(MAC_header_frame_t *frame, const u_char *buffer, uint16_t length)
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
    
    memcpy(&(frame->frame_control), MAC_offset, FRAME_CONTROL_SIZE); // copy in the frame control
    
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
        //printf("MAC start : %02X ",*MAC_offset);
        //printf(" FC: %d ", frame->frame_control.fc_protected);
        
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
        // ( ( (0b1010) & (0b1000) ) >> 3 )  = 1
        // (((0b0000) & (0b1000)) >> 3) = 0
        // printf("fc subtype: %X",frame->frame_control.fc_subtype);
        if( ((frame->frame_control.fc_subtype & 0b1000 ) >> 3) )
        {
            QoS_presnet = true;
        }
        else
        {
            QoS_presnet = false;
        }
        uint16_t qos = 0;
        
        if(QoS_presnet)
        {
            const u_char *qos_ptr = seq_ptr + SEQ_SIZE; // get to start of variation
            if(addr_4_present) qos_ptr = qos_ptr + OCTET_ADDRESS_SIZE;
            memcpy(&(frame->qos_control), qos_ptr, QOS_SIZE);
            memcpy(&qos, qos_ptr, QOS_SIZE);
            frame->qos_present = true;
        }
        else
        {
            frame->qos_present = false;
        }
        
        const u_char *ht_ptr = seq_ptr + SEQ_SIZE; // get to start of variation
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
            frame->ht_present = true;
        }
        else
        {
            frame->ht_present = false;
        }
        
        const u_char *frame_ptr = seq_ptr + SEQ_SIZE; // get to start of variation
        
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
        
        if(frame->qos_present && frame->qos_control.qos_A_MSDU_present)
        {
            if(frame->qos_present)printf("fc QoS: %X \n",qos);
            printf("MSDU present: %d \n", frame->qos_control.qos_A_MSDU_present);
            printf("MSDU type: %d \n", frame->qos_control.qos_A_MSDU_type);
        }
        
        frame->FCS = buffer + length - FCS_SIZE; // end of packet and back up to the start of the FCS (32 bit)
        //printf("FCS: %02X %02X %02X %02X\n",(frame->FCS)[0], (frame->FCS)[1], (frame->FCS)[2], (frame->FCS)[3]);
        
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

// Data frame should always start after DA/SA/Length
void process_MSDU(const u_char *data_frame, uint16_t length)
{ // pass on to LLC
    process_LLC(data_frame, length);
}

void process_MPDU(MAC_header_frame_t frame)
{
    // A-MPDU can be left as they come in since they encapsulate everything needed in the normal MPDU structure.
    
    // 9.2.4.5.9 A-MSDU Present subfield:
    //
    // The A-MSDU Present subfield (B7 of QoS control) is 1 bit in length and indicates the presence of an A-MSDU.
    // The A-MSDU Present subfield is set to 1 to indicate that the Frame Body field contains an entire A-MSDU as defined in 9.3.2.2.
    // The A-MSDU Present subfield is set to 0 to indicate that the Frame Body field contains an MSDU or fragment thereof as defined in 9.3.2.1.
    // NOTE—A DMG STA, when the A-MSDU Present subfield is set to 1, can use one of two A-MSDU formats in the Frame Body.
    // The specific A-MSDU format present is indicated by the A-MSDU Type subfield.
    
    
    //9.2.4.5.13 A-MSDU Type subfield
    //
    //The A-MSDU Type subfield (B8 of QoS control) is 1 bit in length and indicates the type of A-MSDU present in the Frame Body.
    //When the A-MSDU Type subfield is set to 0, the Frame Body field contains a Basic A-MSDU as defined in 9.3.2.2.2.
    //When the A-MSDU Type subfield is set to 1, the Frame Body field contains a Short A-MSDU as defined in 9.3.2.2.3.
    //The A-MSDU Type subfield is reserved if the A-MSDU Present subfield is set to 0.
    
    // When a Data frame carries an MSDU, the DA and SA values related to that MSDU are carried in
    // the Address 1, Address 2, Address 3, and Address 4 fields.
    // Meaning: the data will start with LLC / CCMP instead of A-MSDU formatting
    
    // EAPoL is never encrypted so just pass it on up to process_MSDU as you would a normal MSDU. If an MPDU is encrypted, then
    // take care of decrypting here before passing to process_MSDU
    
    bool MSDU_A_present = frame.qos_control.qos_A_MSDU_present;
    bool MSDU_A_type = frame.qos_control.qos_A_MSDU_type;
    
    const u_char *MSDU_start = frame.frame_body_start; // if encrypted, you'll have to deal with that before passing on
    
    uint16_t data_length = frame.FCS - frame.frame_body_start;
    if(MSDU_A_present)
    { // there's multiple MSDU
        //uint16_t MPDU_data_length = frame.;
        
        // run through all MSDU subframes until data_length is reached
        
        if(MSDU_A_type)
        { // short
            
        }
        else
        { // basic
            
        }
    }
    else
    { // single MSDU
        process_MSDU(MSDU_start, data_length);
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

    //EAPOL_test();
    //testSecurity();
    //while(1);
    
    MAC_header_frame_t MAC_header;
    set_MAC_header(&MAC_header, buffer, length);
    
    if(MAC_header.frame_type == MAC_FRAME_TYPE_DATA)
    {
        uint16_t data_start = MAC_header.frame_body_start - buffer;
        printf("----------------\n");
        printf("packet of length: %d\n",length);
        for(int i = 0; i < length; i++)
        {
            if(i%10 == 0) printf("\n");
            printf(" %02X ",buffer[i]);
            if(i == data_start - 1) printf("  \n FRAME DATA:\n");
        }
        printf("\n\n");
        
        print_MAC_header_addresses(MAC_header);
        printf("----------------\n");
        printf("\n\n");
        
        process_MPDU(MAC_header);
    }
}
