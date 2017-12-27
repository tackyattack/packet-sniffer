//
//  LLC.cpp
//  PacketSniffer
//  Logical Link Controller
//
//  Created by HENRY BERGIN on 8/4/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

// LLC format:
//
// |DSAP|SSAP|Ctrl|DATA|
//
// If DSAP and SSAP are 0xAA, then it's a SNAP LLC:
//
// |DSAP|SSAP|Ctrl|SNAP|DATA|

#include "LLC.h"

#include <stdio.h>
#include <string.h>

#include "_types/_uint16_t.h"

#include "eapol_service.h"

#define LLC_TYPE_LLC  1
#define LLC_TYPE_SNAP 2

#define DSAP_SIZE       1
#define SSAP_SIZE       1
#define CONTROL_SIZE_8  1
#define CONTROL_SIZE_16 2
#define ORG_SIZE        3
#define ETH_SIZE        2

LLC_PDU_SNAP LLC_SNAP;
LLC_PDU      LLC;

// note: make sure to strip LLC header when sending up

void send_LLC_UP(LLC_PDU LLC)
{ // send the LLC up to the correct layer
    printf("\n------LLC------\n");
}

void send_LLC_SNAP_UP(LLC_PDU_SNAP LLC, MAC_header_frame_t MAC_header)
{ // send the LLC up to the correct layer
    printf("\n------LLC SNAP------\n");
    uint16_t eth_type = LLC.ether_type[0] | ((LLC.ether_type[1]) << 8); // convert to 16 bit
    printf("type: %04X\n",eth_type);
    
    if(eth_type == 0x888E)
    { // 802.1X Auth
        printf("802.1X Auth\n");
        process_EAPOL_frame(LLC.data_start, LLC.data_length, MAC_header);
        
    }
    else if (eth_type == 0x0800)
    {
        printf("IPv4\n");
    }
    
}

void process_LLC(const u_char *frame_start, uint16_t data_length, MAC_header_frame_t MAC_header)
{
    uint8_t LLC_type = 0;
    uint8_t LLC_control_size = 0;
    if(frame_start[0] == 0xAA && frame_start[1] == 0xAA)
    {
        LLC_type = LLC_TYPE_SNAP;
    }
    else
    {
        LLC_type = LLC_TYPE_LLC;
    }
    
    // I and S formats require 16 bits
    // U format requires only 8 bits
    
    // Type distinguish: (x <-> bit doesn't matter)
    // Control:
    //    b0 b1 ....
    // I: 0  x
    // S: 1  0
    // U: 1  1
    
    if( ((*(frame_start + DSAP_SIZE + SSAP_SIZE)) & 0b1) == 0b0 )
    { // Information transfer
        LLC_control_size = CONTROL_SIZE_16;
    }
    else if( ((*(frame_start + DSAP_SIZE + SSAP_SIZE)) & 0b11) == 0b10 )
    { // Supervisory C/R
        LLC_control_size = CONTROL_SIZE_16;
    }
    else if( ((*(frame_start + DSAP_SIZE + SSAP_SIZE)) & 0b11) == 0b11 )
    { // Unnumbered C/R
        LLC_control_size = CONTROL_SIZE_8;
    }
    
    if(LLC_type == LLC_TYPE_SNAP)
    {
        memcpy(&(LLC_SNAP.DSAP), frame_start, DSAP_SIZE);
        memcpy(&(LLC_SNAP.SSAP), frame_start + DSAP_SIZE, SSAP_SIZE);
        if(LLC_control_size == CONTROL_SIZE_16)
        {
            memcpy(&(LLC_SNAP.control), frame_start + DSAP_SIZE + SSAP_SIZE, LLC_control_size);
        }
        else if(LLC_control_size == CONTROL_SIZE_8)
        {
            memcpy(&(LLC_SNAP.control), frame_start + DSAP_SIZE + SSAP_SIZE, LLC_control_size);
            LLC_SNAP.control[1] = 0x00; // zero second byte
        }
        
         memcpy(&(LLC_SNAP.org_code), frame_start + DSAP_SIZE + SSAP_SIZE + LLC_control_size, ORG_SIZE);
        memcpy(&(LLC_SNAP.ether_type), frame_start + DSAP_SIZE + SSAP_SIZE + LLC_control_size + ORG_SIZE, ETH_SIZE);
        uint8_t temp = LLC_SNAP.ether_type[0];
        LLC_SNAP.ether_type[0] = LLC_SNAP.ether_type[1];
        LLC_SNAP.ether_type[1] = temp; // switch around since LSB but bytes are right to left
        // came in:  MSB     LSB
        //           oct1   oct0
        
        LLC_SNAP.data_start = frame_start + DSAP_SIZE + SSAP_SIZE + LLC_control_size + ORG_SIZE + ETH_SIZE;
        LLC_SNAP.data_length = data_length - (DSAP_SIZE + SSAP_SIZE + LLC_control_size + ORG_SIZE + ETH_SIZE);
        send_LLC_SNAP_UP(LLC_SNAP, MAC_header);
    }
    else if(LLC_type == LLC_TYPE_LLC)
    {
        memcpy(&(LLC.DSAP), frame_start, DSAP_SIZE);
        memcpy(&(LLC.SSAP), frame_start + DSAP_SIZE, SSAP_SIZE);
        if(LLC_control_size == CONTROL_SIZE_16)
        {
            memcpy(&(LLC.control), frame_start + DSAP_SIZE + SSAP_SIZE, LLC_control_size);
        }
        else if(LLC_control_size == CONTROL_SIZE_8)
        {
            memcpy(&(LLC.control), frame_start + DSAP_SIZE + SSAP_SIZE, LLC_control_size);
            LLC.control[1] = 0x00; // zero second byte
        }
        
        
        LLC.data_start = frame_start + DSAP_SIZE + SSAP_SIZE + LLC_control_size;
        LLC.data_length = data_length - (DSAP_SIZE + SSAP_SIZE + LLC_control_size);
    }
}
