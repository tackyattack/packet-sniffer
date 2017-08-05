//
//  LLC.h
//  PacketSniffer
//  Logical Link Controller
//
//  Created by HENRY BERGIN on 8/4/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#ifndef LLC_h
#define LLC_h

#include <sys/types.h>
#include "_types/_uint16_t.h"
#include "_types/_uint8_t.h"

struct LLC_PDU
{
    uint8_t DSAP;
    uint8_t SSAP;
    uint8_t control[2]; // 8 or 16 depending on sequencing, but if 8 just fill MSB with 0
    const u_char *data_start;
    uint16_t data_length;
};


struct LLC_PDU_SNAP
{
    uint8_t DSAP;
    uint8_t SSAP;
    uint8_t control[2]; // 8 or 16 depending on sequencing, but if 8 just fill MSB with 0
    uint8_t org_code[3];
    uint8_t ether_type[2];
    const u_char *data_start;
    uint16_t data_length;
};

void process_LLC(const u_char *frame_start, uint16_t data_length);

#endif /* LLC_h */
