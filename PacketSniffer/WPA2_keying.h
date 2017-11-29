//
//  WPA2_keying.h
//  PacketSniffer
//
//  Created by HENRY BERGIN on 11/29/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#ifndef WPA2_keying_h
#define WPA2_keying_h

#include <sys/types.h>
#include "_types/_uint32_t.h"
#include "_types/_uint16_t.h"
#include "_types/_uint8_t.h"

void convert_WPA_to_PSK(char *password, char *SSID, uint8_t *output);

#endif /* WPA2_keying_h */
