//
//  HMAC.h
//  PacketSniffer
//
//  Created by HENRY BERGIN on 11/28/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#ifndef HMAC_h
#define HMAC_h

#include <sys/types.h>
#include "_types/_uint32_t.h"
#include "_types/_uint16_t.h"
#include "_types/_uint8_t.h"

void HMAC(const char *input_key, const char *input_message, char *output);

#endif /* HMAC_h */
