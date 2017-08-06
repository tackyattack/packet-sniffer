//
//  security.h
//  PacketSniffer
//
//  Created by HENRY BERGIN on 8/5/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#ifndef security_h
#define security_h

#include <sys/types.h>
#include "_types/_uint16_t.h"
#include "_types/_uint8_t.h"

void decrypt_CCMP_MPDU(const u_char *buffer, uint8_t *A2, uint8_t *PN, uint16_t length);

void testSecurity();

#endif /* security_h */
