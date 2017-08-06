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

#define ENCRYPT_TYPE_HMAC_SHA_1_128 1
#define ENCRYPT_TYPE_AES_128_CMAC   2
#define ENCRYPT_TYPE_HMAC_SHA_256   3
#define ENCRYPT_TYPE_HMAC_SHA_384   4
#define ENCRYPT_TYPE_UNKNOWN        5

void process_EAPOL_frame(const u_char *data_frame, uint16_t length);

#endif /* eapol_service_h */
