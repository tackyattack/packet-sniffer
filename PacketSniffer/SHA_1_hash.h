//
//  SHA_1_hash.h
//  PacketSniffer
//
//  Created by HENRY BERGIN on 11/10/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#ifndef SHA_1_hash_h
#define SHA_1_hash_h

#include <sys/types.h>
#include "_types/_uint32_t.h"
#include "_types/_uint16_t.h"
#include "_types/_uint8_t.h"

void SHA_1_hash(const char *message, char *output_char, char *output_byte , uint32_t byte_length);

#endif /* SHA_1_hash_h */
