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

void process_80211(const u_char *buffer, uint16_t length);

#endif /* _0211_h */
