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


#include <stdio.h>
