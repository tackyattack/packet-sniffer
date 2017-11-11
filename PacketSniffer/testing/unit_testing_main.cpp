//
//  unit_testing_main.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 11/10/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include <stdio.h>
#include "unit_testing_main.h"
#include "btest.h"
#include "crypto_testing.h"

void start_unit_testing()
{
    init_crypto_testing();
    btest_start_testing();
}
