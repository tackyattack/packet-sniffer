//
//  misc_testing.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 12/27/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include "misc_testing.h"
#include <stdio.h>
#include "btest.h"
#include "hash_table.h"
#include <string.h>

struct data_item
{
    uint16_t key;
    uint16_t data;
};

uint16_t hash_code_callback(void *key)
{
    uint16_t key_val = (*(uint16_t *)(key));
    return key_val%20;
}
bool hash_key_match_callback(void *key_A, void *key_B)
{
    uint16_t A = (*(uint16_t *)(key_A));
    uint16_t B = (*(uint16_t *)(key_B));
    if(A == B)
    {
        return true;
    }
    else
    {
        return false;
    }
}

TEST(misc, hash_table)
{
    DataItem hashArray[20];
    data_item items[20];
    for(uint16_t i = 0; i < 20; i++)
    {
        hashArray[i].key = &(items[i].key);
        hashArray[i].data = &(items[i].data);
    }
    hash_table table;
    
    hash_init(&table, hashArray, 20, hash_code_callback, hash_key_match_callback);
    
    uint16_t key1 = 10;
    char arr[] = "hello world";
    hash_insert(table, &key1, sizeof(key1), &arr, sizeof(arr));
    EXPECT_EQ_STR(arr, (char *)hash_search(table, &key1)->data, strlen(arr));
}

void init_misc_testing()
{
    ADD_TEST(misc, hash_table);
}
