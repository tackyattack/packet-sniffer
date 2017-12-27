//
//  hash_table.h
//  PacketSniffer
//
//  Created by HENRY BERGIN on 12/27/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#ifndef hash_table_h
#define hash_table_h

#include <stdbool.h>

struct DataItem
{
    void *data;
    void *key;
    bool empty;
};


void hash_init(DataItem *hash_array_ptr, uint16_t hash_size,
               uint16_t (*hash_code_callback)(void *key),
               bool (*hash_key_match_callback)(void *key_A, void *key_B));
struct DataItem* hash_delete_item(void *key);
void hash_insert(void *key, uint16_t key_size, void *data, uint16_t data_size);
struct DataItem *hash_search(void *key);

void run_hash();

#endif /* hash_table_h */
