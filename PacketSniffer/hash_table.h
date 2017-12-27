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

struct hash_table
{
    uint16_t hash_table_size = 0;
    uint16_t (*hash_code)(void *key); // function pointer to the hash function
                                      // since we're likley not going to have a
                                      // hash table size above 0xffff, it's fine
                                      // to cap it at that size. The function is
                                      // to be implemented as a callback in the
                                      // class that is using the hash function.
    
    bool (*hash_key_match)(void *key_A, void *key_B); // Callback to check if two keys match
    struct DataItem* hashArray;
    struct DataItem* item;
};


void hash_init(hash_table *table,DataItem *hash_array_ptr, uint16_t hash_size,
               uint16_t (*hash_code_callback)(void *key),
               bool (*hash_key_match_callback)(void *key_A, void *key_B));
struct DataItem* hash_delete_item(hash_table table, void *key);
void hash_insert(hash_table table, void *key, uint16_t key_size, void *data, uint16_t data_size);
struct DataItem *hash_search(hash_table table, void *key);

void run_hash();

#endif /* hash_table_h */
