//
//  hash_table.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 12/27/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//  Based on https://www.tutorialspoint.com/data_structures_algorithms/hash_table_program_in_c.htm
//  But modified to support any type through callbacks and void pointers

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "hash_table.h"

#define SIZE 20

// Setup hash by telling it where the array is that stores the values
// and how big it is
void hash_init(hash_table *table, DataItem *hash_array_ptr, uint16_t hash_size,
               uint16_t (*hash_code_callback)(void *key),
               bool (*hash_key_match_callback)(void *key_A, void *key_B))
{
    table->hash_table_size  = hash_size;
    table->hashArray        = hash_array_ptr;
    table->hash_code        = hash_code_callback;
    table->hash_key_match   = hash_key_match_callback;
    for(uint16_t i = 0; i < hash_size; i++)
    {
        table->hashArray[i].empty = true;
    }
}

// Simple hashing function
int hashCode(int key) {
    return key % SIZE;
}

struct DataItem *hash_search(hash_table table, void *key)
{
    //get the hash
    uint16_t hashIndex = table.hash_code(key);
    
    //move in array until an empty
    while(!table.hashArray[hashIndex].empty)
    {
        if(table.hash_key_match((table.hashArray[hashIndex].key), key))
        {
            return &(table.hashArray[hashIndex]);
        }
        
        //go to next cell
        ++hashIndex;
        
        //wrap around the table
        hashIndex %= SIZE;
    }
    
    return NULL;
}

void hash_insert(hash_table table, void *key, uint16_t key_size, void *data, uint16_t data_size)
{
    
    //get the hash
    uint16_t hashIndex = table.hash_code(key);
    
    //move in array until an empty or deleted cell
    while(!table.hashArray[hashIndex].empty)
    {
        //go to next cell
        ++hashIndex;
        
        //wrap around the table
        hashIndex %= SIZE;
    }
    
    memcpy((table.hashArray[hashIndex].key), key, key_size);
    memcpy((table.hashArray[hashIndex].data), data, data_size);
    table.hashArray[hashIndex].empty = false;
}

struct DataItem* hash_delete_item(hash_table table, void *key)
{
    
    //get the hash
    uint16_t hashIndex = table.hash_code(key);
    
    //move in array until an empty
    while(!table.hashArray[hashIndex].empty) {
        
        if(table.hash_key_match(table.hashArray[hashIndex].key, key))
        {
            //mark the item as empty
            table.hashArray[hashIndex].empty = true;
        }
        
        //go to next cell
        ++hashIndex;
        
        //wrap around the table
        hashIndex %= SIZE;
    }
    
    return NULL;
}
