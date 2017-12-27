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

// Setup hash by telling it where the array is that stores the values
// and how big it is
void hash_init(DataItem *hash_array_ptr, uint16_t hash_size,
               uint16_t (*hash_code_callback)(void *key),
               bool (*hash_key_match_callback)(void *key_A, void *key_B))
{
    hash_table_size  = hash_size;
    hashArray        = hash_array_ptr;
    hash_code        = hash_code_callback;
    hash_key_match   = hash_key_match_callback;
    for(uint16_t i = 0; i < hash_size; i++)
    {
        hashArray[i].empty = true;
    }
}

// Simple hashing function
int hashCode(int key) {
    return key % SIZE;
}

struct DataItem *hash_search(void *key)
{
    //get the hash
    uint16_t hashIndex = hash_code(key);
    
    //move in array until an empty
    while(!hashArray[hashIndex].empty)
    {
        if(hash_key_match((hashArray[hashIndex].key), key))
        {
            return &(hashArray[hashIndex]);
        }
        
        //go to next cell
        ++hashIndex;
        
        //wrap around the table
        hashIndex %= SIZE;
    }
    
    return NULL;
}

void hash_insert(void *key, uint16_t key_size, void *data, uint16_t data_size)
{
    
    //get the hash
    uint16_t hashIndex = hash_code(key);
    
    //move in array until an empty or deleted cell
    while(!hashArray[hashIndex].empty)
    {
        //go to next cell
        ++hashIndex;
        
        //wrap around the table
        hashIndex %= SIZE;
    }
    
    memcpy((hashArray[hashIndex].key), key, key_size);
    memcpy((hashArray[hashIndex].data), data, data_size);
    hashArray[hashIndex].empty = false;
}

struct DataItem* hash_delete_item(void *key)
{
    
    //get the hash
    uint16_t hashIndex = hash_code(key);
    
    //move in array until an empty
    while(!hashArray[hashIndex].empty) {
        
        if(hash_key_match(hashArray[hashIndex].key, key))
        {
            //mark the item as empty
            hashArray[hashIndex].empty = true;
        }
        
        //go to next cell
        ++hashIndex;
        
        //wrap around the table
        hashIndex %= SIZE;
    }
    
    return NULL;
}
