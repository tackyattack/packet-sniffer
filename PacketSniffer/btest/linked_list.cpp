//
//  linked_list.c
//  unit_testing
//
//  Created by HENRY BERGIN on 11/5/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "linked_list.h"


// Note: to dereference void pointer: uint8_t value = *(uint8_t *)(void_ptr);

void ll_add_node(list_node **head, void *data, uint16_t data_size)
{
    
    list_node *new_node = (list_node *)malloc(sizeof(list_node));
    
    new_node->data = malloc(data_size);
    memcpy(new_node->data, data, data_size);
    
    if( (*head) == NULL )
    {
        (*head) = new_node;
        (*head)->next = NULL;
    }
    else
    {
        list_node *current_node = (*head);
        while(current_node->next != NULL)
        {
            current_node = current_node->next;
        }
        
        new_node->next = NULL;
        current_node->next = new_node;
    }
}

void ll_teardown(list_node *head, void (*dealloc)(void *data))
{
    // walk down the list and delete the nodes
    list_node *current_node = head;
    list_node *trail_node = head; // walks behind the current node
    
    while(current_node != NULL)
    {
        trail_node = current_node;
        current_node = current_node->next;
        (*(dealloc))(trail_node->data); // call the dealloc
        free(trail_node->data); // delete the data that was alloctated
        free(trail_node);
        trail_node->data = NULL;
        trail_node = NULL;
    }
}

void *ll_get_data(list_node *head, uint16_t pos)
{ // todo: make it so that it stores the last search position and can jump if get is >= last pos
    uint8_t hit_end = 0;
    list_node *current_node = head;
    for (uint16_t i = 0; (i < pos) && (!hit_end); i++) {
        
        if(current_node->next == NULL && (i<pos))
        {
            current_node = NULL;
            hit_end = 1;
        }
        else
        {
            current_node = current_node->next;
        }
    }
    
    if(current_node == NULL)
    {
        return NULL;
    }
    else
    {
        return current_node->data;
    }
}

void *ll_next(list_node *current_node)
{
    if((current_node)->next != NULL)
    {
        void *data = (current_node)->data;
        return data;
    }
    else
    {
        return NULL;
    }
}

void *ll_data(list_node *node)
{
    return node->data;
}

void ll_iterate(list_node **current_node)
{
    (*current_node) = (*current_node)->next;
}
