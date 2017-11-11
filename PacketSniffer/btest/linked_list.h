//
//  linked_list.h
//  unit_testing
//
//  Created by HENRY BERGIN on 11/5/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#ifndef linked_list_h
#define linked_list_h

typedef struct list_node
{
    void *data;
    struct list_node *next;
}list_node;

void ll_add_node(list_node **head, void *data, uint16_t data_size);
void ll_teardown(list_node *head, void (*dealloc)(void *data));
void *ll_get_data(list_node *head, uint16_t pos);
void *ll_next(list_node *current_node);
void *ll_data(list_node *node);
void ll_iterate(list_node **current_node);

#endif /* linked_list_h */
