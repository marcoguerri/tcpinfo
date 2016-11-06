/*
 * The MIT License (MIT)
 * Copyright (C) 2016 Marco Guerri
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of 
 * this software and associated documentation files (the "Software"), to deal in 
 * the Software without restriction, including without limitation the rights to use, 
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
 * Software, and to permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __LIST_H__
#define __LIST_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

typedef struct {
    void *payload;
    size_t size;
} list_data_t;

typedef struct list_node_t_internal {
    list_data_t *data;
    struct list_node_t_internal *next;
    struct list_node_t_internal *prev;
} list_node_t;


list_node_t *list_init(void *payload, size_t size);
void list_destroy(list_node_t *root);
char *list_print(list_node_t *root, int(print_payload)(void*, char *));
size_t list_len(list_node_t *root);
list_node_t* list_insert(list_node_t* ptr_root, void *payload, size_t size, size_t pos);
void* list_get(list_node_t* ptr_root, size_t pos);
list_node_t* list_del(list_node_t* ptr_root, void* payload, size_t size);
list_node_t* list_search(list_node_t* ptr_root, void* payload, size_t size);

#endif

