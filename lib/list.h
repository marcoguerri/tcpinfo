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

typedef struct {
    void *payload;
    size_t size;
} data_t;

typedef struct node_t_internal {
    data_t *data;
    struct node_t_internal *next;
    struct node_t_internal *prev;
} node_t;


node_t *list_init(void *payload, size_t size);
void list_destroy(node_t *root);
char *list_print(node_t *root, int(print_payload)(void*, char *));
size_t list_len(node_t *root);
node_t* list_insert(node_t* ptr_root, void *payload, size_t size, size_t pos);
void* list_get(node_t* ptr_root, size_t pos);
node_t* list_del(node_t* ptr_root, void* payload, size_t size);
node_t* list_search(node_t* ptr_root, void* payload, size_t size);

#endif

