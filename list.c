#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include "list.h"

#define LIST_PRINT_BUFF_SIZE          16
#define REALLOC_THRESHOLD    8

/* Initializes a new root node */
node_t*
list_init(void *payload, size_t size)
{
    if(payload == NULL || size <= 0)
        return NULL;

    data_t *ptr_data = (data_t*)malloc(sizeof(data_t));
    if(ptr_data == NULL)
    {
        perror("malloc");
        goto err_data;
    }

    ptr_data->size = size;
    ptr_data->payload = (void*)malloc(size);
    if(ptr_data->payload == NULL)
    {
        perror("malloc");
        goto err_payload;
    }

    memcpy(ptr_data->payload, payload, size);

    node_t *ptr_node = (node_t*)malloc(sizeof(node_t));
    if(ptr_node == NULL) 
    {
        perror("malloc");
        goto err_node;
    
    }
    ptr_node->data = ptr_data;
    ptr_node->next = NULL;
    ptr_node->prev = NULL;

    assert(memcmp(payload, ptr_node->data->payload, size) == 0);
    assert(ptr_node->next == NULL);
    assert(ptr_node->prev == NULL);

    return ptr_node;

err_node:
    free(ptr_node);
err_payload:
    free(ptr_data->payload); 
err_data:
    free(ptr_data);
    return NULL;
}


char*
list_print(node_t *root, int (*print_payload)(void*, char*))
{
    size_t curr_buff_size = LIST_PRINT_BUFF_SIZE;
    char *buff = (char*)malloc(sizeof(char)*LIST_PRINT_BUFF_SIZE);
    memset(buff, 0, LIST_PRINT_BUFF_SIZE);

    if(print_payload == NULL)
        return NULL;

    int written = 0;
    size_t buff_ptr = 0;
    while(root != NULL)
    {
        written =  (*print_payload)(root->data->payload, buff + buff_ptr);
        if(written == -1)
        {
            free(buff);
            return NULL;
        }

        buff_ptr += written;
        if(buff_ptr  > curr_buff_size - REALLOC_THRESHOLD)
        {
            char *new_buff = (char*)realloc(buff, sizeof(char)*(curr_buff_size*2));
            if(new_buff == NULL) 
            {
                free(buff); /* Old buffer was still allocated */
                perror("realloc");
                return NULL;
            }
            buff = new_buff;
            memset(buff + buff_ptr, 0, curr_buff_size);
            curr_buff_size = curr_buff_size*2;
        }
        root = root->next;
    }
    return buff;
}


/**
 * @brief free root node and all those following
 * @param root Root node. This might not be necessarily the root of the list.
 * All the nodes following root, including root, will be freed
 */
void
list_destroy(node_t *root)
{
    /* root might not be the root of the list. In this case, set the next pointer
     * of the previous node to NULL as root will be freed */
    if(root->prev != NULL)
        root->prev->next = NULL;

    while(root != NULL)
    {
        node_t* next = root->next;
        free(root->data->payload);
        free(root->data);
        free(root);
        root = next;
    }
}

/**
 * Returns the size of the list starting by the node passed as argument,
 * which might not be the root. TODO: Consider improving by keeping temporary
 * counters.
 */
size_t 
list_len(node_t* root)
{
    size_t len = 0;
    while(root != NULL)
    {
        ++len;
        root = root->next;
    }
    return len;
}

/*
 * @brief Inserts a new node in position pos starting from ptr_root. 
 * @param pos Position (0-indexed) where to add the new node.
 * @return Pointer to the new list root or NULL upon failure. When returning
 * NULL the old list is NOT destroyed.
 */
node_t*
list_insert(node_t* ptr_root, void *payload, size_t size, size_t pos)
{
    if(ptr_root == NULL || payload == NULL || pos > list_len(ptr_root))
        return NULL;
    
    node_t *ptr_prev = NULL, *ptr_pos = ptr_root;
    while(pos > 0)
    {
        ptr_prev = ptr_pos;
        /* Checked pos against the length of the list, we can't go beyon the 
         * last element */
        assert(ptr_pos != NULL);
        ptr_pos = ptr_pos-> next;
        --pos;
    }

    node_t *ptr_node = (node_t*)malloc(sizeof(node_t));
    data_t* ptr_data = (data_t*)malloc(sizeof(data_t));
    ptr_data->payload = (void*)malloc(size);

    
    if(ptr_node == NULL || ptr_data == NULL || ptr_data->payload == NULL)
    {
        perror("malloc");
        goto err_node_data;
    }

    if(ptr_pos == NULL) 
    {
        /* Appending at the end */
        assert(ptr_node != NULL && ptr_prev != NULL);
        ptr_node->next = NULL;
        ptr_node->prev = ptr_prev;
        ptr_prev->next = ptr_node;
    }
    else if(ptr_pos->prev == NULL)
    {
        /* Beginning of the list */
        assert(ptr_node != NULL && ptr_pos != NULL);
        ptr_node->next = ptr_root;
        ptr_node->prev = NULL;
        ptr_pos->prev = ptr_node;
        /* The node just allocated is the new root which will be returned */
        ptr_root = ptr_node;
    }
    else
    {  
        /* Adding in the middle */ 
        assert(ptr_node != NULL && ptr_pos != NULL && ptr_pos->prev != NULL);
        ptr_node->next = ptr_pos;
        ptr_node->prev = ptr_pos->prev;
        ptr_pos->prev = ptr_node;
        ptr_pos->prev->next = ptr_node;
    }

    memcpy(ptr_data->payload, payload, size);
    ptr_data->size = size;
    ptr_node->data = ptr_data;
    assert(memcmp(payload, ptr_node->data->payload, size) == 0);

    return ptr_root;

err_node_data:
    free(ptr_data);
    free(ptr_node);
    return NULL;
}

/**
 * @brief Returns a pointer to the payload of the n-th element of the list
 * @param ptr_root Pointer to root of the list
 * @param pos 0-indexed position of the element to return
 * @return Pointer to the payload of the n-th element of the list or NULL upon
 * failure
 */
void*
list_get(node_t *ptr_root, size_t pos)
{

    if(ptr_root == NULL || pos >= list_len(ptr_root))
        return NULL;
    while(pos > 0)
    {
        /* We checked pos against the length of the list, can't be null at this
         * point */
        assert(ptr_root != NULL);
        ptr_root = ptr_root->next;
        --pos;
    }
    return ptr_root->data->payload;

}

