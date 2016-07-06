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

