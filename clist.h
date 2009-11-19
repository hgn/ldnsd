#ifndef CLIST_H
#define CLIST_H

#define list_size(list) ((list)->size)
#define list_head(list) ((list)->head)
#define list_tail(list) ((list)->tail)
#define list_is_head(list, element) ((element) == (list)->head ? 1 : 0)
#define list_is_tail(element) ((element)->next == NULL ? 1 : 0)
#define list_data(element) ((element)->data)
#define list_next(element) ((element)->next)

struct list_element {
    void *data;
    struct list_element    *next;
};

struct list {
    int size;
    int (*match)(const void *key1, const void *key2);
    void (*destroy)(void *data);
    struct list_element *head;
    struct list_element *tail;
};

struct list *list_create(int (*match)(const void *key1, const void *key2), void (*destroy)(void *data));
void list_destroy(struct list *list);
int list_insert(struct list *list, void *data);
int list_lookup(struct list *list, void **data);
void *list_lookup_match(struct list *, int (*cmp)(void *, void *), void *);
int list_for_each(struct list *list, int (*func)(void *data, void *userdata), void *userdata);
int list_remove_each_if_func_eq_1(struct list *list, int (*func)(void *data, void *userdata), void *userdata);
int list_remove(struct list *list, void **data);

int list_ins_next(struct list *list, struct list_element *element, const void *data);
int list_rem_next(struct list *list, struct list_element *element, void **data);
int list_internal_lookup(struct list *list, void **data);



#endif /* CLIST_H */
