#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "clist.h"

#define	FAILURE -1
#define	SUCCESS  0

/* FIXME: don't exit, return a failure code instead */

static void *xzalloc(size_t l)
{
	void *p = malloc(l);
	if (!p) {
		fprintf(stderr, "failed to allocated mem\n");
		exit(EXIT_FAILURE);
	}
	memset(p, 0, l);

	return p;
}

struct list *list_create(int (*match)(const void *key1, const void *key2),
		void (*destroy)(void *data))
{
	struct list *list = xzalloc(sizeof(struct list));

	list->size = 0;

	assert(match && destroy);

	list->destroy = destroy;
	list->match   = match;

	list->head = NULL;
	list->tail = NULL;

	return list;
}


void
list_destroy(struct list *list)
{
	void *data = NULL;

	while (list_size(list) > 0) {
		if (list_rem_next(list, NULL, (void **)&data) == 0) {
			list->destroy(data);
		}
	}
	memset(list, 0, sizeof(struct list));

	free(list);
	list = NULL;

	return;
}


/* return SUCCESS or FAILURE */
int list_insert(struct list *list, void *data)
{
	int ret;
	void *temp = data;

	ret = list_internal_lookup(list, &temp);
	if (ret != FAILURE) {
		fprintf(stderr, "insert failed - element exists already\n");
		return FAILURE;
	}

	return list_ins_next(list, NULL, data);
}


/* return SUCCESS or FAILURE */
int list_insert_tail(struct list *list, void *data)
{
	int ret;
	void *temp = data;

	ret = list_internal_lookup(list, &temp);
	if (ret != FAILURE) {
		fprintf(stderr, "insert failed - element exists already\n");
		return FAILURE;
	}

	return list_ins_next(list, list_tail(list), data);
}


int
list_lookup(struct list *list, void **data)
{
	return list_internal_lookup(list, data);
}


int list_for_each(struct list *list,
		int (*func)(void *data, void *userdata), void *userdata)
{
	struct list_element *element, *next_elem;
	int retval = 0;
	void *data;

	for (element = list_head(list);
		 element != NULL && retval == 0;) {
		 next_elem = list_next(element);

		data = element->data;
		retval = func(data, userdata);
		if (retval != SUCCESS)
			return FAILURE;
		element = next_elem;
	}

	return SUCCESS;
}


int list_remove_each_if_func_eq_1(struct list *list,
		int (*func)(void *data, void *userdata),
		void *userdata)
{
	struct list_element *element, *prev, *next;
	void *data = NULL;

	prev = NULL;

	for (element = list_head(list); element != NULL;) {
		next = list_next(element);
		if (func(list_data(element), userdata) == 1) {
			if (list_rem_next(list, prev, &data) == 0 &&
					list->destroy != NULL) {
				list->destroy(data);
			}
		} else {
			prev = element;
		}
		element = next;
	}
	return 0;
}

int
list_remove(struct list *list, void **data)
{
	struct list_element *element, *prev = NULL;

	for (element = list_head(list); element != NULL; element = list_next(element)) {

		if (list->match(*data, list_data(element))) {
			return list_rem_next(list, prev, data);
		}

		prev = element;
	}

	return FAILURE;
}


int
list_ins_next(struct list *list, struct list_element *element, const void *data)
{
	struct list_element *new_element = xzalloc(sizeof(struct list_element));

	new_element->data = (void *)data;

	if (element == NULL) {
		if (list_size(list) == 0) {
			list->tail = new_element;
		}

		new_element->next = list->head;
		list->head = new_element;
	} else {
		if (element->next == NULL) {
			list->tail = new_element;
		}

		new_element->next = element->next;
		element->next = new_element;
	}

	list->size++;

	return SUCCESS;
}


int list_rem_next(struct list *list, struct list_element *element, void **data)
{
	struct list_element *old_element = NULL;

	if (list_size(list) == 0)
		return FAILURE;

	if (element == NULL) {
		*data = list->head->data;
		old_element = list->head;
		list->head = list->head->next;

		if (list_size(list) == 1)
			list->tail = NULL;

	} else {
		if (element->next == NULL)
			return FAILURE;

		*data = element->next->data;
		old_element = element->next;
		element->next = element->next->next;

		if (element->next == NULL) {
			list->tail = element;
		}
	}

	free(old_element);

	list->size--;

	return SUCCESS;
}


int
list_internal_lookup(struct list *list, void **data)
{
	struct list_element *element;

	assert(data && *data);

	for (element = list_head(list);
		 element != NULL;
		 element = list_next(element))
	{
		if (list->match(*data, list_data(element))) {
			*data = list_data(element);
			return SUCCESS;
		}
	}

	return FAILURE;
}

void *list_lookup_match(struct list *list, int (*cmp)(void *, void *), void *data)
{
	struct list_element *element;

	assert(cmp && data);

	for (element = list_head(list);
		 element != NULL;
		 element = list_next(element))
	{
		if (cmp(list_data(element), data))
			return list_data(element);
	}

	return NULL;
}


