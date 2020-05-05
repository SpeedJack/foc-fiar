#ifndef _COMMON_LIST_H
#define _COMMON_LIST_H

#include <stdbool.h>

/* Doubly linked list implementation. */
struct list_head {
	struct list_head *next, *prev;
};

/* Defines a new list with the specified name. */
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

/* Initializes an empty list (with just one element). */
#define LIST_HEAD_INIT(name) { &(name), &(name) }

/*
 * Returns the entry that contains the specified list head. type is the type to
 * return; member is the name of the list head member in the structure.
 */
#define list_entry(ptr, type, member) ({			\
	const struct list_head *__lptr = (ptr);	\
	(type *)( (char *)__lptr - offsetof(type, member) ); })

/*
 * Returns the first element of the list specified by ptr. type is the type to
 * return; member is the name of the list head member in the structure.
 */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/*
 * Returns the last element of the list specified by ptr. type is the type to
 * return; member is the name of the list head member in the structure.
 */
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

/*
 * Returns the next element in the list. pos is a pointer to the current
 * element; member is the name of the list head member in the structure.
 */
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

/*
 * Returns the previous element in the list. pos is a pointer to the current
 * element; member is the name of the list head member in the structure.
 */
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)

/*
 * Do a for-each over all list heads of the list. pos is a pointer to the
 * current list head; head is a pointer to the list head of the first element.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/*
 * Do a for-each over all elements of the list. pos is a pointer to the current
 * element; head is a pointer to the list head of the first element; member is
 * the namne of the list head member in the structure.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
		&pos->member != (head);					\
		pos = list_next_entry(pos, member))

/* Initializes an empty list head. */
static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

extern void list_add(struct list_head *new, struct list_head *head);
extern void list_add_tail(struct list_head *new, struct list_head *head);
extern void list_del(struct list_head *entry);
extern int list_count(const struct list_head *head);

/* Checks if the specified list head is the first in the list. */
static inline bool list_is_first(const struct list_head *list,
			const struct list_head *head)
{
	return list->prev == head;
}

/* Checks if the specified list head is the last in the list. */
static inline bool list_is_last(const struct list_head *list,
			const struct list_head *head)
{
	return list->next == head;
}

/* Checks if the specified list is empty. */
static inline bool list_empty(const struct list_head *head)
{
	return head->next == head;
}

#endif
