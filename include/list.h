#ifndef _COMMON_LIST_H
#define _COMMON_LIST_H

#include <stdbool.h>

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define list_entry(ptr, type, member) ({			\
	const struct list_head *__lptr = (ptr);	\
	(type *)( (char *)__lptr - offsetof(type, member) ); })

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
		&pos->member != (head);					\
		pos = list_next_entry(pos, member))

struct list_head {
	struct list_head *next, *prev;
};

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}


extern void list_add(struct list_head *new, struct list_head *head);
extern void list_add_tail(struct list_head *new, struct list_head *head);
extern void list_del(struct list_head *entry);
extern int list_count(const struct list_head *head);

static inline bool list_is_first(const struct list_head *list,
			const struct list_head *head)
{
	return list->prev == head;
}

static inline bool list_is_last(const struct list_head *list,
			const struct list_head *head)
{
	return list->next == head;
}

static inline bool list_empty(const struct list_head *head)
{
	return head->next == head;
}

#endif
