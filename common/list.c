#include "list.h"
#include "assertions.h"
#include <stddef.h>

/* Adds a new entry between two entries. */
static inline void __list_add(struct list_head *new,
			struct list_head *prev,
			struct list_head *next)
{
	assert(new && prev && next);
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/* Removes the entry between the two specified entries. */
static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	assert(prev && next);
	next->prev = prev;
	prev->next = next;
}

/* Adds an entry to the list, after the specified list head. */
void list_add(struct list_head *new, struct list_head *head)
{
	assert(head);
	__list_add(new, head, head->next);
}

/* Adds an entry to the list, before the specified list head. */
void list_add_tail(struct list_head *new, struct list_head *head)
{
	assert(head);
	__list_add(new, head->prev, head);
}

/* Removes the specified entry from the list. */
void list_del(struct list_head *entry)
{
	assert(entry);
	__list_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

/* Counts the number of entries in the list. */
int list_count(const struct list_head *head)
{
	assert(head);
	int count = 0;
	struct list_head *pos;
	list_for_each(pos, head)
		count++;
	return count;
}
