#include "stdio_impl.h"

FILE *__ofl_add(FILE *f)
{
	FILE **head = __ofl_lock();
	f->next = *head;
	if (*head) (*head)->prev = f;
	*head = f;
	__ofl_unlock();
	return f;
}

static FILE *__ofl_do_get_file(FILE *head, int fd)
{
	while (head) {
		if (head->fd == fd)
			return head;
		head = head->next;
	}

	return NULL;
}

FILE *__ofl_get_file(int fd)
{
	FILE *file = NULL;
	FILE **head = __ofl_lock();

	/*
	 * for performance reason, will change to rb-tree
	 * later.
	 */
	file = __ofl_do_get_file(*head, fd);
	__ofl_unlock();

	return file;
}

FILE *__ofl_del_fd(int fd)
{
	FILE *f = NULL;
	FILE **head = __ofl_lock();

	f = __ofl_do_get_file(*head, fd);
	if (!f)
		goto out;

	if (f->prev) f->prev->next = f->next;
	if (f->next) f->next->prev = f->prev;
	if (*head == f) *head = f->next;
out:
	__ofl_unlock();

	return f;
}

void *__ofl_del(FILE *f)
{
	FILE **head = __ofl_lock();
	if (f->prev) f->prev->next = f->next;
	if (f->next) f->next->prev = f->prev;
	if (*head == f) *head = f->next;
	__ofl_unlock();
}
