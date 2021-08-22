#ifndef __LIBMINOS_FILE_H__
#define __LIBMINOS_FILE_H__

#include <stdint.h>
#include <inttypes.h>

struct fnode;

#define F_FLAGS_ROOT	(1 << 0)

struct file {
	int f_mode;
	int f_flags;
	int handle;
	int sbuf_size;		// PAGE_SIZE now

	uint64_t offset;
	void *sbuf;		// shared buf with the client.

	union {
		struct fnode *fnode;
		void *pdata;
	};

	struct file *next;	// link all the opened file.
};

typedef struct file dir_t;

struct file *create_file(int flags, int mode);
void release_file(struct file *file);

#endif