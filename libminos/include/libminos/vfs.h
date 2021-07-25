#ifndef __LIBMINOS_VFS_H__
#define __LIBMINOS_VFS_H__

#include <inttypes.h>

struct file;
struct blkdev;
struct super_block;

struct fnode {
	uint8_t mode;
	uint8_t type;
	uint8_t state;
	uint8_t flags;
	uint16_t nlinkes;
	uint32_t atime;
	uint32_t mtime;
	uint32_t ctime;
	size_t file_size;

	uint64_t location;

	struct list_head child; // all opened children in this directory
	struct list_head list;	// list to the superblock f_opens;

	char name[FILENAME_MAX];
	struct partition *partition;
};

struct file {
	uint8_t f_mode;
	uint8_t mmap_mode;
	int f_flags;

	uint64_t offset;
	int handle;		// root file will be -1.
	void *sbuf;		// shared buf with the client.
	int sbuf_size;

	struct fnode *fnode;
	struct file *next;	// link all the opened file.
};

typedef struct file dir_t;

struct super_block {
	unsigned char dirty;		/* if the superblock is dirty */
	unsigned char block_size_bits;	/* block size contains how many bits */
	unsigned short block_size;	/* block size */
	size_t max_file;		/* max file count */
	unsigned long flags;		/* flags */
	unsigned long magic;		/* maigic number if has */
	struct fnode *root_fnode;	/* root fnode of this partition */
	struct partition *partition;	/* partition of this super block */
};

#define FS_NAME_SIZE 32

struct filesystem {
	char name[FS_NAME_SIZE];
	int (*match)(int type, char *name);

	int (*create_super_block)(struct partition *partition,
			struct filesystem *fs);

	ssize_t (*read)(struct fnode *fnode,
			char *buf, size_t size, off_t offset);
	ssize_t (*write)(struct fnode *fnode,
			char *buf, size_t size, off_t offset);
	struct fnode *(*find_file)(struct fnode *parent, char *path);
};

int register_filesystem(struct filesystem *fs);

int vfs_init(void);

struct file *vfs_open(struct partition *part,
		char *path, int flags, int mode);

#endif
