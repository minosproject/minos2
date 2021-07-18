#ifndef __LIBMINOS_FS_H__
#define __LIBMINOS_FS_H__

#include <inttypes.h>

#define FS_NAME_SIZE 64

enum {
	DT_UNKNOWN = 0,
	DT_FIFO = 1,
	DT_CHR = 2,
	DT_DIR = 4,
	DT_BLK = 6,
	DT_REG = 8,
	DT_LNK = 10,
	DT_SOCK = 12,
	DT_WHT = 14,
#define DT_ANY		0xff
};

#define O_ACCMODE	   00000003
#define O_RDONLY	   00000000
#define O_WRONLY	   00000001
#define O_RDWR		   00000002
#define O_CREAT		   00000100
#define O_EXCL		   00000200	/* not fcntl */
#define O_NOCTTY	   00000400	/* not fcntl */
#define O_TRUNC		   00001000	/* not fcntl */
#define O_APPEND	   00002000
#define O_NONBLOCK	   00004000
#define O_NDELAY	   O_NONBLOCK
#define O_SYNC		   00010000
#define FASYNC		   00020000	/* fcntl, for BSD compatibility */
#define O_DIRECTORY	   00040000	/* must be a directory */
#define O_NOFOLLOW	   00100000	/* don't follow links */
#define O_DIRECT	   00200000	/* direct disk access hint - currently ignored */
#define O_LARGEFILE	   00400000
#define O_NOATIME	   01000000

#define F_DUPFD		0	/* dup */
#define F_GETFD		1	/* get close_on_exec */
#define F_SETFD		2	/* set/clear close_on_exec */
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4	/* set file->f_flags */
#define F_GETLK		5
#define F_SETLK		6
#define F_SETLKW	7

#define SEEK_SET	0
#define SEEK_CUR	1
#define SEEK_END	2

struct file;
struct blkdev;
struct super_block;

#define MAX_FILENAME 256

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

	char name[MAX_FILENAME];
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

struct filesystem *lookup_filesystem(unsigned char type);
int register_filesystem(struct filesystem *fs);

int fs_open(struct super_block *sb, char *path, struct fnode **out);

int fs_read(struct fnode *fnode, char *buf, size_t size, off_t offset);

int fs_write(struct fnode *fnode, char *buf, size_t size, off_t offset);

int vfs_init(void);

#endif
