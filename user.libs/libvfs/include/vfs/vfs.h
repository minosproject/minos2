#ifndef __LIBMINOS_VFS_H__
#define __LIBMINOS_VFS_H__

#include <inttypes.h>

#include <vfs/file.h>
#include <minos/types.h>

#define NR_HASH_LIST 10

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

	struct list_head child; // all opened children in this directory
	struct list_head list;	// list to the superblock f_opens;

	struct super_block *sb;

	char name[FILENAME_MAX];
};

struct super_block {
	unsigned char dirty;		/* if the superblock is dirty */
	unsigned char block_size_bits;	/* block size contains how many bits */
	unsigned short block_size;	/* block size */
	size_t max_file;		/* max file count */
	unsigned long flags;		/* flags */
	unsigned long magic;		/* maigic number if has */
	struct partition *partition;	/* partition of this super block */
	struct filesystem *fs;

	/*
	 * cache information for this partition, cache
	 * some fnode and block buffer.
	 */
	struct fnode *root_fnode;	/* root fnode of this partition */
	struct list_head buffer_hash_lists[NR_HASH_LIST];
	struct list_head buffer_free_list;
	struct list_head buffer_lru_list;
};

#define FS_NAME_SIZE 32

struct filesystem {
	char name[FS_NAME_SIZE];
	int (*match)(int type, char *name);
	struct super_block *(*read_super)(struct partition *partition, struct filesystem *fs);
	ssize_t (*read)(struct fnode *fnode, char *buf, size_t size, off_t offset);
	ssize_t (*write)(struct fnode *fnode, char *buf, size_t size, off_t offset);
	int (*lookup)(struct fnode *parent, char *path, struct fnode **fnode);
};

struct vfs_server_ops {
	int (*create)(struct file *file, char *fname);
	struct file *(*open)(struct file *file, char *fname, int mode, int flag);
	ssize_t (*read)(struct file *file, void *buf, size_t size);
	ssize_t (*write)(struct file *file, void *buf, size_t size);
	int (*lseek)(struct file *file, off_t off, int whence);
};

/*
 * a vfs server can be dedicate thread, or running on
 * current thread.
 */
struct vfs_server {
	int epfd;
	struct file root_file;
	struct vfs_server_ops *ops;
	char buf[PAGE_SIZE];
};

int vfs_init(void);

int register_filesystem(struct filesystem *fs);
struct filesystem *lookup_filesystem(unsigned char type);

struct file *vfs_open(struct file *parent, char *path, int flags, int mode);
ssize_t vfs_read(struct file *file, void *buf, size_t size);
ssize_t vfs_write(struct file *file, void *buf, size_t size);

int vfs_read_super(struct partition *part, struct filesystem *fs);

void run_vfs_server(struct vfs_server *vs, int new_thread);

struct vfs_server *create_vfs_server(const char *name,
			struct vfs_server_ops *ops, struct super_block *sb);

#endif
