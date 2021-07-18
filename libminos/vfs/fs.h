#ifndef __LIBMINOS_FS_H__
#define __LIBMINOS_FS_H__

#include <inttypes.h>
#include <minos/compiler.h>

hidden struct filesystem *lookup_filesystem(unsigned char type);

hidden int fs_open(struct super_block *sb, char *path, struct fnode **out);

hidden int fs_read(struct fnode *fnode, char *buf, size_t size, off_t offset);

hidden int fs_write(struct fnode *fnode, char *buf, size_t size, off_t offset);


#endif
