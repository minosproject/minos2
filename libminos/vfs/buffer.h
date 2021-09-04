#ifndef __LIBMINOS_BUFFER_H__
#define __LIBMINOS_BUFFER_H__

enum {
	BH_Uptodate = 0,
	BH_Dirty,
	BH_Lock,
	BH_Req,
	BH_Touched,
	BH_Has_aged,
	BH_Protected,
	BH_FreeOnIO,
};

struct buffer_head {
	unsigned long b_blocknr;	/* block number */
	unsigned long b_rsector;	/* real sector on disk */
	int b_state;			/* state of this buffer */
	int b_size;
	char *data;			/* data PAGE_SIZE */

	struct list_head hash_list;	/* link to the hash list */
	struct list_head lru_list;	/* link to lru array */
	struct list_head buffer_list;	/* link the empty buffer head list */
};

#endif
