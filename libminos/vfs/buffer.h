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
	unsigned long b_state;			/* state of this buffer */
	char *data;			/* data PAGE_SIZE */

	struct list_head list;		/* link the empty buffer head list */
	struct list_head lru_list;	/* link to lru array */
};

static inline int test_bit(int bit, unsigned long *value)
{
	return !!(*value & (1 << bit));
}

static inline void set_bit(int bit, unsigned long *value)
{
	*value |= (1 << bit);
}

static inline void clear_bit(int bit, unsigned long *value)
{
	*value &= ~(1 << bit);
}

static inline int buffer_uptodate(struct buffer_head * bh)
{
	return test_bit(BH_Uptodate, &bh->b_state);
}

static inline int buffer_dirty(struct buffer_head * bh)
{
	return test_bit(BH_Dirty, &bh->b_state);
}

static inline int buffer_locked(struct buffer_head * bh)
{
	return test_bit(BH_Lock, &bh->b_state);
}

static inline int buffer_req(struct buffer_head * bh)
{
	return test_bit(BH_Req, &bh->b_state);
}

static inline int buffer_touched(struct buffer_head * bh)
{
	return test_bit(BH_Touched, &bh->b_state);
}

static inline int buffer_has_aged(struct buffer_head * bh)
{
	return test_bit(BH_Has_aged, &bh->b_state);
}

static inline int buffer_protected(struct buffer_head * bh)
{
	return test_bit(BH_Protected, &bh->b_state);
}

void buffer_head_init(struct super_block *sb);
struct buffer_head *get_block(struct super_block *sb,
		unsigned long block);

#endif
