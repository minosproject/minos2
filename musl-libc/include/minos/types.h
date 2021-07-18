#ifndef __LIBMINOS_TYPES_H__
#define __LIBMINOS_TYPES_H__

#include <stdint.h>
#include <inttypes.h>

#define BIT(n)	(1UL << (n))

#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)

#define container_of(ptr, name, member) \
	(name *)((unsigned char *)ptr - ((unsigned char *)&(((name *)0)->member)))

#undef PAGE_SIZE
#define PAGE_SIZE	(4096)

#undef PAGE_SHIFT
#define PAGE_SHIFT	(12)

#undef PAGE_MASK
#define PAGE_MASK	(0xfffUL)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define BITS_PER_BYTE		(8)

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define DECLARE_BITMAP(name, bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

#define BITMAP_SIZE(size)	(BITS_TO_LONGS((size)) * sizeof(long))

#define BITS_PER_LONG		64
#define BIT_ULL(nr)		(1ULL << (nr))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)	(1ULL << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)

#define __round_mask(x, y) 	((__typeof__(x))((y)-1))
#define round_up(x, y) 		((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) 	((x) & ~__round_mask(x, y))

#define IS_ALIGN_PO2(n)	(((unsigned long)(n) & (unsigned long)(-(n))) == n)

#define ALIGN(x, y)	((x) & ~__round_mask(x, y))
#define BALIGN(x, y)	(((x) + (y) - 1) & ~__round_mask(x, y))

#define PAGE_BALIGN(x)	BALIGN((unsigned long)(x), PAGE_SIZE)
#define PAGE_ALIGN(x)	ALIGN((unsigned long)(x), PAGE_SIZE)

#define IS_PAGE_ALIGN(x)	(!((unsigned long)(x) & (PAGE_SIZE - 1)))
#define IS_BLOCK_ALIGN(x)	(!((unsigned long)(x) & (0x1fffff)))

#define PAGE_NR(size)	(PAGE_BALIGN(size) >> PAGE_SHIFT)

#define u8_to_u16(low, high)	(((uint16_t)(high) << 8) | (uint16_t)(low))
#define u8_to_u32(u1, u2, u3, u4)	\
	(((uint32_t)(u4) << 24) | ((uint32_t)(u3) << 16) | ((uint32_t)(u2) << 8) | (uint32_t)(u1))
#define u16_to_u32(low, high)	(((uint32_t)(high) << 16) | (uint32_t)(low))

#endif
