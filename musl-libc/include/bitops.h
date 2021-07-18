#ifndef _LINUX_BITOPS_H
#define _LINUX_BITOPS_H

#include <inttypes.h>
#include <strings.h>
#include <minos/types.h>

static inline unsigned long __ffs(unsigned long word)
{
	int num = 0;

#if BITS_PER_LONG == 64
	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
#endif
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

static inline unsigned long __fls(unsigned long word)
{
	int num = BITS_PER_LONG - 1;

#if BITS_PER_LONG == 64
	if (!(word & (~0ul << 32))) {
		num -= 32;
		word <<= 32;
	}
#endif
	if (!(word & (~0ul << (BITS_PER_LONG-16)))) {
		num -= 16;
		word <<= 16;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-8)))) {
		num -= 8;
		word <<= 8;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-4)))) {
		num -= 4;
		word <<= 4;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-2)))) {
		num -= 2;
		word <<= 2;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-1))))
		num -= 1;
	return num;
}

static inline int fls(int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

#if BITS_PER_LONG == 32
static inline int fls64(uint64_t x)
{
	__u32 h = x >> 32;
	if (h)
		return fls(h) + 32;
	return fls(x);
}
#elif BITS_PER_LONG == 64
static inline int fls64(uint64_t x)
{
	if (x == 0)
		return 0;
	return __fls(x) + 1;
}
#else
#error BITS_PER_LONG not 32 or 64
#endif

#define ffz(x)  __ffs(~(x))

extern unsigned int sw_hweight8(unsigned int w);
extern unsigned int sw_hweight16(unsigned int w);
extern unsigned int sw_hweight32(unsigned int w);
extern unsigned long sw_hweight64(uint64_t w);

unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset);
unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset);
unsigned long find_next_bit_loop(const unsigned long *addr, unsigned long size,
			    unsigned long offset);
unsigned long find_next_zero_bit_loop(const unsigned long *addr, unsigned long size,
				 unsigned long offset);
unsigned long find_first_bit(const unsigned long *addr, unsigned long size);
unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size);
unsigned long find_last_bit(const unsigned long *addr, unsigned long size);

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

/* same as for_each_set_bit() but use bit as value to start with */
#define for_each_set_bit_from(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

#define for_each_clear_bit(bit, addr, size) \
	for ((bit) = find_first_zero_bit((addr), (size));	\
	     (bit) < (size);					\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

/* same as for_each_clear_bit() but use bit as value to start with */
#define for_each_clear_bit_from(bit, addr, size) \
	for ((bit) = find_next_zero_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

static inline int get_bitmask_order(unsigned int count)
{
	int order;

	order = fls(count);
	return order;
}

static inline int get_count_order(unsigned int count)
{
	int order;

	order = fls(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}

static inline unsigned long hweight_long(unsigned long w)
{
	return sizeof(w) == 4 ? sw_hweight32(w) : sw_hweight64(w);
}

static inline uint64_t rol64(uint64_t word, unsigned int shift)
{
	return (word << shift) | (word >> (64 - shift));
}

static inline uint64_t ror64(uint64_t word, unsigned int shift)
{
	return (word >> shift) | (word << (64 - shift));
}

static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

static inline uint32_t ror32(uint32_t word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}

static inline uint16_t rol16(uint16_t word, unsigned int shift)
{
	return (word << shift) | (word >> (16 - shift));
}

static inline uint16_t ror16(uint16_t word, unsigned int shift)
{
	return (word >> shift) | (word << (16 - shift));
}

static inline uint8_t rol8(uint8_t word, unsigned int shift)
{
	return (word << shift) | (word >> (8 - shift));
}

static inline uint8_t ror8(uint8_t word, unsigned int shift)
{
	return (word >> shift) | (word << (8 - shift));
}

static inline int32_t sign_extend32(uint32_t value, int index)
{
	uint8_t shift = 31 - index;
	return (int32_t)(value << shift) >> shift;
}

static inline int64_t sign_extend64(uint64_t value, int index)
{
	uint8_t shift = 63 - index;
	return (int64_t)(value << shift) >> shift;
}

static inline unsigned fls_long(unsigned long l)
{
	if (sizeof(l) == 4)
		return fls(l);
	return fls64(l);
}

static inline unsigned long __ffs64(uint64_t word)
{
#if BITS_PER_LONG == 32
	if (((uint32_t)word) == 0UL)
		return __ffs((uint32_t)(word >> 32)) + 32;
#elif BITS_PER_LONG != 64
#error BITS_PER_LONG not 32 or 64
#endif
	return __ffs((unsigned long)word);
}

#ifndef set_mask_bits
#define set_mask_bits(ptr, _mask, _bits)	\
({								\
	const typeof(*ptr) mask = (_mask), bits = (_bits);	\
	typeof(*ptr) old, new;					\
								\
	do {							\
		old = ACCESS_ONCE(*ptr);			\
		new = (old & ~mask) | bits;			\
	} while (cmpxchg(ptr, old, new) != old);		\
								\
	new;							\
})
#endif

#ifndef bit_clear_unless
#define bit_clear_unless(ptr, _clear, _test)	\
({								\
	const typeof(*ptr) clear = (_clear), test = (_test);	\
	typeof(*ptr) old, new;					\
								\
	do {							\
		old = ACCESS_ONCE(*ptr);			\
		new = old & ~clear;				\
	} while (!(old & test) &&				\
		 cmpxchg(ptr, old, new) != old);		\
								\
	!(old & test);						\
})
#endif

#ifndef find_last_bit
extern unsigned long find_last_bit(const unsigned long *addr,
				   unsigned long size);
#endif

#endif
