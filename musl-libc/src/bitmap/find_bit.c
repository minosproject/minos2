#include <bitops.h>
#include <bitmap.h>
#include <sys/param.h>

static unsigned long _find_next_bit(const unsigned long *addr,
		unsigned long nbits, unsigned long start, unsigned long invert)
{
	unsigned long tmp;

	if (!nbits || start >= nbits)
		return nbits;

	tmp = addr[start / BITS_PER_LONG] ^ invert;

	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = round_down(start, BITS_PER_LONG);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / BITS_PER_LONG] ^ invert;
	}

	return MIN(start + __ffs(tmp), nbits);
}

unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset)
{
	return _find_next_bit(addr, size, offset, 0UL);
}

unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset)
{
	return _find_next_bit(addr, size, offset, ~0UL);
}

unsigned long _find_next_bit_loop(const unsigned long *addr, unsigned long size,
				unsigned long offset, unsigned long invert)
{
	unsigned long bit;

loop:
	bit = _find_next_bit(addr, size, offset, invert);
	if (bit >= size) {
		if (offset != 0) {
			offset = 0;
			goto loop;
		}
	}

	return bit;
}

unsigned long find_next_bit_loop(const unsigned long *addr, unsigned long size,
				unsigned long offset)
{
	return _find_next_bit_loop(addr, size, offset, 0UL);
}

unsigned long find_next_zero_bit_loop(const unsigned long *addr, unsigned long size,
				unsigned long offset)
{
	return _find_next_bit_loop(addr, size, offset, ~0UL);
}

unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx])
			return MIN(idx * BITS_PER_LONG + __ffs(addr[idx]), size);
	}

	return size;
}

unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx] != ~0UL)
			return MIN(idx * BITS_PER_LONG + ffz(addr[idx]), size);
	}

	return size;
}

unsigned long find_last_bit(const unsigned long *addr, unsigned long size)
{
	if (size) {
		unsigned long val = BITMAP_LAST_WORD_MASK(size);
		unsigned long idx = (size-1) / BITS_PER_LONG;

		do {
			val &= addr[idx];
			if (val)
				return idx * BITS_PER_LONG + __fls(val);

			val = ~0ul;
		} while (idx--);
	}
	return size;
}
