#ifndef __ASM_UACCESS_H__
#define __ASM_UACCESS_H__

#include <asm/asm_types.h>
#include <minos/compiler.h>

static inline unsigned long user_ranges_ok(const void __user *addr, unsigned long size)
{
	unsigned long ret, limit = USER_PROCESS_ADDR_LIMIT;

	asm volatile(
	// A + B <= C + 1 for all A,B,C, in four easy steps:
	// 1: X = A + B; X' = X % 2^64
	"	adds	%0, %3, %2\n"
	// 2: Set C = 0 if X > 2^64, to guarantee X' > C in step 4
	"	csel	%1, xzr, %1, hi\n"
	// 3: Set X' = ~0 if X >= 2^64. For X == 2^64, this decrements X'
	//    to compensate for the carry flag being set in step 4. For
	//    X > 2^64, X' merely has to remain nonzero, which it does.
	"	csinv	%0, %0, xzr, cc\n"
	// 4: For X < 2^64, this gives us X' - C - 1 <= 0, where the -1
	//    comes from the carry in being clear. Otherwise, we are
	//    testing X' - C == 0, subject to the previous adjustments.
	"	sbcs	xzr, %0, %1\n"
	"	cset	%0, ls\n"
	: "=&r" (ret), "+r" (limit) : "Ir" (size), "0" (addr) : "cc");

	return ret;
}

#endif
