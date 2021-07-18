/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
 */

	.global raw_spin_lock
	.global raw_spin_unlock

#include "asm.inc"

func raw_spin_lock
	mov	w2, #1
	sevl
l1:	wfe
l2:	ldaxr	w1, [x0]
	cbnz	w1, l1
	stlxr	w1, w2, [x0]
	cbnz	w1, l1
	ret
endfunc raw_spin_lock

func raw_spin_unlock
	stlr	wzr, [x0]
	ret
endfunc raw_spin_unlock
