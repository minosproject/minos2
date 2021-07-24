/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
 */

	.global aarch64_svc_call

#include "asm.inc"

func aarch64_svc_call
	mov	x8, x7
	svc	#0
	ldr	x4, [sp]
	stp	x0, x1, [x4, #0]
	stp	x2, x3, [x4, #16]
	ret
endfunc aarch64_svc_call
