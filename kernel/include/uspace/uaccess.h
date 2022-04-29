#ifndef __MINOS_ACCESS_H__
#define __MINOS_ACCESS_H__

#include <minos/compiler.h>
#include <asm/uaccess.h>

struct vspace;

int copy_string_from_user(char *dst, char __user *src, int max);
int __copy_from_user(void *dst, struct vspace *vsrc, void __user *src, size_t size);
int __copy_to_user(struct vspace *vdst, void __user *dst, void *src, size_t size);
int copy_from_user(void *dst, void __user *src, size_t size);
int copy_to_user(void __user *dst, void *src, size_t size);

int copy_user_to_user(struct vspace *vdst, void __user *dst,
		struct vspace *vsrc, void __user *src, size_t size);

int copy_string_from_user_safe(char *dst, char __user *src, size_t max);

#endif
