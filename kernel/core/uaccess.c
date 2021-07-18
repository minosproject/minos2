/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <minos/minos.h>

int copy_string_from_user(char *dst, char __user *src, int max)
{
	int offset = (unsigned long)src - PAGE_ALIGN(src);
	int copy_size, left = max, copied = 0;
	char *ksrc;

	while (left) {
		copy_size = PAGE_SIZE - offset;
		copy_size = copy_size > left ? left : copy_size;

		ksrc = (void *)arch_translate_va_to_pa(&current->proc->vspace,
				(unsigned long)src);
		if ((phy_addr_t)ksrc == INVALID_ADDR)
			return -EFAULT;

		ksrc = (char *)ptov(ksrc);
		while (copy_size > 0) {
			*dst = *ksrc;
			copied++;

			if (*ksrc == 0)
				return copied;

			dst++;
			ksrc++;
			copy_size--;
		}

		offset = 0;
		left -= copy_size;
		src += copy_size;
		dst += copy_size;
	}

	return copied;
}

int __copy_from_user(void *dst, struct vspace *vsrc, void __user *src, size_t size)
{
	int offset = (unsigned long)src - PAGE_ALIGN(src);
	int copy_size;
	size_t cnt = size;
	void *ksrc;

	while (size > 0) {
		copy_size = PAGE_SIZE - offset;
		copy_size = copy_size > size ? size : copy_size;

		ksrc = (void *)arch_translate_va_to_pa(vsrc, (unsigned long)src);
		if ((phy_addr_t)ksrc == INVALID_ADDR)
			return -EFAULT;

		ksrc = (char *)ptov(ksrc);
		memcpy(dst, ksrc, copy_size);
		offset = 0;
		size -= copy_size;
		src += copy_size;
		dst += copy_size;
	}

	return cnt;
}

int __copy_to_user(struct vspace *vdst, void __user *dst, void *src, size_t size)
{
	int offset = (unsigned long)dst - PAGE_ALIGN(dst);
	int copy_size;
	size_t cnt = size;
	void *kdst;

	while (size > 0) {
		copy_size = PAGE_SIZE - offset;
		copy_size = copy_size > size ? size : copy_size;

		kdst = (void *)arch_translate_va_to_pa(vdst, (unsigned long)dst);
		if ((phy_addr_t)kdst == INVALID_ADDR)
			return -EFAULT;

		memcpy(kdst, src, copy_size);
		offset = 0;
		size -= copy_size;
		src += copy_size;
		dst += copy_size;
	}

	return cnt;
}

int copy_from_user(void *dst, void __user *src, size_t size)
{
	return __copy_from_user(dst, &current->proc->vspace, src, size);
}

int copy_to_user(void __user *dst, void *src, size_t size)
{
	return __copy_to_user(&current->proc->vspace, dst, src, size);
}

int copy_user_to_user(struct vspace *vdst, void __user *dst,
		struct vspace *vsrc, void __user *src, size_t size)
{
	int dst_offset = (unsigned long)dst - PAGE_ALIGN(dst);
	int copy_size, ret;
	size_t cnt = size;
	void *kdst;

	while (size > 0) {
		copy_size = PAGE_SIZE - dst_offset;
		copy_size = copy_size > size ? size : copy_size;

		kdst = (void *)arch_translate_va_to_pa(vdst, (unsigned long)dst);
		if ((phy_addr_t)kdst == INVALID_ADDR)
			return -EFAULT;

		ret = __copy_from_user(kdst, vsrc, src, copy_size);
		if (ret)
			return ret;

		size -= copy_size;
		src += copy_size;
		dst += copy_size;
	}

	return cnt;
}

int copy_string_from_user_safe(char *dst, char __user *src, size_t max)
{
	int ret;

	ret = copy_string_from_user(dst, src, max - 1);
	if (ret <= 0)
		return -E2BIG;
	dst[ret] = 0;

	return ret;
}
