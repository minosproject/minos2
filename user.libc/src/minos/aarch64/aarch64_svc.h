#ifndef __LIBC_AARCH64_SVC_H__
#define __LIBC_AARCH64_SVC_H__

struct aarch64_svc_res {
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
};

void aarch64_svc_call(unsigned long a0, unsigned long a1, unsigned long a2,
		unsigned long a3, unsigned long a4, unsigned long a5,
		unsigned long a6, unsigned long svc_num_a7,
		struct aarch64_svc_res *res);

#endif
