#ifndef __MINOS_PROTO_H__
#define __MINOS_PROTO_H__

enum {
	PROCESS_ACTION_MMAP = 0,
	PROCESS_ACTION_EXEC,
	PROCESS_ACTION_IAM_OK,
	PROCESS_ACTION_MAX,
};

struct process_proto {
	int action;
	union {
		struct {
			void *addr;
			size_t len;
			int prot;
			int flags;
			int fd;
			off_t offset;
		} mmap_args;

		char buf[256];
	};
};

#endif
