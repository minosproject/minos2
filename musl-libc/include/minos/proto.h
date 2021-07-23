#ifndef __MINOS_PROTO_H__
#define __MINOS_PROTO_H__

enum {
	PROCESS_ACTION_MMAP = 0xed00,
	PROCESS_ACTION_EXEC,
	PROCESS_ACTION_IAM_OK,
}

struct process_proto {
	uint16_t action;
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
