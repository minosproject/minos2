#ifndef __PANGU_REQUEST_H__
#define __PANGU_REQUEST_H__

struct request_entry {
	int type;
	void *data;
	struct list_head list;
};

enum {
	REQUEST_TYPE_PROCESS = 1,
	REQUEST_TYPE_PROCFS,
	REQUEST_TYPE_MAX,
};

int register_request_entry(int type, int handle, void *data);

#endif
