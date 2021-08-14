#ifndef __PANGU_REQUEST_H__
#define __PANGU_REQUEST_H__

struct request_entry {
	int type;
	int handle;
	void *data;
	struct list_head list;
};

enum {
	REQUEST_TYPE_PROCESS,
	REQUEST_TYPE_SERVICE_INFO,
	REQUEST_TYPE_PROCESS_INFO,
	REQUEST_TYPE_MAX,
};

struct request_entry *register_request_entry(int type, int handle, void *data);

#endif
