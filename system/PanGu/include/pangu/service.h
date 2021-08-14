#ifndef __PANGU_SERVICE_H__
#define __PANGU_SERVICE_H__

#define SERVICENAME_MAX	32

struct service {
	int mutil_client;
	int handle;
	int right;
	struct list_head list;
	struct process *proc;
	char name[SERVICENAME_MAX];
};

int process_register_service(struct process *proc, char *name,
		struct proto_register_srv *proto);

int process_connect_service(struct process *proc, char *name,
		struct proto_connect_srv *proto);

int process_unregister_service(struct process *proc, char *name);

#endif
