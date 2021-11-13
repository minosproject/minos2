#include <sys/wait.h>
#include "syscall.h"

#include <minos/proto.h>

pid_t waitpid(pid_t pid, int *status, int options)
{
	struct proto proto;
	long ret;

	proto.proto_id = PROTO_WAITPID;
	proto.waitpid.pid = pid;
	proto.waitpid.options = options;

	ret = sys_send_proto(0, &proto);
	if (status)
		*status = ret & 0xffff;

	return (pid_t)(ret >> 16);
}
