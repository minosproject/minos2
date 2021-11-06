#ifndef __LIBC_PROCESS_INFO_H__
#define __LIBC_PROCESS_INFO_H__

#include <inttypes.h>
#include <minos/procinfo_uapi.h>

int sys_proccnt(void);
int sys_procinfo_handle(void);
int sys_taskstat_handle(void);

#endif
