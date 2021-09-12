#ifndef __LIBC_SERVICE_H__
#define __LIBC_SERVICE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define SRV_NONE 0
#define SRV_DIR 1
#define SRV_PORT 2
#define SRV_NOTIFY 3
#define SRV_REMOTE 4

int register_service(const char *src, const char *target, int type, int flags);

int unregister_service(int fd);

#ifdef __cplusplus
}
#endif

#endif
