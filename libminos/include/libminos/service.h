#ifndef __LIBMINOS_SERVICE_H__
#define __LIBMINOS_SERVICE_H__

int register_service(const char *src, const char *target, int flags, int right);
int unreigster_service(int fd);

#endif
