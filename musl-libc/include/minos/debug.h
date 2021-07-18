#ifndef __MINOS_SYS_PRINT_H__
#define __MINOS_SYS_PRINT_H__

#include <stdio.h>

#define __pr_debug(...)					\
	do {						\
		printf("[DEBUG] " __VA_ARGS__);		\
	} while (0)

#ifdef __DEBUG__
#define pr_debug(...)	__pr_debug(__VA_ARGS__)
#else
#define pr_debug(...)
#endif

#define pr_err(...)					\
	do {						\
		printf("[ERROR] " __VA_ARGS__);		\
	} while (0)

#define pr_notice(...)					\
	do {						\
		printf("[NIC  ] " __VA_ARGS__);		\
	} while (0)

#define pr_info(...)					\
	do {						\
		printf("[INFO ] " __VA_ARGS__);		\
	} while (0)

#define pr_warn(...)					\
	do {						\
		printf("[WARN ] " __VA_ARGS__);		\
	} while (0)

#endif
