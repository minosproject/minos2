#ifndef __PANGU_RESOURCE_H__
#define __PANGU_RESOURCE_H__

#include <stdint.h>

enum {
	RES_TYPE_MMIO,
	RES_TYPE_IRQ,
	RES_TYPE_GPIO,
	RES_TYPE_DMA_CHANNEL,
	RES_TYPE_MAX,
};

struct resource {
	uint16_t type;
	int client;
	int handle;
	unsigned long base;
	unsigned long end;
	struct resource *next;
};

#define RES_DEFAULT_RIGHT	\
	KOBJ_RIGHT_RW | KOBJ_RIGHT_CTL | KOBJ_RIGHT_MMAP

int request_device_resource(const char *name, struct resource **res);

void release_resource(struct resource *head);

#endif
