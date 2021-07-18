#ifndef _MINOS_MM_H_
#define _MINOS_MM_H_

#include <minos/list.h>
#include <minos/spinlock.h>
#include <minos/memattr.h>
#include <minos/kmem.h>
#include <minos/memory.h>
#include <minos/page.h>
#include <minos/slab.h>

void mem_init(void);
int umem_init(void);

#endif
