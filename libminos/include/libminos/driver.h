#ifndef __LIBMINOS_DRIVER_H__
#define __LIBMINOS_DRIVER_H__

#include <stdint.h>

extern int get_mmio_handles(int argc, char **argv, handle_t *handles, int cnt);
extern int get_irq_handles(int argc, char **argv, handle_t *handles, int cnt);
extern int get_dma_handles(int argc, char **argv, handle_t *handles, int cnt);

#endif
