#ifndef __MINOS_MISC_H__
#define __MINOS_MISC_H__

int get_irq_handles(int argc, char **argv, int *handles, int cnt);
int get_mmio_handles(int argc, char **argv, int *handles, int cnt);
int get_dma_handles(int argc, char **argv, int *handles, int cnt);
int get_handles(int argc, char **argv, int *handles, int cnt);

#endif
