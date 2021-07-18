#ifndef __MINOS_VIRT_VMM_H__
#define __MINOS_VIRT_VMM_H__

#include <minos/types.h>
#include <minos/mm.h>
#include <minos/vspace.h>
#include <virt/vm_mmap.h>

struct vm;

int vm_mm_init(struct vm *vm);
void vm_vspace_init(struct vm *vm);

int create_guest_mapping(struct vspace *vs, vir_addr_t vir,
		phy_addr_t phy, size_t size, unsigned long flags);

int destroy_guest_mapping(struct vspace *vs,
		unsigned long vir, size_t size);

int map_vm_memory(struct vm *vm, unsigned long vir_base,
		unsigned long phy_base, size_t size, int type);
int unmap_vm_memory(struct vm *vm, unsigned long vir_addr,
			size_t size, int type);

int alloc_vm_memory(struct vm *vm);
void release_vm_memory(struct vm *vm);

struct vspace_area *vm_mmap(struct vm *vm, unsigned long offset,
		unsigned long size);

unsigned long create_hvm_iomem_map(struct vm *vm, unsigned long gbase,
		uint32_t size, unsigned long gflags);

void destroy_hvm_iomem_map(unsigned long vir, uint32_t size);
int create_early_pmd_mapping(unsigned long vir, unsigned long phy);

void *map_vm_mem(unsigned long gva, size_t size);
void unmap_vm_mem(unsigned long gva, size_t size);

int map_vspace_area(struct vspace *vs, struct vspace_area *va,
		unsigned long pbase);

phy_addr_t translate_vm_address(struct vm *vm, unsigned long a);

#endif
