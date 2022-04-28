/*
 * Copyright (C) 2019 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <minos/minos.h>
#include <minos/of.h>
#include <minos/mm.h>
#include <minos/memory.h>

#define MAX_MEMORY_REGION 16

static struct memory_region memory_regions[MAX_MEMORY_REGION];
static int current_region_id;
LIST_HEAD(mem_list);

struct memory_region *alloc_memory_region(void)
{
	ASSERT(current_region_id < MAX_MEMORY_REGION);
	return &memory_regions[current_region_id++];
}

int add_memory_region(uint64_t base, uint64_t size, int type, int vmid)
{
	phy_addr_t end = base + size - 1;
	phy_addr_t r_base, r_end;
	struct memory_region *region;

	if ((size == 0) || (type >= MEMORY_REGION_TYPE_MAX))
		return -EINVAL;

	/*
	 * need to check whether this region is confilct with
	 * other region
	 */
	list_for_each_entry(region, &mem_list, list) {
		r_base = region->phy_base;
		r_end = r_base + region->size - 1;

		if (!((base > r_end) || (end < r_base))) {
			pr_err("memory region invalid [0x%lx 0x%lx]\n", base, end);
			return -EINVAL;
		}
	}

	region = alloc_memory_region();
	region->phy_base = base;
	region->size = size;
	region->type = type;
	region->vmid = vmid;

	list_add_tail(&mem_list, &region->list);
	pr_info("ADD   MEM: 0x%p [0x%p] 0x%x\n", region->phy_base,
			region->size, region->type);

	return 0;
}

int split_memory_region(uint64_t base, size_t size, int type, int vmid)
{
	phy_addr_t start, end;
	phy_addr_t new_end = base + size;
	struct memory_region *region, *n, *tmp;

	if ((size == 0) || (type >= MEMORY_REGION_TYPE_MAX))
		return -EINVAL;

	pr_info("SPLIT MEM: 0x%p [0x%p] 0x%x\n", base, size, type);

	/*
	 * delete the memory for host, these region
	 * usually for vms
	 */
	list_for_each_entry_safe(region, n, &mem_list, list) {
		start = region->phy_base;
		end = start + region->size;

		if ((base > end) || (base < start) || (new_end > end))
			continue;

		/* just delete this region from the list */
		if ((base == start) && (new_end == end)) {
			region->type = type;
			return 0;
		} else if ((base == start) && (new_end < end)) {
			region->phy_base = new_end;
			region->size -= size;
		} else if ((base > start) && (new_end < end)) {
			/* create a new region for the tail space */
			n = alloc_memory_region();
			n->phy_base = new_end;
			n->size = end - new_end;
			n->type = region->type;
			n->vmid = region->vmid;
			list_add_tail(&mem_list, &n->list);

			region->size = base - start;
		} else if ((base > start) && (end == new_end)) {
			region->size = region->size - size;
		} else {
			pr_warn("incorrect memory region 0x%x 0x%x\n",
					base, size);
			return -EINVAL;
		}

		/* alloc a new memory region for vm memory */
		tmp = alloc_memory_region();
		tmp->phy_base = base;
		tmp->size = size;
		tmp->type = type;
		tmp->vmid = vmid;
		list_add_tail(&mem_list, &tmp->list);

		return 0;
	}

	panic("Found Invalid memory config 0x%p [0x%p]\n", base, size);

	return 0;
}

void dump_memory_info(void)
{
	struct memory_region *region;
	char vm[8];

	char *mem_attr[MEMORY_REGION_TYPE_MAX] = {
		"Normal",
		"RSV",
		"VM",
		"DTB",
		"Kernel",
		"RamDisk",
	};

	list_for_each_entry(region, &mem_list, list) {
		sprintf(vm, "VM%d", region->vmid);
		pr_notice("MEM: 0x%p -> 0x%p [0x%p] %s/%s\n", region->phy_base,
				region->phy_base + region->size,
				region->size, mem_attr[region->type],
				region->vmid == 0 ? "Host" : vm);
	}
}

static void handle_normal_memory_region(struct memory_region *region)
{
	int ret;

	/*
	 * only add the normal memory for user, other memory will used as
	 * other purpose. kernel memeory will use alloc_kernel_mem(), once
	 * the kernel memory is allocated, it will never freed.
	 */
	ret = add_page_section(region->phy_base, region->size, region->type);
	ASSERT(ret == 0)
}

static void map_all_memory(void)
{
	struct memory_region *re;
	int ret;

	pr_notice("map all memory to host space\n");

	for_each_memory_region(re) {
		if (re->type != MEMORY_REGION_TYPE_NORMAL)
			continue;
	
		ret = create_host_mapping(ptov(re->phy_base),
				re->phy_base, re->size,
				VM_RW | VM_NORMAL | VM_HUGE);
		if (ret)
			pr_err("map memory region [0x%lx +0x%lx] failed\n",
					re->phy_base, re->size);
	}
}

static void prepare_memory_region(struct memory_region *re)
{
	size_t left_size, right_size;
	unsigned long start, end, tmp;

	tmp = PAGE_ALIGN(re->phy_base + re->size);
	re->phy_base = PAGE_BALIGN(re->phy_base);
	re->size = tmp - re->phy_base;
	if (re->size == 0)
		return;

	if (IS_BLOCK_ALIGN(re->phy_base) && IS_BLOCK_ALIGN(re->size))
		return;

	start = re->phy_base;
	end = re->phy_base + re->size;

	tmp = BLOCK_ALIGN(end);
	re->phy_base = BLOCK_BALIGN(re->phy_base);
	re->size = tmp - re->phy_base;

	left_size = re->phy_base - start;
	right_size = end - (re->phy_base + re->size);

	/*
	 * add these memory to the kernel.
	 */
	if (left_size)
		add_memory_region(start, left_size, MEMORY_REGION_TYPE_NORMAL, 0);
	if (right_size)
		add_memory_region(re->phy_base + re->size,
				right_size, MEMORY_REGION_TYPE_NORMAL, 0);
}

static inline int in_os_memory_range(unsigned long addr, size_t size)
{
	return IN_RANGE_UNSIGNED(addr, size, minos_start, CONFIG_MINOS_RAM_SIZE);
}

void mem_init(void)
{
	extern void set_ramdisk_address(void *start, void *end);
	extern void slab_init(void);
	extern void kmem_init(void);
	struct memory_region *re, *tmp;
	struct memory_region *kre = NULL;
	size_t kmem_size;

#ifdef CONFIG_DEVICE_TREE
	of_parse_memory_info();
#endif

	/*
	 * if there is no memory information founded then panic
	 * the system.
	 */
	BUG_ON(is_list_empty(&mem_list), "no memory information found\n");

	minos_end = PAGE_BALIGN(minos_end);
	kmem_size = CONFIG_MINOS_RAM_SIZE - (minos_end - minos_start);
	if (kmem_size <= 0)
		panic("kmem: memory layout is wrong after boot\n");

	/*
	 * first handle the kernel memory region, so later, the mapping
	 * function can be used.
	 */
	for_each_memory_region(re) {
		if (re->type != MEMORY_REGION_TYPE_KERNEL)
			continue;

		kre = re;
		if (in_os_memory_range(re->phy_base, re->size))
			add_kmem_section(re);
		else
			panic("Wrong kernel memory section [0x%x 0x%x]\n",
					re->phy_base, re->phy_base + re->size);
		break;
	}
	BUG_ON(kre == NULL, "Wrong memory configuration\n")

	/*
	 * for the normal and dma memory, need to make sure it is BLOCK align
	 * since the page allocater will based BLOCK memory.
	 */
	list_for_each_entry_safe(re, tmp, &mem_list, list) {
		if (re->type == MEMORY_REGION_TYPE_NORMAL)
			prepare_memory_region(re);
	}

	/*
	 * delete the memory region which the size is 0.
	 */
	list_for_each_entry_safe(re, tmp, &mem_list, list) {
		if (re->size == 0)
			list_del(&re->list);
	}

	for_each_memory_region(re) {
		if (re->type == MEMORY_REGION_TYPE_RAMDISK) {
			pr_notice("set ramdisk address 0x%lx 0x%lx\n",
					re->phy_base, re->size);
			set_ramdisk_address((void *)re->phy_base,
					(void *)(re->phy_base + re->size));
		} else if (re->type == MEMORY_REGION_TYPE_NORMAL) {
			handle_normal_memory_region(re);
		}
	}

	slab_init();

	kmem_init();

	dump_memory_info();

	map_all_memory();
}
