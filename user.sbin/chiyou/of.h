#ifndef __MINOS_SYS_OF_H__
#define __MINOS_SYS_OF_H__

#include <libfdt/libfdt.h>
#include <minos/list.h>

typedef enum __device_class {
	DT_CLASS_CPU = 0,
	DT_CLASS_MEMORY,
	DT_CLASS_IRQCHIP,
	DT_CLASS_TIMER,
	DT_CLASS_SIMPLE_BUS,
	DT_CLASS_PCI_BUS,
	DT_CLASS_VDEV,
	DT_CLASS_PDEV,
	DT_CLASS_VM,
	DT_CLASS_VMBOX,
	DT_CLASS_VIRQCHIP,
	DT_CLASS_OTHER,
} device_class_t;

#define DEVICE_NODE_F_ROOT		(1 << 0)
#define DEVICE_NODE_F_OF		(1 << 1)

/*
 * data       - the data for all device such as dtb or acpi
 * offset     - node offset
 * name       - the name of the device node
 * compatible - the compatible used to match device
 * parent     - the parent node of device_node
 * child      - child nodes of the device_node
 * sibling    - brother of the device node
 */
struct device_node {
	void *data;
	int offset;
	const char *name;
	const char *compatible;
	struct device_node *parent;
	struct device_node *child;
	struct device_node *sibling;
	struct device_node *next;
	device_class_t class;
	unsigned long flags;
	uint32_t key;
	struct list_head resource_list;
};

#define devnode_name(node)	node->name


typedef fdt16_t of16_t;
typedef fdt32_t of32_t;
typedef fdt64_t of64_t;

#define MAX_DTB_SIZE	(MEM_BLOCK_SIZE)

#define OF_MAX_ADDR_CELLS	4
#define OF_BAD_ADDR		((uint64_t)-1)

typedef void * (*of_iterate_fn)(struct device_node *, void *arg);

extern struct device_node *of_root_node;
extern void *dtb_address;

#define of_node_for_each_child(node, child)	\
	for (child = node->child; child != NULL; child = child->sibling)

static fdt32_t inline cpu_to_of32(uint32_t v)
{
	return cpu_to_fdt32(v);
}

static uint32_t inline of16_to_cpu(of16_t v)
{
	return fdt32_to_cpu((fdt16_t)v);
}

static uint32_t inline of32_to_cpu(of32_t v)
{
	return fdt32_to_cpu((fdt32_t)v);
}

static uint64_t inline of32_to_cpu64(of32_t high, of32_t low)
{
	return ((uint64_t)fdt32_to_cpu((fdt32_t)high) << 32) |
		fdt32_to_cpu((fdt32_t)low);
}

int __of_get_u64_array(void *, int, char *, uint64_t *, int);
int __of_get_u32_array(void *, int, char *, uint32_t *, int);
int __of_get_u16_array(void *, int, char *, uint16_t *, int);
int __of_get_string(void *, int, char *, char *, int);
int __of_get_bool(void *dtb, int node, char *attr);
char *of_get_cmdline(void *dtb);

int of_get_bool(struct device_node *node, char *attr);
void *of_getprop(struct device_node *node, char *attr, int *len);
int of_get_node_by_name(void *data, int pnode, char *str);
const char *__of_get_compatible(void *dtb, int node);
int of_device_match(struct device_node *node, char **comp);

void *of_iterate_all_node_loop(struct device_node *node,
		of_iterate_fn func, void *arg);
void *of_iterate_all_node(struct device_node *node,
		of_iterate_fn func, void *arg);

struct device_node * of_find_node_by_compatible(struct device_node *root, char **comp);

int of_n_addr_cells(struct device_node *node);
int of_n_size_cells(struct device_node *node);
int of_n_interrupt_cells(struct device_node *node);
int of_n_addr_count(struct device_node *node);
int of_data(void *data);

int of_translate_address_index(struct device_node *node,
		uint64_t *address, uint64_t *size, int index);
int of_translate_address(struct device_node *node,
		uint64_t *address, uint64_t *size);

void of_parse_device_tree(void);
void of_release_all_node(struct device_node *node);
void *of_device_node_match(struct device_node *node, void *s, void *e);
int of_get_phandle(struct device_node *node);

struct device_node *
of_find_node_by_name(struct device_node *root, char *name);

int fdt_n_size_cells(void *dtb, int node);
int fdt_n_addr_cells(void *dtb, int node);

static inline int of_get_u64_array(struct device_node *node,
		char *attr, uint64_t *array, int len)
{
	if (!node || !attr || !array)
		return -EINVAL;

	return __of_get_u64_array(node->data, node->offset,
			attr, array, len);
}

static inline int of_get_u32_array(struct device_node *node,
		char *attr, uint32_t *array, int len)
{
	if (!node || !attr || !array)
		return -EINVAL;

	return __of_get_u32_array(node->data, node->offset,
			attr, array, len);
}

static inline int of_get_u16_array(struct device_node *node,
		char *attr, uint16_t *array, int len)
{
	if (!node || !attr || !array)
		return -EINVAL;

	return __of_get_u16_array(node->data, node->offset,
			attr, array, len);
}

static inline int of_get_string(struct device_node *node,
		char *attr, char *str, int len)
{
	if (!node || !attr || !str)
		return -EINVAL;

	return __of_get_string(node->data, node->offset,
			attr, str, len);
}

static int inline device_node_is_root(struct device_node *node)
{
	return (node->parent == NULL);
}

static int inline translate_device_address_index(struct device_node *node,
		uint64_t *base, uint64_t *size, int index)
{
	if (node->flags & DEVICE_NODE_F_OF)
		return of_translate_address_index(node, base, size, index);

	return -EINVAL;
}

static inline int translate_device_address(struct device_node *node,
		uint64_t *base, uint64_t *size)
{
	return translate_device_address_index(node, base, size, 0);
}

int of_get_device_irq_index(struct device_node *node, uint32_t *irq,
		unsigned long *flags, int index);

int of_init(void *base);

#endif
