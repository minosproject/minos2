/*
 * Copyright (C) 2020 Min Le (lemin9538@gmail.com)
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
#include <minos/ramdisk.h>
#include <minos/bootarg.h>
#include <minos/proc.h>
#include <minos/elf.h>
#include <minos/sched.h>
#include <uapi/bootdata.h>
#include <minos/memattr.h>
#include <minos/page.h>
#include <asm/arch.h>
#include <minos/vspace.h>
#include <minos/kobject.h>
#include <minos/handle.h>

#include <asm/io.h>

extern struct kobject *uproc_info_pma;
extern struct kobject *ktask_stat_pma;
extern struct process *create_root_process( task_func_t func,
		void *usp, int prio, int aff, unsigned long opt);

struct elf_ctx {
	Elf_Addr base_load_vbase;
	Elf_Addr base_load_vend;
	Elf_Addr memsz;
	Elf_Addr align;
	Elf_Ehdr ehdr;
	Elf_Off  dynoff;
	Elf_Addr dynsize;
};

enum {
	EL_OK         = 0,
	EL_EIO,
    	EL_ENOMEM,
    	EL_NOTELF,
    	EL_WRONGBITS,
    	EL_WRONGENDIAN,
    	EL_WRONGARCH,
    	EL_WRONGOS,
    	EL_NOTEXEC,
    	EL_NODYN,
    	EL_BADREL,
};

typedef struct
{
	uint64_t a_type;              /* Entry type */
	uint64_t a_val;
} Elf64_auxv_t;

/* Symbolic values for the entries in the auxiliary table
   put on the initial stack */
#define AT_NULL   0     /* end of vector */
#define AT_IGNORE 1     /* entry should be ignored */
#define AT_EXECFD 2     /* file descriptor of program */
#define AT_PHDR   3     /* program headers for program */
#define AT_PHENT  4     /* size of program header entry */
#define AT_PHNUM  5     /* number of program headers */
#define AT_PAGESZ 6     /* system page size */
#define AT_BASE   7     /* base address of interpreter */
#define AT_FLAGS  8     /* flags */
#define AT_ENTRY  9     /* entry point of program */
#define AT_NOTELF 10    /* program is not ELF */
#define AT_UID    11    /* real uid */
#define AT_EUID   12    /* effective uid */
#define AT_GID    13    /* real gid */
#define AT_EGID   14    /* effective gid */
#define AT_PLATFORM 15  /* string identifying CPU for optimizations */
#define AT_HWCAP  16    /* arch dependent hints at CPU capabilities */
#define AT_CLKTCK 17    /* frequency at which times() increments */
/* AT_* values 18 through 22 are reserved */
#define AT_SECURE 23   /* secure mode boolean */
#define AT_BASE_PLATFORM 24     /* string identifying real platform, may
                                 * differ from AT_PLATFORM. */
#define AT_RANDOM 25    /* address of 16 random bytes */
#define AT_HWCAP2 26    /* extension of AT_HWCAP */

#define AT_EXECFN  31   /* filename of program */

#define EL_PHOFF(ctx, num) (((ctx)->ehdr.e_phoff + (num) * (ctx)->ehdr.e_phentsize))
#define EL_SHOFF(ctx, num) (((ctx)->ehdr.e_shoff + (num) * (ctx)->ehdr.e_shentsize))

int elf_findphdr(struct ramdisk_file *file, struct elf_ctx *ctx,
		Elf_Phdr *phdr, uint32_t type, unsigned *i)
{
	int rv = EL_OK;

    	for (; *i < ctx->ehdr.e_phnum; (*i)++) {
		rv = ramdisk_read(file, phdr, sizeof(Elf_Phdr), EL_PHOFF(ctx, *i));
		if (rv)
			return rv;
		
		if (phdr->p_type == type)
			return rv;
    	}

    	*i = -1;
    	return rv;
}

int elf_init(struct ramdisk_file *file, struct elf_ctx *ctx)
{
	Elf_Phdr ph;
	int rv = EL_OK;
	unsigned i = 0;

	memset(ctx, 0, sizeof(struct elf_ctx));
	
	if ((rv = ramdisk_read(file, &ctx->ehdr, sizeof(ctx->ehdr), 0)))
		return rv;
	
	if (!IS_ELF(ctx->ehdr))
		return EL_NOTELF;
	
	if (ctx->ehdr.e_ident[EI_CLASS] != ELFCLASS)
	        return EL_WRONGBITS;
	
	if (ctx->ehdr.e_ident[EI_DATA] != ELFDATATHIS)
	        return EL_WRONGENDIAN;
	
	if (ctx->ehdr.e_ident[EI_VERSION] != EV_CURRENT)
	        return EL_NOTELF;
	
	if (ctx->ehdr.e_type != ET_EXEC || ctx->ehdr.e_type == ET_DYN)
	        return EL_NOTEXEC;

	if (ctx->ehdr.e_machine != EM_THIS)
	        return EL_WRONGARCH;
	
	if (ctx->ehdr.e_version != EV_CURRENT)
	        return EL_NOTELF;
	
	/*
	 * calculate how many memory is needed for this elf file, the
	 * memory will allocated together.
	 */
	ctx->base_load_vbase = (unsigned long)-1;

	for(;;) {
		if ((rv = elf_findphdr(file, ctx, &ph, PT_LOAD, &i)))
			return rv;
	
	        if (i == (unsigned) -1)
			break;

		if (ph.p_vaddr < ctx->base_load_vbase)
			ctx->base_load_vbase = ph.p_vaddr;
	
	        Elf_Addr phend = ph.p_vaddr + ph.p_memsz;
	        if (phend > ctx->base_load_vend)
			ctx->base_load_vend = phend;
	
	        if (ph.p_align > ctx->align)
			ctx->align = ph.p_align;
		i++;
	}

	ctx->memsz = PAGE_BALIGN(ctx->base_load_vend - ctx->base_load_vbase);
	
	return rv;
}

static int elf_load_section(struct ramdisk_file *file, void *vaddr, Elf_Shdr *shdr)
{
	/*
	 * bss section ?
	 */
	if (shdr->sh_type == SHT_NOBITS) {
		pr_info("bzero elf section [0x%x 0x%x 0x%x 0x%x]\n",
			shdr->sh_offset, shdr->sh_addr, shdr->sh_size, shdr->sh_type);
		memset(vaddr, 0, shdr->sh_size);
		return 0;
	}

	pr_info("loading elf section [0x%x 0x%x 0x%x]\n",
			shdr->sh_offset, shdr->sh_addr, shdr->sh_size, shdr->sh_type);
	ramdisk_read(file, vaddr, shdr->sh_size, shdr->sh_offset);

	return 0;
}

static int elf_findshdr(struct ramdisk_file *file, struct elf_ctx *ctx,
		Elf_Shdr *shdr, unsigned int *i)
{

	int rv = EL_OK;
	int j = *i;

	for ( ;j < ctx->ehdr.e_shnum; j++) {
		rv = ramdisk_read(file, shdr, sizeof(Elf64_Ehdr), EL_SHOFF(ctx, j));
		if (rv)
			return rv;

		if (shdr->sh_flags & SHF_ALLOC) {
			*i = j;
			return 0;
		}
	}

	*i = -1;
	return rv;
}

int elf_load(struct process *proc, struct ramdisk_file *file, struct elf_ctx *ctx)
{
	int rv = EL_OK;
    	unsigned int i = 0;
	void *page;
	void *vaddr;
	Elf_Shdr shdr;

	page = get_free_pages(ctx->memsz >> PAGE_SHIFT, GFP_USER);
	if (!page)
		return -ENOMEM;

	rv = map_process_memory(proc, ctx->base_load_vbase,
			ctx->memsz, vtop(page), VM_RWX);
	if (rv)
		return rv;

    	for(;;) {
		if ((rv = elf_findshdr(file, ctx, &shdr, &i)))
            		return rv;

        	if (i == (unsigned int)-1)
            		break;

		vaddr = page + (shdr.sh_addr - ctx->base_load_vbase);
		rv = elf_load_section(file, vaddr, &shdr);
        	if (rv)
            		return EL_ENOMEM;
        	i++;
    	}
	
	return rv;
}

long elf_load_process(struct process *proc, struct ramdisk_file *file)
{
	struct elf_ctx ctx;

	if (elf_init(file, &ctx))
		return -EBADF;
	
	if (elf_load(proc, file, &ctx))
		return -EIO;

	return ctx.ehdr.e_entry;
}

static int setup_user_memory_region(struct process *proc, struct bootdata *env)
{
	struct memory_region *region;
	unsigned long flags;
	int ret;

	env->heap_start = SYS_PROC_HEAP_BASE;
	env->heap_end = SYS_PROC_HEAP_END;
	env->vmap_start = SYS_PROC_VMAP_BASE;
	env->vmap_end = SYS_PROC_VMAP_END;

	/*
	 * user memory region will mapped as point to point
	 * to the root service's address space. currently the
	 * dtb memory and the ramdisk memory will mapped to
	 * root service.
	 */
	for_each_memory_region(region) {
		switch (region->flags & MEMORY_REGION_F_MASK) {
		case MEMORY_REGION_F_DTB:
			env->dtb_start = pa2sva(region->phy_base);
			env->dtb_end = pa2sva(region->phy_base + region->size);
			flags = VM_RO;
			break;
		case MEMORY_REGION_F_RAMDISK:
			env->ramdisk_start = pa2sva(region->phy_base);
			env->ramdisk_end = pa2sva(region->phy_base + region->size);
			flags = VM_RO;
			break;
		default:
			continue;
		}

		ret = map_process_memory(proc, pa2sva(region->phy_base),
				region->size, region->phy_base, flags);
		if (ret) {
			pr_err("map memory region for root service failed\n");
			return ret;
		}
	}

	return 0;
}

static int setup_root_service_env(struct process *proc)
{
	int ret = 0;
	struct bootdata *env;

	/*
	 * allocate one page for enve for root service, and
	 * map it to the root service's space address
	 */
	env = get_free_page(GFP_USER);
	if (!env)
		return -ENOMEM;

	memset(env, 0, PAGE_SIZE);
	env->magic = BOOTDATA_MAGIC;
	ret = setup_user_memory_region(proc, env);
	if (ret)
		return ret;

	/*
	 * pass the uproc_info and ktask_stat pma handle to the
	 * root service.
	 */
	env->max_proc = OS_NR_TASKS;
	env->proc_handle= __alloc_handle(proc, &proc->kobj,
			KOBJ_RIGHT_WRITE | KOBJ_RIGHT_CTL);
	env->uproc_info_handle = __alloc_handle(proc, uproc_info_pma,
			KOBJ_RIGHT_RW | KOBJ_RIGHT_MMAP);
	env->ktask_stat_handle = __alloc_handle(proc, ktask_stat_pma,
			KOBJ_RIGHT_READ | KOBJ_RIGHT_MMAP);
	ASSERT(env->proc_handle > 0);
	ASSERT(env->uproc_info_handle > 0);
	ASSERT(env->ktask_stat_handle > 0);

	/*
	 * map env page to a fix memory address
	 */
	ret = map_process_memory(proc, ROOTSRV_BOOTDATA_BASE,
			PAGE_SIZE, vtop(env), VM_RO);

	return ret;
}

#define NEW_AUX_ENT(auxp, type, value)	\
	do {				\
		auxp--;			\
		auxp->a_type = type;	\
		auxp->a_val = value;	\
	} while (0)

static void *setup_auxv(void *top)
{
	Elf64_auxv_t *auxp = (Elf64_auxv_t *)top;

	NEW_AUX_ENT(auxp, AT_NULL, 0);
	NEW_AUX_ENT(auxp, AT_PAGESZ, PAGE_SIZE);
	NEW_AUX_ENT(auxp, AT_HWCAP, 0);		// TBD cpu feature.

	/*
	 * root service will have it own memory management
	 * service, kernel will handle the page fault for
	 * it.
	 */
	NEW_AUX_ENT(auxp, AT_HEAP_BASE, SYS_PROC_HEAP_BASE);
	NEW_AUX_ENT(auxp, AT_HEAP_END, SYS_PROC_HEAP_END);

	return (void *)auxp;
}

static void *set_argv_string(void *top, int i, char **argv,
		char *opt, char *arg)
{
	char buf[256];
	int size;

	if (opt)
		sprintf(buf, "%s=%s", opt, arg);
	else
		sprintf(buf, "%s", arg);

	size = strlen(buf) + 1;
	size = BALIGN(size, sizeof(unsigned long));
	top -= size;
	strcpy((char *)top, buf);
	argv[i] = (char *)top;

	return top;
}

static void *set_argv_uint64(void *top, int i, char **argv,
		char *opt, uint64_t val)
{
	char buf[64];
	sprintf(buf, "0x%x", val);
	return set_argv_string(top, i, argv, opt, buf);
}

static void *setup_envp(void *top)
{
	top -= sizeof(unsigned long);
	*(char **)top = NULL;

	return top;
}

static void *setup_argv(void *top, int argc, char **argv)
{
	char **str = (char **)top;
	int i;

	str--;
	*str = NULL;

	for (i = 0; i < argc; i++) {
		str--;
		*str = argv[i];
	}

	str--;
	*(unsigned long *)str = argc;

	return (void *)str;
}

static int setup_root_service_ustack(struct process *proc)
{
	void *ustack, *origin;
	char *argv[8] = { NULL };
	int ret, i;

	/*
	 * allocate 16KB 4 pages as the user space stack for
	 * the root service.
	 */
	ustack = get_free_pages(ROOTSRV_USTACK_PAGES, GFP_USER);
	if (!ustack)
		return -ENOMEM;

	ret = map_process_memory(proc, ROOTSRV_USTACK_BOTTOM,
			ROOTSRV_USTACK_PAGES * PAGE_SIZE, vtop(ustack), VM_RW);
	if (ret)
		return -ENOMEM;

	ustack += ROOTSRV_USTACK_PAGES << PAGE_SHIFT;
	origin = ustack;

	/*
	 * set the argc and argv for this process.
	 */
	ustack = set_argv_uint64(ustack, 0, argv,
			"bootdata", ROOTSRV_BOOTDATA_BASE);
	ustack = set_argv_string(ustack, 1, argv, NULL, "pangu.srv");

	/*
	 * convert the argv address to user space address.
	 */
	for (i = 0; i < 2; i++)
		argv[i] = (char *)ROOTSRV_USTACK_TOP - ((char *)origin - argv[i]);

	ustack = setup_auxv(ustack);
	ustack = setup_envp(ustack);
	ustack = setup_argv(ustack, 2, argv);
	arch_set_task_user_stack(proc->head, ROOTSRV_USTACK_TOP - (origin - ustack));

	return 0;
}

/*
 * root service will create the first user space
 * process, then response for the memory management
 * for all the task
 */
int load_root_service(void)
{
	int ret;
	long entry;
	struct ramdisk_file file;
	struct process *proc;

	ret = ramdisk_open("pangu.srv", &file);
	if (ret) {
		pr_err("can not find root service pangu.srv\n");
		goto out;
	}

	proc = create_root_process(NULL, NULL, OS_PRIO_SYSTEM, TASK_AFF_ANY,
			TASK_FLAGS_SRV | TASK_FLAGS_NO_AUTO_START);
	ASSERT(proc != NULL);

	entry = elf_load_process(proc, &file);
	if (entry < MIN_ELF_LOAD_BASE) {
		pr_err("load root service elf failed\n");
		goto out;
	}
	arch_set_task_entry_point(proc->head, entry);

	if (setup_root_service_env(proc)) {
		pr_err("setup root service env failed\n");
		goto out;
	}

	ret = setup_root_service_ustack(proc);
	if (ret) {
		pr_err("serup user stack for root service failed\n");
		goto out;
	}

	pr_notice("Root service load successfully prepare to run...\n");

	return wake_up_process(proc);

out:
	panic("load root service fail\n");
	return -EFAULT;
}
