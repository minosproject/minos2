/*
 * Copyright (C) 2021 Min Le (lemin9538@163.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <misc.h>
#include <sys/mman.h>
#include <sys/epoll.h>

#include <minos/kobject.h>
#include <minos/map.h>
#include <minos/debug.h>
#include <minos/proto.h>

#include "elf.h"

static int nvwa_handle;

extern int elf_init(struct elf_ctx *ctx, FILE *file);
extern int load_process_from_file(void *page, struct elf_ctx *ctx, FILE *file);

struct nvwa_proto {
	char path[FILENAME_MAX];
	uint64_t token;
	int pma_handle;
};

static struct nvwa_proto nvwa_proto;

#define MAPPING_BASE 0x100000000
#define MAPPING_SIZE 0x40000000

static int nvwa_pma_init(int pma_handle, size_t size)
{
	return kobject_ctl(pma_handle, KOBJ_PMA_ADD_PAGES, size >> PAGE_SHIFT);
}

static int unmap_elf_memory(int pma_handle, size_t size)
{
	return sys_unmap(0, pma_handle, MAPPING_BASE, size);
}

static int map_elf_memory(int pma_handle, size_t size, int perm)
{
	return sys_map(0, pma_handle, MAPPING_BASE, size, perm);
}

static int __handle_elf_request(struct nvwa_proto *proto,
		struct proto *elf_proto)
{
	int pma_handle = proto->pma_handle;
	struct elf_ctx ctx;
	FILE *file = NULL;
	int ret;

	if (proto->path[FILENAME_MAX - 1] != 0) {
		ret = -EINVAL;
		goto out;
	}

	file = fopen(proto->path, "r");
	if (!file)
		return -EIO;

	ret = elf_init(&ctx, file);
	if (ret)
		goto out;

	if (ctx.memsz > MAPPING_SIZE) {
		ret = -EINVAL;
		goto out;
	}

	ret = nvwa_pma_init(pma_handle, ctx.memsz);
	if (ret) {
		pr_err("init pma failed\n");
		goto out;
	}

	ret = map_elf_memory(pma_handle, ctx.memsz, KR_RW);
	if (ret)
		goto out;

	ret = load_process_from_file((void *)MAPPING_BASE, &ctx, file);
	unmap_elf_memory(pma_handle, ctx.memsz);
	if (ret)
		goto out;

	elf_proto->elf_info.token = proto->token;
	elf_proto->elf_info.ret_code = 0;
	elf_proto->elf_info.elf_base = ctx.base_load_vbase;
	elf_proto->elf_info.elf_size = ctx.memsz;
	elf_proto->elf_info.entry = ctx.ehdr.e_entry;
out:
	fclose(file);
	kobject_close(pma_handle);

	return ret;
}

static void handle_elf_request(struct nvwa_proto *proto)
{
	struct proto elf_proto;
	int ret;

	/*
	 * after loading the content of the elf, nvwa will return
	 * the elf information and the PMA handle to pangu.
	 */
	ret = __handle_elf_request(proto, &elf_proto);
	if (ret) {
		pr_info("loading elf file %d fail\n", ret);
		memset(&elf_proto, 0, sizeof(struct proto));
		elf_proto.elf_info.ret_code = ret;
		elf_proto.elf_info.token = proto->token;
	}

	elf_proto.proto_id = PROTO_ELF_INFO;
	kobject_write(0, &elf_proto, sizeof(struct proto), NULL, 0, -1);
}

static int nvwa_loop(void)
{
	long token;

	i_am_ok();

	pr_info("nvwa waitting elf load request\n");

	for (; ;) {
		token = kobject_read_simple(nvwa_handle, &nvwa_proto,
				sizeof(struct nvwa_proto), -1);
		if (token < 0) {
			pr_err("read request from pangu failed\n");
			continue;
		}

		kobject_reply_errcode(nvwa_handle, token, 0);
		handle_elf_request(&nvwa_proto);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret;

	printf("\n\nNvWa service start...\n\n");

	ret = get_handles(argc, argv, &nvwa_handle, 1);
	if (ret != 1) {
		pr_err("can not get nvwa handle\n");
		return -EINVAL;
	}

	ret = nvwa_loop();
	if (ret)
		pr_err("nvwa exit with code %d\n", ret);

	return ret;
}
