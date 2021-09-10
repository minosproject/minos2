/*
 * Copyright (c) 2020 - 2021 Min Le (lemin9538@163.com)
 */

#include <stdlib.h>
#include <errno.h>
#include <minos/debug.h>
#include <minos/list.h>
#include <minos/kmalloc.h>

#include <vfs/vfs.h>
#include <vfs/blkdev.h>

#define MBR_SIG_SIZE 2
#define BYTES_PER_RECORD 16
#define MAX_NUM_RECORDS  4

#define MBR_OFFSET 0x1b8
#define DISC_SIG_SIZE 4
#define NULLS_SIZE 2
#define BUFFER_SIZE	\
	DISC_SIG_SIZE + NULLS_SIZE + (BYTES_PER_RECORD * MAX_NUM_RECORDS) + MBR_SIG_SIZE

void print_part_type (unsigned char type)
{
	switch (type) {
	case 01: printf("FAT12"); break;
 	case 04: printf("FAT16<32M"); break;		
 	case 05: printf("Extended"); break;		
	case 06: printf("FAT16"); break;		
	case 07: printf("NTFS"); break;		
	case 0x0B: printf("WIN95 FAT32"); break;		
	case 0x0C: printf("WIN95 FAT32 (LBA)"); break;		
	case 0x0E: printf("WIN95 FAT16 (LBA)"); break;		
	case 0x0F: printf("WIN95 Ext'd (LBA)"); break;		
	case 0x11: printf("Hidden FAT12"); break;		
	case 0x14: printf("Hidden FAT16<32M"); break;		
	case 0x16: printf("Hidden FAT16"); break;		
	case 0x17: printf("Hidden NTFS"); break;		
	case 0x1B: printf("Hidden WIN95 FAT32"); break;		
	case 0x1C: printf("Hidden WIN95 FAT32 (LBA)"); break;		
	case 0x1E: printf("Hidden WIN95 FAT16 (LBA)"); break;		
	case 0x82: printf("Linux Swap"); break;		
	case 0x83: printf("Linux"); break;		
	case 0x85: printf("Linux Ext'd"); break;		
	case 0x86: case 0x87: printf("NTFS Vol. Set"); break;		
	case 0x8E: printf("Linux LVM"); break;		
	case 0x9f: printf("BSD/OS"); break;		
	case 0xa5: printf("FreeBSD"); break;		
	case 0xa6: printf("OpenBSD"); break;		
	case 0xa9: printf("NetBSD"); break;		
	case 0xeb: printf("BeOS fs"); break;		
	case 0xee: printf("EFI GPT"); break;		
	case 0xef: printf("EFI FAT?"); break;
	default: printf("?");
	}
}

void print_human_size (float size)
{
	if (!size) {
		printf("%d", 0);
		return;
	}
	
	char a = 'T';
	if (size < 1024.0) a = 'B'; 
	else if ((size/=1024.0) < 1024.0) a = 'K';
	else if ((size/=1024.0) < 1024.0) a = 'M';
	else if ((size/=1024.0) < 1024.0) a = 'G';
	else size/=1024.0;

	printf("%.1f %c", size, a);
}


static int parse_partition(struct blkdev *bdev,
		char *current_record, unsigned long lba_rel)
{
	unsigned char boot = (unsigned char)current_record[0];
	unsigned char type = (unsigned char)current_record[4];
	unsigned int lba = *(int*)(current_record+8);
	unsigned int sectors = *(int*)(current_record+12);
	struct partition *part;

	if (type == 0x0)
		return -ENOENT;

	if (type == 0x05) {
		pr_warn("Extended Partition Detected - Not Support Yet\n");
		return -EIO;
	}

	pr_info("disk%dp%d:\n", bdev->id, bdev->nrpart);
	pr_info("      boot: %s\n", boot == 0x80 ? "Y" : "N");

	pr_info("filesystem: ");
	print_part_type(type);
	printf("\n");

	if (lba_rel)
		pr_info("       lba: %lx (+%x)\n", lba + lba_rel, lba);
	else 
		pr_info("       lba: %x\n", lba);

	pr_info("      size: ");
	print_human_size((float)((uint64_t)sectors * 0x200));
	printf("\n");

	part = libc_zalloc(sizeof(struct partition));
	if (!part)
		return -ENOMEM;

	bdev->partitions[bdev->nrpart] = part;
	part->partid = bdev->nrpart;
	part->blkdev = bdev;
	part->lba = lba + lba_rel;
	part->type = type;
	bdev->nrpart++;

	return 0;
}

static int __parse_mbr(struct blkdev *bdev, char *buf)
{
	/*
	 * mbr info section only takes up 512 bytes.
	 */
	char *buffer = &buf[MBR_OFFSET];
	char str[16] = { 0 };
	int i;

	if ((buf[510] != 0x55) || (buf[511] != 0xaa))
		return -ENOENT;

	sprintf(str, "%02x%02x%02x%02x", buffer[0],
			buffer[1], buffer[2], buffer[3]);
	pr_info("Disk Signature: %s\n", str);

	for (i = 0; i < MAX_NUM_RECORDS; i++) {
		char *current_record = buffer + DISC_SIG_SIZE +
			NULLS_SIZE + (BYTES_PER_RECORD * i);
		parse_partition(bdev, current_record, 0);
	}

	return 0;
}

int parse_mbr(struct blkdev *bdev)
{
	int ret;
	char *buf;

	buf = get_pages(bdev_sector_pages(bdev, 1));
	if (!buf)
		return -ENOMEM;

	ret = read_blkdev_sectors(bdev, buf, 0, 1);
	if (ret)
		return -EIO;

	ret = __parse_mbr(bdev, buf);

	free_pages(buf);

	return ret;
}
