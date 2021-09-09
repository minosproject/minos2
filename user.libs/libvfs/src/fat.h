#ifndef __LIBMINOS_FAT_H__
#define __LIBMINOS_FAT_H__

#include <minos/types.h>

#define FAT12				0
#define FAT16				1
#define FAT32				2

#define FAT_NAME_TYPE_SHORT		0
#define FAT_NAME_TYPE_LONG		1
#define FAT_NAME_TYPE_UNKNOWN		0xff

#define FAT_LONG_NAME_MIN_MATCH_SIZE	6

struct fs_info {
	uint32_t lead_sig;		/* 0 */
	uint32_t struct_sig;		/* 484 */
	uint32_t free_count;		/* 488 */
	uint32_t next_free;		/* 492 */
};

struct fat32_extra {
	uint32_t fat32_sec_cnt;
	uint16_t fat32_ext_flag;
	uint16_t fs_ver;
	uint32_t root_clus;
	uint16_t fs_info;
	uint16_t boot_sec;
	char res[12];
	uint8_t drv_num;
	uint8_t res1;
	uint8_t boot_sig;
	uint32_t vol_id;
	char vol_lab[11];
	char file_system[8];		/* fat12 or fat16 or fat32 */
};

struct fat16_extra {
	uint8_t drv_num;
	uint8_t res;
	uint8_t boot_sig;
	uint32_t vol_id;
	char vol_lab[11];
	char file_system[8];		/* fat12 or fat16 or fat32 */
};

struct fat_super_block {
	struct super_block sb;
	uint8_t jmp[3];
	char oem_name[8];
	uint16_t byts_per_sec;
	uint8_t sec_per_clus;
	uint16_t res_sec_cnt;
	uint8_t fat_num;
	uint16_t root_ent_cnt;
	uint16_t total_sec16;
	uint8_t media;
	uint16_t fat16_sec_size;
	uint16_t sec_per_trk;
	uint16_t num_heads;
	uint32_t hide_sec;
	uint32_t total_sec32;
	union _fat_extra {
		struct fat32_extra fat32;
		struct fat16_extra fat16;
	} fat_extra;

	/* to be done */
	struct fs_info info;

	uint32_t clus_size;		/* bytes_per_sec * sec_per_clus */
	uint32_t first_data_sector;
	uint32_t total_sec;
	uint16_t fat_size;
	uint32_t data_sec;
	uint32_t clus_count;
	uint8_t fat_type;
	uint8_t fat_offset;
	uint32_t root_dir_sectors;
	uint16_t dentry_per_block;
	uint16_t root_dir_start_sector;
	uint16_t fat12_16_root_dir_blk;
};

struct fat_fnode {
	struct fnode fnode;
	uint32_t first_clus;
	uint32_t first_sector;
	uint32_t prev_clus;
	uint32_t prev_sector;
	uint32_t current_clus;
	uint32_t current_sector;
	uint32_t file_entry_clus;		/* information of the file entry */
	uint16_t file_entry_pos;
};

struct fat_dir_entry {
	char name[8];		/* name[0] = 0xe5 the dir is empty */
	char externed[3];
	uint8_t dir_attr;
	uint8_t nt_res;
	uint8_t crt_time_teenth;
	uint16_t crt_time;
	uint16_t crt_date;
	uint16_t last_acc_date;
	uint16_t fst_cls_high;
	uint16_t write_time;
	uint16_t write_date;
	uint16_t fst_cls_low;
	uint32_t file_size;
} __attribute__((packed));

struct fat_long_dir_entry {
	uint8_t attr;
	uint16_t name1[5];
	uint8_t dir_attr;
	uint8_t res;
	uint8_t check_sum;
	uint16_t name2[6];
	uint16_t file_start_clus;
	uint16_t name3[2];
}__attribute__((packed));

struct fat_name {
	char short_name[11];
	char is_long;
	uint16_t *long_name;
};

#define FIRST_DATA_BLOCK	2

#define FAT_ATTR_READ_ONLY	0x01
#define FAT_ATTR_HIDDEN		0x02
#define FAT_ATTR_SYSTEM		0X04
#define FAT_ATTR_VOLUME_ID	0x08
#define FAT_ATTR_DIRECTORY	0x10
#define FAT_ATTR_ARCHIVE	0x20

#define FAT_ATTR_LONG_NAME	\
	(FAT_ATTR_READ_ONLY | FAT_ATTR_HIDDEN | \
	FAT_ATTR_SYSTEM | FAT_ATTR_VOLUME_ID)

#define FAT_ATTR_LONG_NAME_MASK	\
	(FAT_ATTR_LONG_NAME | FAT_ATTR_DIRECTORY | FAT_ATTR_ARCHIVE)

#define FAT_SB(_sb) container_of(_sb, struct fat_super_block, sb)
#define FAT_FNODE(node) container_of(node, struct fat_fnode, fnode)

#endif
