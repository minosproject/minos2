/*
 * Copyright (c) 2013 Grzegorz Kostka (kostka.grzegorz@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * - The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/** @addtogroup lwext4
 * @{
 */
/**
 * @file  ext4_blockdev.h
 * @brief Block device module.
 */

#ifndef EXT4_BLKDEV_H_
#define EXT4_BLKDEV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

struct ext4_blockdev;

struct ext4_blockdev_iface {
    /**@brief   Open device function
     * @param   bdev block device.*/
    int (*open)(struct ext4_blockdev *bdev);

    /**@brief   Block read function.
     * @param   bdev block device
     * @param   buf output buffer
     * @param   blk_id block id
     * @param   blk_cnt block count*/
    int (*bread)(struct ext4_blockdev *bdev, void *buf, uint64_t blk_id,
             uint32_t blk_cnt);

    /**@brief   Block write function.
     * @param   buf input buffer
     * @param   blk_id block id
     * @param   blk_cnt block count*/
    int (*bwrite)(struct ext4_blockdev *bdev, const void *buf,
              uint64_t blk_id, uint32_t blk_cnt);

    /**@brief   Close device function.
     * @param   bdev block device.*/
    int (*close)(struct ext4_blockdev *bdev);

    /**@brief   Lock block device. Required in multi partition mode
     *          operations. Not mandatory field.
     * @param   bdev block device.*/
    int (*lock)(struct ext4_blockdev *bdev);

    /**@brief   Unlock block device. Required in multi partition mode
     *          operations. Not mandatory field.
     * @param   bdev block device.*/
    int (*unlock)(struct ext4_blockdev *bdev);

    /**@brief   Block size (bytes): physical*/
    uint32_t ph_bsize;

    /**@brief   Block count: physical*/
    uint64_t ph_bcnt;

    /**@brief   Block size buffer: physical*/
    uint8_t *ph_bbuf;

    /**@brief   Reference counter to block device interface*/
    uint32_t ph_refctr;

    /**@brief   Physical read counter*/
    uint32_t bread_ctr;

    /**@brief   Physical write counter*/
    uint32_t bwrite_ctr;

    /**@brief   User data pointer*/
    void* p_user;
};

/**@brief   Definition of the simple block device.*/
struct ext4_blockdev {
    /**@brief Block device interface*/
    struct ext4_blockdev_iface *bdif;

    /**@brief Offset in bdif. For multi partition mode.*/
    uint64_t part_offset;

    /**@brief Part size in bdif. For multi partition mode.*/
    uint64_t part_size;

    /**@brief   Block cache.*/
    struct ext4_bcache *bc;

    /**@brief   Block size (bytes) logical*/
    uint32_t lg_bsize;

    /**@brief   Block count: logical*/
    uint64_t lg_bcnt;

    /**@brief   Cache write back mode reference counter*/
    uint32_t cache_write_back;

    /**@brief   The filesystem this block device belongs to. */
    struct ext4_fs *fs;

    void *journal;
};

/**@brief   Static initialization of the block device.*/
#define EXT4_BLOCKDEV_STATIC_INSTANCE(__name, __bsize, __bcnt, __open, __bread,\
                      __bwrite, __close, __lock, __unlock)     \
    static uint8_t __name##_ph_bbuf[(__bsize)];                            \
    static struct ext4_blockdev_iface __name##_iface = {                   \
        .open = __open,                                                \
        .bread = __bread,                                              \
        .bwrite = __bwrite,                                            \
        .close = __close,                                              \
        .lock = __lock,                                                \
        .unlock = __unlock,                                            \
        .ph_bsize = __bsize,                                           \
        .ph_bcnt = __bcnt,                                             \
        .ph_bbuf = __name##_ph_bbuf,                                   \
    };                                     \
    static struct ext4_blockdev __name = {                                 \
        .bdif = &__name##_iface,                                       \
        .part_offset = 0,                                              \
        .part_size =  (__bcnt) * (__bsize),                            \
    }

int run_ext4_file_server(struct ext4_blockdev *bdev);

#ifdef __cplusplus
}
#endif

#endif /* EXT4_BLOCKDEV_H_ */

/**
 * @}
 */
