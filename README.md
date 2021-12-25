# Minos2

**Minos2 is a micro-kernel OS for ARMv8-a.**

- [x] Multi-process
- [x] SMP
- [ ] Multi-thread
- [x] Virtual memory management
- [x] Libc (based on musl-libc)
- [x] IPC
- [x] VFS
- [x] Ext4 (based on lwext4)
- [x] Virtio-blk driver
- [x] Qemu
- [x] ARM FVP
- [ ] Virtualization

## Build Minos2

Below command tested on Ubuntu-18.04.

1. Create a working directory

   ```bash
   # mkdir ~/minos2-workspace
   # cd ~/minos2-workspace
   ```

2. Install AARCH64 GCC cross compilation tool (Other GCC version is also work fine)

   ```bash
   # wget https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/aarch64-linux-gnu/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz
   # tar xjf gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu.tar.xz
   # sudo mv gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu /opt
   # echo "export PATH=/opt/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu/bin:$PATH" >> ~/.bashrc
   # source ~/.bashrc
   ```

3. Install device-tree tool

   ```bash
   # sudo apt-get install device-tree-compiler
   ```

4. Download minos2 source code

   ```bash
   # git clone https://github.com/minosproject/minos2.git
   ```

5. Compile minos2

   ```bash
   # make PLATFORM=xxx prepare   	(platform can be fvp or qemu_arm64)
   # make ramdisk					(build kernel, libc, system service, application, ramdisk in out/ directory)
   ```

## Download Virtio-blk image

Minos2 support Qemu and FVP now, and both use virtio-blk disk with Ext4 filesystem as rootfs, this image can be create by qemu-img tool. If you do not want to create it by self, you can download the example one here.

```
virtio-sd.img 链接: https://pan.baidu.com/s/1hMaQT20s7n8HNEZ-BqG7XQ 提取码: 9wyh 
```

## Run Minos2 on Qemu

1. Install qemu-system-aarch64

   ```bash
   # apt install qemu-system-arm
   ```

2. Download and compile u-boot

   ```
   # git clone https://github.com/u-boot/u-boot.git
   ```

   Before compile the U-boot, please apply below patch to support boot minos2.

   ```c
   diff --git a/common/image-fdt.c b/common/image-fdt.c
   index eb552ca207..987817546d 100644
   --- a/common/image-fdt.c
   +++ b/common/image-fdt.c
   @@ -175,6 +175,8 @@ int boot_relocate_fdt(struct lmb *lmb, char **of_flat_tree, ulong *of_size)
           if (fdt_high) {
                   void *desired_addr = (void *)simple_strtoul(fdt_high, NULL, 16);
    
   +               desired_addr = (void *)-1;
   +
                   if (((ulong) desired_addr) == ~0UL) {
                           /* All ones means use fdt in place */
                           of_start = fdt_blob;
   
   ```

   Build u-boot

   ```bash
   # make qemu_arm64_defconfig
   # make -j16 CROSS_COMPILE=aarch64-linux-gnu-
   ```

3. Build Minos

   ```bash
   # make PLATFORM=qemu_arm64 prepare
   # make ramdisk
   ```

4. Copy files to the virtio image (use the image which from the pan.baidu.com as an example)

   Mount the virtio image, please refer to https://unix.stackexchange.com/questions/82314/how-to-find-the-type-of-an-img-file-and-mount-it. There are two partitions in the virtio-sd.img, one is fat16 and other is ext4, please put below file in fat16 partitions.

   ```
   out/kernel.bin out/ramdisk.bin out/qemu-arm64.dtb
   ```

   and put below file in ext4 partiotion

   ```
   # mkdir bin  (create a directory named bin first)
   # cp out/rootfs/bin/ps.app out/rootfs/shell.app to $(virtio_ext_partition)/bin
   ```

5. Run minos2 on Qemu

   ```bash
   # qemu-system-aarch64 -nographic -machine virt -bios u-boot.bin -cpu cortex-a57 -smp 4 -m 2G \
       -drive if=none,file=virtio-sd.img,format=raw,id=hd0 -device virtio-blk-device,drive=hd0
       
   After qemu boot, use below command to boot minos2
   
   # fatload virtio 0:1 0x40000000 kernel.bin;fatload virtio 0:1 0x43c00000 ramdisk.bin;fatload virtio 0:1 0x43e00000 qemu-arm64.dtb;booti 0x40000000 - 0x43e00000
   ```

Below is the boot log for Qemu

```
minle@minle-Z840:~/work/github/u-boot$ qemu-system-aarch64 -nographic -machine virt -bios u-boot.bin -cpu cortex-a57 -smp 4 -m 2G  -drive if=none,file=/home/minle/work/minos-next/fvp_debug/sd.img,format=raw,id=hd0 \
-device virtio-blk-device,drive=hd0


U-Boot 2019.07-rc4-00358-g1f83431f00-dirty (Dec 24 2021 - 15:20:30 +0800)

DRAM:  2 GiB
(virtio_mmio@a003e00): device (2) vendor (554d4551) version (1)
Flash: 128 MiB
*** Warning - bad CRC, using default environment

In:    pl011@9000000
Out:   pl011@9000000
Err:   pl011@9000000
Net:   No ethernet found.
Hit any key to stop autoboot:  0 
=> fatload virtio 0:1 0x40000000 kernel.bin;fatload virtio 0:1 0x43c00000 ramdisk.bin;fatload virtio 0:1 0x43e00000 qemu-arm64.dtb;booti 0x40000000 - 0x43e00000
257656 bytes read in 4 ms (61.4 MiB/s)
695304 bytes read in 1 ms (663.1 MiB/s)
4143 bytes read in 1 ms (4 MiB/s)
## Flattened Device Tree blob at 43e00000
   Booting using the fdt blob at 0x43e00000
   Using Device Tree in place at 0000000043e00000, end 0000000043e0402e

Starting kernel ...

[       0.000000@00 000] NIC Starting Minos AARCH64
[       0.000000@00 000] NIC DTB address [0x43e00000]
[       0.000000@00 000] NIC Minos v0.3.3 unstable
[       0.000000@00 000] NIC memory node address_cells:2 size_cells:2
[       0.000000@00 000] NIC DTB - 0x43e00000 ---> 0x2000
[       0.000000@00 000] NIC MEM: 0x0000000044000000 ---> 0x00000000c0000000 [0x000000007c000000] Normal
[       0.000000@00 000] NIC MEM: 0x0000000040000000 ---> 0x0000000043c00000 [0x0000000003c00000] Kernel
[       0.000000@00 000] NIC MEM: 0x0000000043e02000 ---> 0x0000000044000000 [0x00000000001fe000] Kernel
[       0.000000@00 000] NIC MEM: 0x0000000043e00000 ---> 0x0000000043e02000 [0x0000000000002000] DTB
[       0.000000@00 000] NIC MEM: 0x0000000043c00000 ---> 0x0000000043e00000 [0x0000000000200000] RamDisk
[       0.000000@00 000] NIC kmem [0xffffff804004d000 0xffffff8043c00000]
[       0.000000@00 000] NIC kmem [0xffffff8043e02000 0xffffff8044000000]
[       0.000000@00 000] NIC umem [0x44000000 0xc0000000]
[       0.000000@00 000] NIC slab memory allocator init ...
[       0.000000@00 000] NIC bootargs: bootwait=3 tty=vm0 rootfs=virtio-blk.drv
[       0.000000@00 000] NIC platform : linux,qemu-arm64
[       0.000000@00 000] NIC current EL is 1
[       0.000000@00 000] NIC *** gicv2 init ***
[       0.000000@00 000] NIC gicv2 information: gic_dist_addr=0000000008000000 size=0x10000 gic_cpu_addr=0000000008010000 size=0x10000 gic_hyp_addr=0000000000000000 size=0x0 gic_vcpu_addr=0000000000000000 size=0x0
[       0.000000@00 000] NIC GICv2: 288 lines, 4 cpus (IID 0).
[       0.000000@00 000] WRN not support unmask irq_percpu
[       0.000000@00 000] WRN not support unmask irq_percpu
[       0.000000@00 000] WRN not support unmask irq_percpu
[       0.000000@00 000] WRN not support unmask irq_percpu
[       0.000000@00 000] NIC Register kobject type [5] name [endpoint]
[       0.000000@00 000] NIC Register kobject type [1] name [process]
[       0.000000@00 000] NIC Register kobject type [4] name [pma]
[       0.000000@00 000] NIC Register kobject type [2] name [thread]
[       0.000000@00 000] NIC Register kobject type [9] name [irq]
[       0.000000@00 000] NIC Register kobject type [12] name [poll_hub]
[       0.000000@00 000] NIC Register kobject type [3] name [notify]
[       0.000000@00 000] NIC Register kobject type [13] name [port]
[       0.000000@00 000] NIC    sec_phy_timer  : 29
[       0.000000@00 000] NIC nonsec_phy_timer  : 30
[       0.000000@00 000] NIC       virt_timer  : 27
[       0.000000@00 000] NIC hypervisor_timer  : 26
[      16.687407@00 000] NIC get timer clock freq from reg 62500
[       0.000000@00 000] NIC boot ticks is :0x3e2a8f97
[       0.004660@00 X95] NIC waiting 2 seconds for cpu-1 up
[       0.006231@00 X95] NIC waiting 2 seconds for cpu-2 up
[       0.005760@01 000] NIC cpu-1 is up
[       0.006962@02 000] NIC cpu-2 is up
[       0.007815@00 X95] NIC waiting 2 seconds for cpu-3 up
[       0.008542@03 000] NIC cpu-3 is up
[       0.010513@02 000] NIC current EL is 1
[       0.010518@01 000] NIC current EL is 1
[       0.010652@03 000] NIC current EL is 1
[       0.012897@00 X95] NIC Root service load successfully prepare to run...


PanGu service start...

pangu: dtb     [0x4043e00000 0x4043e02000]
pangu: ramdisk [0x4043c00000 0x4043e00000]
pangu: vmap    [0x1040000000 0x3fc0000000]
pangu: heap    [0x1000000000 0x1010000000]
pangu: sys max proc 4096
pangu: uproc_info 5
pangu: ktask_stat 6
pangu: bootargs: bootwait=3 tty=vm0 rootfs=virtio-blk.drv
pangu: handle send to fuxi.srv [handle@4]
pangu: Start fuxi.srv and waitting ...


FuXi service start...

fuxi: fuxi handle 4
pangu: Get response from fuxi.srv service 4132
fuxi: waitting request
pangu: handle send to nvwa.srv [handle@4]
pangu: Start nvwa.srv and waitting ...


NvWa service start...

pangu: Get response from nvwa.srv service 4132
nvwa: nvwa waitting elf load request
pangu: handle send to chiyou.srv [handle@4,5]
pangu: only support map anon mapping for process
virtio-blk: virtio-dev: legacy mode
virtio-blk: virtio supports unsupported option VIRTIO_BLK_F_SEG_MAX (Maximum number of segments in a request is in seg_max.)
virtio-blk: virtio supports unsupported option VIRTIO_BLK_F_GEOMETRY (Disk-style geometry specified in geometry.)
virtio-blk: virtio supports unsupported option VIRTIO_BLK_F_BLK_SIZE (Block size of disk is in blk_size.)
virtio-blk: virtio supports unsupported option VIRTIO_BLK_F_FLUSH (Cache flush command support.)
virtio-blk: virtio supports unsupported option VIRTIO_BLK_F_TOPOLOGY (Device exports information on optimal I/O alignment.)
virtio-blk: virtio supports unsupported option VIRTIO_BLK_F_CONFIG_WCE (Device can toggle its cache between writeback and writethrough modes.)
virtio-blk: virtio supports unsupported option VIRTIO_F_RING_INDIRECT_DESC (Negotiating this feature indicates that the driver can use descriptors with the VIRTQ_DESC_F_INDIRECT flag set, as described in 2.4.5.3 Indirect Descriptors.)
virtio-blk: virtio supports unsupported option VIRTIO_F_RING_EVENT_IDX (This feature enables the used_event and the avail_event fields as described in 2.4.7 and 2.4.8.)
virtio-blk: virtio-blk: device supports unknown bits 0x1000080 in bank 0
pangu: only support map anon mapping for process
virtio-blk: virtio-blk virtq size 8192
virtio-blk: vd0 capacity : 512MB
ext4_mbr: l: 75   [info]  ext4_mbr_scan
ext4_mbr: l: 96   mbr_part: bootstrap:
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 
00, 00, 00, 00, 00, 00, 00, 00, 9f, 27, 

ext4_mbr: l: 106   mbr_part: 0
ext4_mbr: l: 107   	status: 0x80
ext4_mbr: l: 108   	type 0xe:
ext4_mbr: l: 109   	first_lba: 0x3f
ext4_mbr: l: 110   	sectors: 0x25fc0
ext4_mbr: l: 106   mbr_part: 1
ext4_mbr: l: 107   	status: 0x0
ext4_mbr: l: 108   	type 0x83:
ext4_mbr: l: 109   	first_lba: 0x26000
ext4_mbr: l: 110   	sectors: 0xda000
ext4_mbr: l: 106   mbr_part: 2
ext4_mbr: l: 107   	status: 0x0
ext4_mbr: l: 108   	type 0x0:
ext4_mbr: l: 109   	first_lba: 0x0
ext4_mbr: l: 110   	sectors: 0x0
ext4_mbr: l: 106   mbr_part: 3
ext4_mbr: l: 107   	status: 0x0
ext4_mbr: l: 108   	type 0x0:
ext4_mbr: l: 109   	first_lba: 0x0
ext4_mbr: l: 110   	sectors: 0x0
liblwext4: ext4_mbr_scan:
liblwext4: mbr_entry 0:
liblwext4: 	empty/unknown
liblwext4: mbr_entry 1:
liblwext4: 	offeset: 0x4c00000, 76MB
liblwext4: 	size:    0x1b400000, 436MB
liblwext4: mbr_entry 2:
liblwext4: 	empty/unknown
liblwext4: mbr_entry 3:
liblwext4: 	empty/unknown
ext4_fs: l: 219   [info]  sblock features_incompatible:
ext4_fs: l: 144   filetype
ext4_fs: l: 152   extents
ext4_fs: l: 154   64bit
ext4_fs: l: 158   flex_bg
ext4_fs: l: 222   [info]  sblock features_compatible:
ext4_fs: l: 177   has_journal
ext4_fs: l: 179   ext_attr
ext4_fs: l: 181   resize_inode
ext4_fs: l: 183   dir_index
ext4_fs: l: 225   [info]  sblock features_read_only:
ext4_fs: l: 189   sparse_super
ext4_fs: l: 191   large_file
ext4_fs: l: 195   huge_file
ext4_fs: l: 199   dir_nlink
ext4_fs: l: 201   extra_isize
ext4_fs: l: 207   metadata_csum
liblwext4: ext4 server epfd:10 root_fd:9
pangu: loading init shell.app ...
liblwext4: ext4 server start, waitting for request...
chiyou: rootfs is ready, exit chiyou event loop
pangu: only support map anon mapping for process

 _   _   _   _   _   _
/ \ / \ / \ / \ / \ / \
(M | i | n | o | s | 2 )
\_/ \_/ \_/ \_/ \_/ \_/

  Welcome to Minos2 


minos # help
cd : "change directory"
pwd : "current directory"
clear : "clear the screen"
ls : "list directory"
help : "get help"
exec : "run a application on the filesystem"
exit : "exit the shell"
minos # ls
pangu: only support map anon mapping for process
drw-    c/
total   1
minos # cd c
minos # ls
drw-    ./
drw-    ../
-rw-    kernel.bin 
drw-    bin/
drw-    etc/
drw-    home/
-rw-    ramdisk.bin 
-rw-    qemu-arm64.dtb 
total   8
minos # cd bin
minos # ls
drw-    ./
drw-    ../
-rw-    ps.app 
-rw-    shell.app 
total   4
minos # ps
 PID CMD 
   0 pangu.srv
   1 fuxi.srv
   2 nvwa.srv
   3 chiyou.srv
   4 virtio-blk.drv
   5 /c/bin/shell.app
   6 /c/bin/ps.app
minos # 
```

## Video tutorial

**TBD**