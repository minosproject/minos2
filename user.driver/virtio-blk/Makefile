TARGET 		:= virtio-blk.drv
APP_LINK_LIBS 	:= lwext4
APP_CFLAGS	:= -DCONFIG_USE_DEFAULT_CFG

SRC_C		:= $(wildcard *.c)

TEXT_START	:= 0x2000000

APP_INSTALL_DIR := ramdisk

include $(projtree)/scripts/app_build.mk
