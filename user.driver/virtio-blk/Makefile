TARGET 		:= virtio-blk.srv
APP_LINK_LIBS 	:= lwext4 drv
APP_CFLAGS	:= -DCONFIG_USE_DEFAULT_CFG

SRC_C		:= $(wildcard *.c)

APP_INSTALL_DIR := ramdisk

include $(projtree)/scripts/app_build.mk
