TARGET		= liblwext4.a
LIB_CFLAGS	= -I./include/lwext4 -DCONFIG_USE_DEFAULT_CFG

SRC_C	= $(wildcard src/*.c)
SRC_C	+= ./ext4_server.c

INSTALL_HEADERS := include/lwext4/ext4_blkdev.h

include $(projtree)/scripts/lib_build.mk
