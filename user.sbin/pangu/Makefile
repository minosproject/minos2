TARGET 		= pangu.srv
APP_CFLAGS 	= -I./include
APP_LINK_LIBS	= fdt vfs

SRC_C	:= $(wildcard src/*.c)

APP_INSTALL_DIR = ramdisk

TEXT_START := 0x8000000

include $(projtree)/scripts/app_build.mk
