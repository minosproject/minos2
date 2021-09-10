TARGET 		= pangu.srv
APP_CFLAGS 	= -I./include
APP_LINK_LIBS	= fdt vfs

SRC_C	:= src/main.c
SRC_C	+= src/pangu.c
SRC_C	+= src/ramdisk.c
SRC_C	+= src/bootarg.c
SRC_C	+= src/of.c
SRC_C	+= src/elf_ramdisk.c
SRC_C	+= src/elf_std.c
SRC_C	+= src/vma.c
SRC_C	+= src/process.c
SRC_C	+= src/procfs.c
SRC_C	+= src/resource.c

APP_INSTALL_DIR = ramdisk/

include $(projtree)/scripts/app_build.mk
