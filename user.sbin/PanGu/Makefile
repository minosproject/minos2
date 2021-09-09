TARGET 		= pangu.srv
APP_CFLAGS 	= -I./include
APP_LINK_LIBS	= fdt c

APP_SRC_C	:= src/main.c
APP_SRC_C	+= src/pangu.c
APP_SRC_C	+= src/ramdisk.c
APP_SRC_C	+= src/bootarg.c
APP_SRC_C	+= src/of.c
APP_SRC_C	+= src/elf_ramdisk.c
APP_SRC_C	+= src/elf_std.c
APP_SRC_C	+= src/vma.c
APP_SRC_C	+= src/process.c
APP_SRC_C	+= src/procfs.c
APP_SRC_C	+= src/resource.c

APP_INSTALL_DIR = ramdisk/

include $(projtree)/scripts/app.build.mk
