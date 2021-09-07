PHONY := _all
_all:

ifeq ("$(origin DEBUG)", "command line")
  BUILD_DEBUG = $(DEBUG)
endif
ifndef BUILD_DEBUG
  BUILD_DEBUG = 0
endif

ifeq ($(VERBOSE),1)
  quiet =
  Q =
else
  quiet=quiet_
  Q = @
endif

projtree := $(shell pwd)
srctree  := .
src	 := $(srctree)

VPATH	:= $(srctree)

export BUILD_DEBUG srctree projtree

TARGET_ARCH            ?= aarch64
TARGET_CROSS_COMPILE   ?= aarch64-linux-gnu-

# Make variables (CC, etc...)
TARGET_AS	= $(TARGET_CROSS_COMPILE)as
TARGET_LD	= $(TARGET_CROSS_COMPILE)ld
TARGET_CC	= $(TARGET_CROSS_COMPILE)gcc
TARGET_APP_CC	= musl-gcc
TARGET_CPP	= $(TARGET_CC) -E
TARGET_AR	= $(TARGET_CROSS_COMPILE)ar
TARGET_NM	= $(TARGET_CROSS_COMPILE)nm
TARGET_STRIP	= $(TARGET_CROSS_COMPILE)strip
TARGET_OBJCOPY	= $(TARGET_CROSS_COMPILE)objcopy
TARGET_OBJDUMP	= $(TARGET_CROSS_COMPILE)objdump

HOST_LEX	= flex
HOST_YACC	= bison
HOST_AWK	= awk
HOST_PERL	= perl
HOST_PYTHON	= python
HOST_PYTHON2	= python2
HOST_PYTHON3	= python3
HOST_CHECK	= sparse
HOST_CC		= gcc
HOST_AS		= as
HOST_LD		= ld
HOST_CC		= gcc
HOST_APP_CC	= musl-gcc
HOST_CPP	= gcc -E
HOST_AR		= ar
HOST_NM		= nm
HOST_STRIP	= strip
HOST_OBJCOPY	= objcopy
HOST_OBJDUMP	= objdump
MAKE		= make

OUT_DIR := $(projtree)/out

export TARGET_AS TARGET_LD TARGET_CC TARGET_APP_CC TARGET_CPP TARGET_AR TARGET_NM TARGET_STRIP TARGET_OBJCOPY TARGET_OBJDUMP MAKE
export HOST_LEX HOST_YACC HOST_AWK HOST_PERL HOST_PYTHON HOST_PYTHON2 HOST_PYTHON3 HOST_CHECK HOST_CC HOST_AS HOST_LD HOST_CC HOST_APP_CC HOST_CPP HOST_AR HOST_NM HOST_STRIP HOST_OBJCOPY HOST_OBJDUMP

PHONY += all
_all: all

all: libc libs apps kernel

libc libs apps kernel: objdirs

libc:
	$(Q) $(MAKE) -C user.libc
	$(Q)

objdirs:
	$(Q) mkdir -p $(srctree)/out
	$(Q) mkdir -p $(srctree)/out/include
	$(Q) mkdir -p $(srctree)/out/libs
	$(Q) mkdir -p $(srctree)/out/ramdisk
	$(Q) mkdir -p $(srctree)/out/rootfs/bin
	$(Q) mkdir -p $(srctree)/out/rootfs/sbin
	$(Q) mkdir -p $(srctree)/out/rootfs/etc

PHONY += images ramdisk.bin rootfs.img kernel.bin prepare

prepare:
	$(Q) cd user.libc; ./build.sh $(OUT_DIR)
