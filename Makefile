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

ARCH		?= aarch64
CROSS_COMPILE	?= aarch64-linux-gnu-
PLATFORM	?= fvp

TARGET_ARCH            	= $(ARCH)
TARGET_CROSS_COMPILE   	= $(CROSS_COMPILE)
TARGET_PLATFORM 	= $(PLATFORM)

# Make variables (CC, etc...)
TARGET_AS	= $(TARGET_CROSS_COMPILE)as
TARGET_LD	= $(TARGET_CROSS_COMPILE)ld
TARGET_CC	= $(TARGET_CROSS_COMPILE)gcc
TARGET_APP_CC	= $(projtree)/out/bin/musl-gcc
TARGET_CPP	= $(TARGET_CC) -E
TARGET_AR	= $(TARGET_CROSS_COMPILE)ar
TARGET_NM	= $(TARGET_CROSS_COMPILE)nm
TARGET_STRIP	= $(TARGET_CROSS_COMPILE)strip
TARGET_OBJCOPY	= $(TARGET_CROSS_COMPILE)objcopy
TARGET_OBJDUMP	= $(TARGET_CROSS_COMPILE)objdump
TARGET_INCLUDE_DIR = $(projtree)/out/include
TARGET_LIBS_DIR = $(projtree)/out/lib
TARGET_INSTALL = $(projtree)/out/bin/install.sh

TARGET_OUT_DIR = $(projtree)/out

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
HOST_CPP	= gcc -E
HOST_AR		= ar
HOST_NM		= nm
HOST_STRIP	= strip
HOST_OBJCOPY	= objcopy
HOST_OBJDUMP	= objdump
MAKE		= make

OUT_DIR := $(projtree)/out

export TARGET_AS TARGET_LD TARGET_CC TARGET_APP_CC TARGET_CPP TARGET_AR TARGET_NM TARGET_STRIP TARGET_OBJCOPY TARGET_OBJDUMP MAKE TARGET_INCLUDE_DIR TARGET_LIBS_DIR TARGET_INSTALL TARGET_OUT_DIR
export HOST_LEX HOST_YACC HOST_AWK HOST_PERL HOST_PYTHON HOST_PYTHON2 HOST_PYTHON3 HOST_CHECK HOST_CC HOST_AS HOST_LD HOST_CC HOST_APP_CC HOST_CPP HOST_AR HOST_NM HOST_STRIP HOST_OBJCOPY HOST_OBJDUMP

LIB_DIRS := user.libs
APP_DIRS := user.sbin user.bin user.driver

# get all the libs folder under LIB_DIRS
LIB_SUB_DIRS = $(foreach dir, $(LIB_DIRS), $(shell find $(dir) -maxdepth 1 -type d))
LIB_TARGETS = $(filter-out $(LIB_DIRS),$(LIB_SUB_DIRS))

# get the all application folders under APP_DIRS
APP_SUB_DIRS = $(foreach dir, $(APP_DIRS), $(shell find $(dir) -maxdepth 1 -type d))
APP_TARGETS = $(filter-out $(APP_DIRS),$(APP_SUB_DIRS))

PHONY += all
_all: all

all: libc libs apps kernel

libc libs apps kernel: objdirs

apps: libs
	$(Q) set -e;					\
	for i in $(APP_TARGETS); do 			\
		echo "Compiling libary $$i";		\
		$(MAKE) -w -C $$i ;			\
		$(MAKE) -w -C $$i install;		\
	done

libs: libc
	$(Q) set -e;					\
	for i in $(LIB_TARGETS); do 			\
		echo "Compiling libary $$i";		\
		$(MAKE) -w -C $$i ;			\
		$(MAKE) -w -C $$i install;		\
	done

libc:
	$(Q) $(MAKE) -C user.libc -j 16
	$(Q) $(MAKE) -C user.libc install

kernel:
	$(Q) $(MAKE) -w -C kernel
	$(Q) $(MAKE) -w -C kernel install

objdirs:
	$(Q) mkdir -p $(srctree)/out
	$(Q) mkdir -p $(srctree)/out/include
	$(Q) mkdir -p $(srctree)/out/libs
	$(Q) mkdir -p $(srctree)/out/ramdisk
	$(Q) mkdir -p $(srctree)/out/rootfs/bin
	$(Q) mkdir -p $(srctree)/out/rootfs/sbin
	$(Q) mkdir -p $(srctree)/out/rootfs/driver
	$(Q) mkdir -p $(srctree)/out/rootfs/etc

PHONY += images ramdisk rootfs prepare

images: ramdisk rootfs

ramdisk: apps

rootfs: apps

prepare:
	$(Q) cd user.libc; ./build.sh $(OUT_DIR) $(TARGET_ARCH) $(TARGET_CROSS_COMPILE)
	$(Q) cd kernel; make $(TARGET_PLATFORM)_defconfig
