PHONY := _all
_all:

ifeq ("$(origin DEBUG)", "command line")
  BUILD_DEBUG = $(DEBUG)
endif
ifndef BUILD_DEBUG
  BUILD_DEBUG = 0
endif

ifeq ($(VERBOSE),1)
  Q =
else
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
TARGET_INSTALL = $(projtree)/tools/install.sh

TARGET_INCLUDE_DIR = $(projtree)/out/include
TARGET_LIBS_DIR = $(projtree)/out/lib
TARGET_OUT_DIR = $(projtree)/out
UAPI_INCLUDE_DIR = $(projtree)/generic/include/

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
MFLAGS		:= --no-print-directory

export TARGET_AS TARGET_LD TARGET_CC TARGET_APP_CC TARGET_CPP TARGET_AR TARGET_NM TARGET_STRIP TARGET_OBJCOPY TARGET_OBJDUMP MAKE TARGET_INCLUDE_DIR TARGET_LIBS_DIR TARGET_INSTALL TARGET_OUT_DIR
export UAPI_INCLUDE_DIR VERBOSE
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

PHONY += libc libs apps kernel

all: apps kernel

libc libs apps kernel: objdirs

apps: libs
	$(Q) set -e;					\
	for i in $(APP_TARGETS); do 			\
		if [ -f $$i/Makefile ]; then		\
			echo "\n---> Compiling App $$i ... \n";	\
			$(MAKE) $(MFLAGS) -C $$i ;		\
			$(MAKE) $(MFLAGS) -C $$i install;	\
		fi					\
	done

libs: libc
	$(Q) set -e;					\
	for i in $(LIB_TARGETS); do 			\
		if [ -f $$i/Makefile ]; then		\
			echo "\n---> Compiling Lib $$i ... \n";	\
			$(MAKE) $(MFLAGS) -C $$i ;		\
			$(MAKE) $(MFLAGS) -C $$i install;	\
		fi					\
	done

libc:
	$(Q) echo "\n--->Build LIBC ... \n"
	$(Q) $(MAKE) $(MFLAGS) -C user.libc -j 16
	$(Q) $(MAKE) $(MFLAGS) -C user.libc install

kernel:
	$(Q) echo "\n--->Build Kernel ... \n"
	$(Q) $(MAKE) $(MFLAGS) -C kernel
	$(Q) $(MAKE) $(MFLAGS) -C kernel dtbs
	$(Q) $(MAKE) $(MFLAGS) -C kernel install

objdirs:
	$(Q) mkdir -p $(srctree)/out
	$(Q) mkdir -p $(srctree)/out/include
	$(Q) mkdir -p $(srctree)/out/lib
	$(Q) mkdir -p $(srctree)/out/ramdisk
	$(Q) mkdir -p $(srctree)/out/rootfs/bin
	$(Q) mkdir -p $(srctree)/out/rootfs/sbin
	$(Q) mkdir -p $(srctree)/out/rootfs/driver
	$(Q) mkdir -p $(srctree)/out/rootfs/etc

PHONY += images ramdisk rootfs prepare clean clean-libs clean-apps

clean-libs:
	$(Q)set -e;					\
	for i in $(LIB_TARGETS); do 			\
		if [ -f $$i/Makefile ]; then		\
			echo "Clean $$i";		\
			$(MAKE) $(MFLAGS) -C $$i clean;	\
		fi					\
	done

clean-apps:
	$(Q)set -e;					\
	for i in $(APP_TARGETS); do 			\
		if [ -f $$i/Makefile ]; then		\
			echo "Clean $$i";		\
			$(MAKE) $(MFLAGS) -C $$i clean;	\
		fi					\
	done

clean: clean-libs clean-apps
	$(Q) echo "Clean libc"
	$(Q) $(MAKE) $(MFLAGS) -C user.libc clean
	$(Q) echo "Clean kernel"
	$(Q) $(MAKE) $(MFLAGS) -C kernel clean
	$(Q) rm -rf out
	$(Q) echo "Clean done ..."

images: ramdisk rootfs kernel

ramdisk: apps
	$(Q) echo "\n--->Packing Ramdisk image ...\n"
	$(Q) tools/make_ramdisk.sh -o out/ramdisk.bin -- out/ramdisk/*

rootfs: apps
	$(Q) echo "\n--->Packing Rootfs image ...\n"
	$(Q)

prepare: objdirs
	$(Q) cd user.libc; ./build.sh $(TARGET_OUT_DIR) $(TARGET_ARCH) $(TARGET_CROSS_COMPILE)
	$(Q) cd kernel; make $(TARGET_PLATFORM)_defconfig

bin/% sbin/% driver/% libs/%:
	$(Q)set -e;					\
	if [ -f user.$@/Makefile ]; then		\
		$(MAKE) $(MFLAGS) -C user.$@;		\
	else						\
		echo "Target user.$@ not found";	\
	fi

.PHONY: $(PHONY)
