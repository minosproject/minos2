ARCH 		?= aarch64
CROSS_COMPILE 	?= aarch64-linux-gnu-

CC 		:= musl-gcc
LD 		:= $(CROSS_COMPILE)ld
OBJ_COPY	:= $(CROSS_COMPILE)objcopy
OBJ_DUMP 	:= $(CROSS_COMPILE)objdump
NM		:= $(CROSS_COMPILE)nm
STRIP		:= $(CROSS_COMPILE)strip

PWD		:= $(shell pwd)

QUIET ?= @

ifeq ($(QUIET),@)
PROGRESS = @echo Compiling $@ ...
endif

ifeq ("$(origin O)", "command line")
	O_LEVEL = $(O)
endif
ifndef O_LEVEL
	O_LEVEL = 0
endif

TARGET 	:= pangu.srv

CFLAGS	:= -Wall -g -D_XOPEN_SOURCE -D_GNU_SOURCE -march=armv8-a -MD \
	-Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing \
	-fno-common -Werror-implicit-function-declaration -O$(O_LEVEL) \
	-Wno-format-security -I$(PWD)/include -I../../libminos/include \
	--static -L../../libminos/ -lminos

src_c	:= src/main.c
src_c	+= src/ramdisk.c
src_c	+= src/bootarg.c
src_c	+= src/of.c
src_c	+= src/elf_ramdisk.c
src_c	+= src/vma.c
src_c	+= src/process.c
src_c	+= src/resource.c

OBJS	:= $(src_c:%.c=%.o)
OBJS	+= $(src_s:%.S=%.o)
OBJS_D	= $(src_c:%.c=%.d)
OBJS_D 	+= $(src_s:%.S=%.d)

$(TARGET) : $(OBJS) $(LDS)
	$(PROGRESS)
	$(QUIET) $(CC) $^ -o $@ $(CFLAGS)
#	$(QUIET) $(STRIP) -s $(TARGET)
	$(QUIET) echo "Build PanGu Done ..."

%.o : %.c
	$(PROGRESS)
	$(QUIET) $(CC) $(CFLAGS) -c $< -o $@

%.o : %.S
	$(PROGRESS)
	$(QUIET) $(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

.PHONY: clean distclean

clean:
	$(QUIET) rm -rf $(TARGET) $(OBJS) $(LDS) $(OBJS_D)

distclean: clean
	rm -rf cscope.in.out cscope.out cscope.po.out tags

-include src/*.d
