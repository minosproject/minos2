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
	O_LEVEL = 2
endif

TARGET 	:= libminos.a

CFLAGS	:= -Wall -g -D_XOPEN_SOURCE -D_GNU_SOURCE -march=armv8-a -MD \
	-Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing \
	-fno-common -Werror-implicit-function-declaration -O0 \
	-Wno-format-security -I$(PWD)/include \
	--static

srcdir = .
SRC_DIRS = $(addprefix $(srcdir)/, libfdt tiny_malloc vfs kapi spinlock driver)
BASE_C = $(addsuffix /*.c,$(SRC_DIRS))
BASE_S = $(addsuffix /*.S,$(SRC_DIRS))
SRC_C = $(sort $(wildcard $(BASE_C)))
SRC_S = $(sort $(wildcard $(BASE_S)))

OBJS	:= $(SRC_C:%.c=%.o)
OBJS	+= $(SRC_S:%.S=%.o)

OBJS_D 	:= $(SRC_C:%.c=%.d)
OBJS_D 	+= $(SRC_S:%.S=%.d)

$(TARGET) : $(OBJS)
	$(PROGRESS)
	$(QUIET) $(AR) crv $@ -o $^
	$(QUIET) echo "Build Libminos.a Done ..."

%.o : %.c
	$(PROGRESS)
	$(QUIET) $(CC) $(CFLAGS) -c $< -o $@

%.o : %.S
	$(PROGRESS)
	$(QUIET) $(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

.PHONY: clean distclean

clean:
	$(QUIET) rm -rf $(TARGET) $(OBJS) $(OBJS_D)

distclean: clean
	rm -rf cscope.in.out cscope.out cscope.po.out tags

-include $(OBJS_D)
