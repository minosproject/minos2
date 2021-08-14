ARCH 		?= aarch64
CROSS_COMPILE 	?= aarch64-linux-gnu-

CC 		:= musl-gcc
LD 		:= $(CROSS_COMPILE)ld
OBJ_COPY	:= $(CROSS_COMPILE)objcopy
OBJ_DUMP 	:= $(CROSS_COMPILE)objdump
NM		:= $(CROSS_COMPILE)nm
STRIP		:= $(CROSS_COMPILE)strip

PWD		:= $(shell pwd)

QUIET ?=

ifeq ($(QUIET),@)
PROGRESS = @echo Compiling $@ ...
endif

ifeq ("$(origin O)", "command line")
	O_LEVEL = $(O)
endif
ifndef O_LEVEL
	O_LEVEL = 0
endif

TARGET 	:= fuxi.srv

LDS	:= fuxi.ld

CFLAGS	:= -mlittle-endian -Wall -g -D_XOPEN_SOURCE -D_GNU_SOURCE -march=armv8-a -MD \
	-Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing \
	-fno-common -Werror-implicit-function-declaration -O$(O_LEVEL) \
	-Wno-format-security

LDFLAGS := -T $(LDS) --static -nostartfiles -e main

src_c	:= fuxi.c

OBJS	:= $(src_c:%.c=%.o)
OBJS_D	= $(src_c:%.c=%.d)

$(TARGET) : $(OBJS) $(LDS)
	$(PROGRESS)
#	$(QUIET) $(CC) $^ -o $@ $(CFLAGS)
#	$(QUIET) $(STRIP) -s $(TARGET)
#	$(QUIET) $(LD) $(LDFLAGS) -o $(TARGET) $(OBJS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJS)
	$(QUIET) echo "Build FuXi Done ..."

%.o : %.c
	$(PROGRESS)
	$(QUIET) $(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean distclean

clean:
	$(QUIET) rm -rf $(TARGET) $(OBJS) $(OBJS_D)

distclean: clean
	rm -rf cscope.in.out cscope.out cscope.po.out tags

-include *.d
