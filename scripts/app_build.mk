ARCH 		?= $(TARGET_ARCH)
CROSS_COMPILE 	?= $(TARGET_CROSS_COMPILE)

ifeq ($(TARGET_APP_CC),)
  CC = musl-gcc
else
  CC = $(TARGET_APP_CC)
endif

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

ifeq ($(BUILD_DEBUG),)
  O_LEVEL=0
else
  O_LEVEL=2
endif

ifeq ($(TARGET),)
  $(error "target is not defined")
endif

ifeq ($(APP_TAG),)
  APP_TAG = $(target)
endif

LINK_LIBS = $(addprefix -l, $(APP_LINK_LIBS))
__LIBS_DEPS = $(addprefix $(TARGET_LIB_DIR)/lib, $(LINK_LIBS))
LIBS_DEPS = $(addsuffix .a, $(__LIBS_DEPS))

CLFAGS	:= $(APP_CFLAGS)

CFLAGS	+= -Wall -g -D_XOPEN_SOURCE -D_GNU_SOURCE -MD \
	-Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing \
	-fno-common -Werror-implicit-function-declaration -O$(O_LEVEL) \
	-Wno-format-security -I$(TARGET_INCLUDE_DIR) \
	--static -L$(TARGET_LIBS_DIR) -D__APP_TAG__=$(APP_TAG) $(LINK_LIBS) \

ifeq ($(ARCH),aarch64)
  CFLAGS += -march=armv8-a
endif

src_c	:= $(APP_SRC_C)
src_s	:= $(APP_SRC_S)

OBJS	:= $(src_c:%.c=%.o)
OBJS	+= $(src_s:%.S=%.o)
OBJS_D	= $(src_c:%.c=%.d)
OBJS_D 	+= $(src_s:%.S=%.d)

$(TARGET) : $(OBJS) $(LIBS_DEPS)
	$(PROGRESS)
	$(QUIET) $(CC) $^ -o $@ $(CFLAGS)
#	$(QUIET) $(STRIP) -s $(TARGET)
	$(QUIET) echo "Build $(TARGET) Done ..."
	$(QUIET) cp $(TARGET) $(OUT_DIR)/$(APP_INSTALL_DIR)/

%.o : %.c
	$(PROGRESS)
	$(QUIET) $(CC) $(CFLAGS) -c $< -o $@

%.o : %.S
	$(PROGRESS)
	$(QUIET) $(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

.PHONY: clean distclean install

clean:
	$(QUIET) rm -rf $(TARGET) $(OBJS) $(LDS) $(OBJS_D)

$(OUT_DIR)/$(APP_INSTALL_DIR)/%: %
	$(TARGET_INSTALL) -D -m 644 $< $@

distclean: clean
	rm -rf cscope.in.out cscope.out cscope.po.out tags

-include $(OBJS_D)
