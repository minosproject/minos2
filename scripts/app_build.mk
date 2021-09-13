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

ifeq ($(VERBOSE),1)
  QUIET =
else
  QUIET = @
endif

ifeq ($(QUIET),@)
PROGRESS = @echo Compiling $@ ...
endif

ifeq ($(BUILD_DEBUG), 1)
  O_LEVEL=0
else
  O_LEVEL=2
endif

ifeq ($(TARGET),)
  $(error "target is not defined")
endif

ifeq ($(APP_TAG),)
  APP_TAG = $(TARGET)
endif

DBG_TAG = $(basename $(APP_TAG))

ifeq ($(APP_INSTALL_DIR),)
  APP_INSTALL_DIR := $(TARGET_OUT_DIR/rootfs/bin)
endif

LINK_LIBS = $(addprefix -l, $(APP_LINK_LIBS))
__LIBS_DEPS = $(addprefix $(TARGET_LIBS_DIR)/lib, $(APP_LINK_LIBS))
LIBS_DEPS = $(addsuffix .a, $(__LIBS_DEPS))
LIBS_DEPS += $(TARGET_LIBS_DIR)/libc.a

CFLAGS := -Wall -g -D_XOPEN_SOURCE -D_GNU_SOURCE \
	-Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing \
	-fno-common -Werror-implicit-function-declaration -O$(O_LEVEL) \
	-Wno-format-security -I$(TARGET_INCLUDE_DIR) -I$(UAPI_INCLUDE_DIR)

LDFLAGS :=
LDFLAGS += $(APP_LDFLAGS)

CFLAGS	+= --static -L$(TARGET_LIBS_DIR) -DAPP_TAG=\"$(DBG_TAG)\" $(LINK_LIBS)
CFLAGS	+= $(APP_CFLAGS)
CFLAGS  += -MD -MP

ifeq ($(BUILD_DEBUG),1)
  CFLAGS += -g
endif

ifeq ($(ARCH),aarch64)
  CFLAGS += -march=armv8-a
endif

src_c	:= $(SRC_C)
src_s	:= $(SRC_S)

OBJS	:= $(src_c:%.c=%.o)
OBJS	+= $(src_s:%.S=%.o)

OBJS_D	= $(OBJS:%.o=%.d)

ifeq (S(BUILD_DEBUG),1)
$(TARGET) : $(OBJS) $(LIBS_DEPS)
	$(PROGRESS)
	$(QUIET) $(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS)
	$(QUIET) $(STRIP) -s $(TARGET)
	$(QUIET) echo "Build $(TARGET) Done ..."
else
$(TARGET) : $(OBJS) $(LIBS_DEPS)
	$(PROGRESS)
	$(QUIET) $(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS)
	$(QUIET) echo "Build $(TARGET) Done ..."
endif

%.o : %.c
	$(PROGRESS)
	$(QUIET) $(CC) $(CFLAGS) -c $< -o $@

%.o : %.S
	$(PROGRESS)
	$(QUIET) $(CC) $(CFLAGS) -D__ASSEMBLY__ -c $< -o $@

.PHONY: clean distclean install

$(TARGET_OUT_DIR)/$(APP_INSTALL_DIR)/%: %
	$(TARGET_INSTALL) -D -m 644 $< $@

install: $(TARGET_OUT_DIR)/$(APP_INSTALL_DIR)/$(TARGET)

clean:
	$(QUIET) rm -rf $(TARGET) $(OBJS) $(LDS) $(OBJS_D)

distclean: clean
	rm -rf cscope.in.out cscope.out cscope.po.out tags

-include $(OBJS_D)
