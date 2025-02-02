#Check for using system libs
USE_SYS_LIBS := no

#Userspace app makes here
BUILD_DIR := $(CURDIR)/build
DEPSDIR := $(BUILD_DIR)/deps
INCLUDE_DIR := $(CURDIR)/src
SRC_DIR := $(CURDIR)/src

CC:=gcc
CCLD:=$(CC)
LD:=ld

ifeq ($(USE_SYS_LIBS), no)
	override CFLAGS += -I$(DEPSDIR)/include
	override LDFLAGS += -L$(DEPSDIR)/lib
	REQ = $(LIBNETFILTER_QUEUE) $(LIBMNL) $(LIBCRYPTO)
endif

override CFLAGS += -DPKG_VERSION=\"$(PKG_FULLVERSION)\" -I$(INCLUDE_DIR) -Wall -Wpedantic -Wno-unused-variable -std=gnu99 -Ideps/cyclone/include

LIBNFNETLINK_CFLAGS := -I$(DEPSDIR)/include
LIBNFNETLINK_LIBS := -L$(DEPSDIR)/lib
LIBMNL_CFLAGS := -I$(DEPSDIR)/include
LIBMNL_LIBS := -L$(DEPSDIR)/lib

# PREFIX is environment variable, if not set default to /usr/local
ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

export CC CCLD LD CFLAGS LDFLAGS LIBNFNETLINK_CFLAGS LIBNFNETLINK_LIBS LIBMNL_CFLAGS LIBMNL_LIBS

APP:=$(BUILD_DIR)/youtubeUnblock
TEST_APP:=$(BUILD_DIR)/testYoutubeUnblock

SRCS := mangle.c args.c utils.c quic.c tls.c getopt.c quic_crypto.c inet_ntop.c trie.c
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)
APP_EXEC := youtubeUnblock.c 
APP_OBJ := $(APP_EXEC:%.c=$(BUILD_DIR)/%.o)


TEST_SRCS := $(shell find test -name "*.c")
TEST_OBJS := $(TEST_SRCS:%.c=$(BUILD_DIR)/%.o)
TEST_CFLAGS := -Itest/unity -Itest

LIBNFNETLINK := $(DEPSDIR)/lib/libnfnetlink.la
LIBMNL := $(DEPSDIR)/lib/libmnl.la
LIBNETFILTER_QUEUE := $(DEPSDIR)/lib/libnetfilter_queue.la
LIBCYCLONE := $(DEPSDIR)/lib/libcyclone.a

.PHONY: default all test build_test dev dev_attrs prepare_dirs
default: all

run_dev: dev
	bash -c "sudo $(APP)"

dev: dev_attrs all

dev_attrs:
	$(eval CFLAGS := $(CFLAGS) -DDEBUG -ggdb -g3)

all: prepare_dirs $(APP)

build_test: prepare_dirs $(TEST_APP)
test: build_test
	$(TEST_APP)

prepare_dirs:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/crypto
	mkdir -p $(BUILD_DIR)/test
	mkdir -p $(BUILD_DIR)/test/unity
	mkdir -p $(DEPSDIR)

$(LIBCYCLONE):
	$(MAKE) -C deps/cyclone CFLAGS="$(CFLAGS)"
	mkdir -p $(DEPSDIR)/lib
	cp deps/cyclone/libcyclone.a $(DEPSDIR)/lib/libcyclone.a

$(LIBNFNETLINK):
	cd deps/libnfnetlink && ./autogen.sh && ./configure --prefix=$(DEPSDIR) $(if $(CROSS_COMPILE_PLATFORM),--host=$(CROSS_COMPILE_PLATFORM),) --enable-static --disable-shared
	$(MAKE) -C deps/libnfnetlink
	$(MAKE) install -C deps/libnfnetlink
	
$(LIBMNL):
	cd deps/libmnl && ./autogen.sh && ./configure --prefix=$(DEPSDIR) $(if $(CROSS_COMPILE_PLATFORM),--host=$(CROSS_COMPILE_PLATFORM),) --enable-static --disable-shared
	$(MAKE) -C deps/libmnl
	$(MAKE) install -C deps/libmnl

$(LIBNETFILTER_QUEUE): $(LIBNFNETLINK) $(LIBMNL) 
	cd deps/libnetfilter_queue && ./autogen.sh && ./configure --prefix=$(DEPSDIR) $(if $(CROSS_COMPILE_PLATFORM),--host=$(CROSS_COMPILE_PLATFORM),) --enable-static --disable-shared
	$(MAKE) -C deps/libnetfilter_queue
	$(MAKE) install -C deps/libnetfilter_queue

$(APP): $(OBJS) $(APP_OBJ) $(REQ) $(LIBCYCLONE)
	@echo 'CCLD $(APP)'
	$(CCLD) $(OBJS) $(APP_OBJ) -o $(APP) $(LDFLAGS) -lmnl -lnetfilter_queue -lpthread -lcyclone

$(TEST_APP): $(APP) $(TEST_OBJS) $(REQ) $(LIBCYCLONE)
	@echo 'CCLD $(TEST_APP)'
	$(CCLD) $(OBJS) $(TEST_OBJS) -o $(TEST_APP) $(LDFLAGS) -lmnl -lnetfilter_queue -lpthread -lcyclone

$(BUILD_DIR)/%.o: src/%.c $(REQ) $(INCLUDE_DIR)/config.h
	@echo 'CC $@'
	$(CC) -c $(CFLAGS) $(LDFLAGS) $< -o $@

$(BUILD_DIR)/test/%.o: test/%.c $(REQ) $(INCLUDE_DIR)/config.h
	@echo 'CC $@'
	$(CC) -c $(CFLAGS) $(LDFLAGS) $(TEST_CFLAGS) $< -o $@

install: all
	install -d $(DESTDIR)$(PREFIX)/bin/
	install -m 755 $(APP) $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system/
	@cp youtubeUnblock.service $(BUILD_DIR)
	@sed -i 's/$$(PREFIX)/$(subst /,\/,$(PREFIX))/g' $(BUILD_DIR)/youtubeUnblock.service
	install -m 644 $(BUILD_DIR)/youtubeUnblock.service $(DESTDIR)$(PREFIX)/lib/systemd/system/

uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/youtubeUnblock
	rm $(DESTDIR)$(PREFIX)/lib/systemd/system/youtubeUnblock.service
	-systemctl disable youtubeUnblock.service

clean:
	find $(BUILD_DIR) -maxdepth 1 -type f | xargs rm -rf

distclean: clean
	rm -rf $(BUILD_DIR)
ifeq ($(USE_SYS_LIBS), no)
	$(MAKE) distclean -C deps/libnetfilter_queue || true
	$(MAKE) distclean -C deps/libmnl || true
	$(MAKE) distclean -C deps/libnfnetlink || true
endif
	$(MAKE) clean -C deps/cyclone || true
