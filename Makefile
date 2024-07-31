BUILD_DIR := $(CURDIR)/build
DEPSDIR := $(BUILD_DIR)/deps

CC := gcc
LD := gcc
CFLAGS:=-Wall -Wpedantic -Wno-unused-variable -I$(DEPSDIR)/include -Os 
LDFLAGS:=-L$(DEPSDIR)/lib -static

LIBNFNETLINK_CFLAGS := -I$(DEPSDIR)/include
LIBNFNETLINK_LIBS := -L$(DEPSDIR)/lib
LIBMNL_CFLAGS := -I$(DEPSDIR)/include
LIBMNL_LIBS := -L$(DEPSDIR)/lib

# PREFIX is environment variable, if not set default to /usr/local
ifeq ($(PREFIX),)
	PREFIX := /usr/local
else
	PREFIX := $(DESTDIR)
endif

export CC LD CFLAGS LDFLAGS LIBNFNETLINK_CFLAGS LIBNFNETLINK_LIBS LIBMNL_CFLAGS LIBMNL_LIBS

APP:=$(BUILD_DIR)/youtubeUnblock

SRCS := youtubeUnblock.c
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)

LIBNFNETLINK := $(DEPSDIR)/lib/libnfnetlink.a
LIBMNL := $(DEPSDIR)/lib/libmnl.a
LIBNETFILTER_QUEUE := $(DEPSDIR)/lib/libnetfilter_queue.a


.PHONY: default all dev dev_attrs prepare_dirs
default: all

run_dev: dev
	bash -c "sudo $(APP) 537"

dev: dev_attrs all

dev_attrs:
	$(eval CFLAGS := $(CFLAGS) -DDEBUG -ggdb -g3)

all: prepare_dirs $(APP)

prepare_dirs:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(DEPSDIR)

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

$(APP): $(OBJS) $(LIBNETFILTER_QUEUE) $(LIBMNL)
	@echo 'LD $(APP)'
	@$(LD) $(OBJS) -o $(APP) -L$(DEPSDIR)/lib -lmnl -lnetfilter_queue

$(BUILD_DIR)/%.o: %.c $(LIBNETFILTER_QUEUE) $(LIBMNL)
	@echo 'CC $@'
	@$(CC) -c $(CFLAGS) $^ -o $@

install: all
	install -d $(PREFIX)/bin/
	install -m 755 $(APP) $(PREFIX)/bin/
	install -d $(PREFIX)/lib/systemd/system/
	@cp youtubeUnblock.service $(BUILD_DIR)
	@sed -i 's/$$(PREFIX)/$(subst /,\/,$(PREFIX))/g' $(BUILD_DIR)/youtubeUnblock.service
	install -m 644 $(BUILD_DIR)/youtubeUnblock.service $(PREFIX)/lib/systemd/system/

uninstall:
	rm $(PREFIX)/bin/youtubeUnblock
	rm $(PREFIX)/lib/systemd/system/youtubeUnblock.service
	-systemctl disable youtubeUnblock.service

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) distclean -C deps/libnetfilter_queue || true
	$(MAKE) distclean -C deps/libmnl || true
	$(MAKE) distclean -C deps/libnfnetlink || true
