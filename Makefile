CC := gcc
CC_FLAGS:=-Wall -Wpedantic -Wno-unused-variable

LD_FLAGS:=-lmnl -lnetfilter_queue
BUILD_DIR:=build
APP:=$(BUILD_DIR)/youtubeUnblock

SRCS := youtubeUnblock.c
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)

# PREFIX is environment variable, if not set default to /usr/local
ifeq ($(PREFIX),)
	PREFIX := /usr/local
else
	PREFIX := $(DESTDIR)
endif

.PHONY: default all dev dev_attrs prepare_dirs
default: all


run_dev: dev
	bash -c "sudo ./$(APP) 537"
	

dev: dev_attrs all

dev_attrs:
	$(eval CC_FLAGS := $(CC_FLAGS) -DDEBUG -ggdb -g3)

all: prepare_dirs $(APP)


prepare_dirs:
	mkdir -p $(BUILD_DIR)

$(APP): $(OBJS)
	@echo 'LD $(APP)'
	@$(CC) $(OBJS) -o $(APP) $(LD_FLAGS) 

$(BUILD_DIR)/%.o: %.c
	@echo 'CC $@'
	@$(CC) -c $(CC_FLAGS) $^ -o $@

install: all
	install -d $(PREFIX)/bin/
	install -m 755 $(APP) $(PREFIX)/bin/
	install -d $(PREFIX)/lib/systemd/system/

	@cp youtubeUnblock.service $(BUILD_DIR)
	@sed -i 's/$$(PREFIX)/$(subst /,\/,$(PREFIX))/g' $(BUILD_DIR)/youtubeUnblock.service
	install -m 644 $(BUILD_DIR)/youtubeUnblock.service $(PREFIX)/lib/systemd/system/

uninstall:
	rm $(PREFIX)/bin/youtubeUnblock
	systemctl disable youtubeUnblock.service
	rm $(PREFIX)/lib/systemd/system/youtubeUnblock.service

clean:
	rm -rf $(BUILD_DIR)
