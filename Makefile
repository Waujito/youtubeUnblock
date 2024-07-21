CC := gcc
CC_FLAGS:=-Wall -Wpedantic -Wno-unused-variable

LD_FLAGS:=-lmnl -lnetfilter_queue
BUILD_DIR:=build
APP:=$(BUILD_DIR)/youtubeUnblock

SRCS := youtubeUnblock.c
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)

.PHONY: default all dev dev_attrs prepare_dirs
default: all


run_dev: dev
	bash -c "sudo ./$(APP) 2"
	

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

clean:
	rm -rf $(BUILD_DIR)
