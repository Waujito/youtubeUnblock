SRCS := $(shell find -name "*.c")
OBJS := $(SRCS:%.c=build/%.o)
override CFLAGS += -Iinclude -Wno-pedantic
LIBNAME := libcyclone.a
CC := gcc


run: $(OBJS)
	@echo "AR $(LIBNAME)"
	@ar rcs libcyclone.a $(OBJS)

prep_dirs:
	mkdir build


build/%.o: %.c prep_dirs
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm $(OBJS) || true
	@rm libcyclone.a || true
	@rm -rf build || true


