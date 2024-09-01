#Kernel module makes here
PWD := $(CURDIR)

CC	:= gcc 
CCLD	:= $(CC)
LD	:= ld
CFLAGS	:=
LDFLAGS	:=

IPT_CFLAGS := -Wall -Wpedantic -O2

.PHONY: kmake kload kunload kreload kclean kmclean xclean
kmake: kmod xmod

kmod:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

xmod: libipt_YTUNBLOCK.so libip6t_YTUNBLOCK.so

libipt_YTUNBLOCK.so: libipt_YTUNBLOCK.o
	$(CCLD) -shared -fPIC ${IPT_CFLAGS} -o $@ $^;

libipt_YTUNBLOCK.o: libipt_YTUNBLOCK.c
	$(CC) ${IPT_CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;

libip6t_YTUNBLOCK.so: libip6t_YTUNBLOCK.o
	$(CCLD) -shared -fPIC ${IPT_CFLAGS} -o $@ $^;

libip6t_YTUNBLOCK.o: libip6t_YTUNBLOCK.c
	$(CC) ${IPT_CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;

kload:
	insmod ipt_YTUNBLOCK.ko
	cp ./libipt_YTUNBLOCK.so /usr/lib/xtables/
	cp ./libip6t_YTUNBLOCK.so /usr/lib/xtables/

kunload:
	-rmmod ipt_YTUNBLOCK
	-/bin/rm /usr/lib/xtables/libipt_YTUNBLOCK.so
	-/bin/rm /usr/lib/xtables/libip6t_YTUNBLOCK.so

kreload: kunload kload

kclean: xtclean kmclean

kmclean:
	-$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

xtclean:
	-/bin/rm -f libipt_YTUNBLOCK.so libipt_YTUNBLOCK.o
