#Kernel module makes here
PWD := $(CURDIR)

CC	:= gcc 
CCLD	:= $(CC)
LD	:= ld
CFLAGS	:=
LDFLAGS	:=

IPT_CFLAGS := -Wall -Wpedantic -O2

.PHONY: kmake kload kunload kreload kclean kmclean xclean
kmake: kmod

kmod:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

kload:
	insmod kyoutubeUnblock.ko

kunload:
	-rmmod kyoutubeUnblock

kreload: kunload kload

kclean: kmclean

kmclean:
	-$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
