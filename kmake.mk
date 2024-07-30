#Kernel module makes here
PWD := $(CURDIR)

override CC		:= $(OCC) 
override LD		:= $(OLD)
override CFLAGS		:=
override LDFLAGS	:=

export CC LD CFLAGS LDFLAGS

.PHONY: kmake kload kunload kreload kclean
kmake:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

kload:
	insmod youtubeKUnblock.ko

kunload:
	-rmmod youtubeKUnblock

kreload: kunload kload

kclean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


