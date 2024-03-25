# obj-m = rootkit.o
# PWD := $(shell pwd)
# EXTRA_CFLAGS = -Wall -g

# all:
# 	$(MAKE) ARCH=arm64 -C $(KDIR) M=$(PWD) modules

# clean:
# 	$(MAKE) -C $(KDIR) M=$(PWD) clean


obj-m += rootkit.o
PWD	:= $(shell pwd)
EXTRA_CFLAGS = -Wall -g

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
