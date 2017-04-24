obj-m := rootkit.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm *.ko *.mod.* *.o Module.symvers module.order

rootify:
	gcc getperms.c -o rootify

get:
	gcc getpids.c -o get
