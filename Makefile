obj-m := hook.o
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
#KERNELDIR ?= /data1/code_2.6.32/Sina-Linux-2.6.32-base/taobao-kernel-build/kernel-2.6.32-220.23.1.el5/linux-2.6.32-220.23.1.el5.x86_64
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
