# Licensed under the Apache-2.0 license

CONFIG_MODULE_SIG=n
KERNEL ?= $(shell uname -r)
# Kernel build tree. On the VCK-190 CI image (NixOS, cross-built) the host
# helper binaries in the -dev tree are x86_64, so build these modules on an
# x86_64 workstation with e.g.:
#   make KDIR=/path/to/linux-xlnx-vck190-6.6.40-dev/lib/modules/6.6.40/build \
#        ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
KDIR ?= /lib/modules/$(KERNEL)/build
obj-m += rom_backdoor_class.o caliptra_rom_backdoor.o mcu_rom_backdoor.o io_module.o
# Linux USB host controller driver for the in-fabric ULPI USB 2.0 HS host
# (Caliptra 2.2 USB "Architecture B"), see caliptra_fpga_hcd.c.
obj-m += caliptra_fpga_hcd.o
all:
		make -C $(KDIR) M=$(PWD) modules
clean:
		make -C $(KDIR) M=$(PWD) clean
