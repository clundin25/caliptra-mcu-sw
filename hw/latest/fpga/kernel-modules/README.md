# Caliptra FPGA kernel modules

| Module | Purpose |
| :--- | :--- |
| `io_module.ko` | UIO devices exposing the FPGA wrapper, Caliptra, ROM backdoors and MCU SRAM to the hardware model (`/dev/uio0`, `/dev/uio1`). |
| `rom_backdoor_class.ko`, `caliptra_rom_backdoor.ko`, `mcu_rom_backdoor.ko` | Backdoor ROM loaders. |
| `caliptra_fpga_hcd.ko` | **Linux USB Host Controller Driver** for the wrapper's in-fabric USB 2.0 High-Speed host engine (`caliptra_fpga_ulpi_host`, Caliptra 2.2 USB "Architecture B"). Registers a single-port high-speed root hub so the Caliptra 2.2 USB device enumerates with the stock kernel USB stack (`usbcore`) and is usable by `lsusb`, `libusb`, `usbmon`, and the `caliptra-mcu-usb-recovery` CLI like any physical device. |

## `caliptra_fpga_hcd`

- Hardware: MMIO at `0xA401_4000` (`S_AXI_WRAPPER + 0x4000`), token-level
  engine (`BUS_RESET_HS` / `SETUP` / `IN` / `OUT`, 64-byte buffers, handshake
  PID in `STATUS`). No interrupt line yet: completion is polled from an ordered
  workqueue.
- Supported: control, bulk and interrupt transfers (PIO, no DMA, no isochronous),
  NAK retry, `STALL -> -EPIPE`, URB unlink between packets, root-hub port reset
  (`OP_BUS_RESET_HS`, reports `PORT_HIGH_SPEED` from `STATUS.hs_active`) and
  connection polling (`STATUS.dev_connected`, 100 ms).
- Module parameter: `base_addr=<phys>` (default `0xA4014000`).
- `rmmod caliptra_fpga_hcd` before using the raw `FpgaUlpiUsbHost` MMIO driver
  from `hw/model`; the two must not share the engine. The integration tests do
  this automatically (`unload_fpga_hcd()` / `load_fpga_hcd_fresh()`).

### Building

The VCK-190 CI image is a NixOS build whose kernel (`linux-xlnx-vck190`, e.g.
`6.6.40`) is cross-compiled, so its `-dev` tree carries x86_64 helper binaries
and modules must be cross-built from an x86_64 host:

```shell
# 1. Fetch the kernel build tree from the booted image (once per image).
KDEV=$(ssh caliptra-fpga 'ls -d /nix/store/*-linux-xlnx-vck190-*-dev' | head -n 1)
rsync -aL caliptra-fpga:$KDEV/lib/modules/*/build/ /tmp/vck190-kbuild/

# 2. Cross-compile (vermagic must match `uname -r` on the FPGA).
cd hw/latest/fpga/kernel-modules
make KDIR=/tmp/vck190-kbuild ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- caliptra_fpga_hcd.ko

# 3. Deploy: `cargo xtask-fpga fpga bootstrap` copies the module if it exists
#    next to the sources or at $CPTRA_FPGA_HCD_KO; or copy it by hand:
rsync caliptra_fpga_hcd.ko caliptra-fpga:~/
ssh caliptra-fpga sudo insmod ~/caliptra_fpga_hcd.ko
```

### Verifying

```shell
ssh caliptra-fpga 'sudo dmesg | grep -E "caliptra-fpga-hcd|usb 1-"; lsusb'
# caliptra-fpga-hcd: new USB bus registered, assigned bus number 1
# caliptra-fpga-hcd: port reset done: high-speed device (status 0400003a)
# usb 1-1: new high-speed USB device number 2 using caliptra-fpga-hcd
# usb 1-1: New USB device found, idVendor=ffff, idProduct=ffff, bcdDevice= 1.00
```

End-to-end: `test_fpga_usb_arch_b_linux_hcd_recovery_boot` in
`tests/integration` loads the module, lets `usbcore` enumerate the device, and
runs the unmodified libusb `RecoveryTransport` through a full 3-image OCP USB
Recovery boot.
