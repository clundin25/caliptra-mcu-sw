_*SPDX-License-Identifier: Apache-2.0<BR>
<BR>
<BR>
Licensed under the Apache License, Version 2.0 (the "License");<BR>
you may not use this file except in compliance with the License.<BR>
You may obtain a copy of the License at<BR>
<BR>
http://www.apache.org/licenses/LICENSE-2.0 <BR>
<BR>
Unless required by applicable law or agreed to in writing, software<BR>
distributed under the License is distributed on an "AS IS" BASIS,<BR>
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.<BR>
See the License for the specific language governing permissions and<BR>
limitations under the License.*_<BR>

# **Caliptra FPGA Guide** #
FPGA provides a fast environment for software development and testing that is built on Caliptra Core and Subsystem RTL.
The ARM CPU takes the place of an SOC manager and can drive stimulus to Caliptra SS over an AXI bus. In addition the Caliptra Core, MCU, and LCC JTAGs are connected to GPIO pins for debug and testing from the ARM CPU.

### FPGA Block Diagram Components ###
- Wrapper Registers
  - Controls resets, straps, and FPGA wrapper utilities such as the log and debug FIFOs.
- AXI Interconnect
  - SS requires the integrator to connect the various SS AXI busses to an interconnect to allow MMIO access both from the SOC manager and SS components with an AXI manager interface.
- Backdoor memory interfaces
  - The Caliptra Core, MCU, and OTP ROMs are implemented as dual port SRAM's to allow them to be reconfigured without rebuilding. These SRAMs are mapped into the ARM CPU to allow them to be written by the hw-model before taking SS out of reset.
- Xilinx I3C
  - The FPGA instantiates an I3C host controller to communicate with the SS I3C. In order for the I3C controllers to reach I3C bus speeds a higher clock is needed. The FPGA modifies caliptra_ss_top to insert CDC logic and run the SS I3C at the same clock.
- Internal ULPI USB 2.0 High-Speed Host (Architecture B)
  - `caliptra_fpga_ulpi_host` (`0xA401_4000`) instantiates a synthesizable Microchip USB3320 ULPI PHY register responder, High-Speed (`480 Mbps`) Chirp engine, autonomous `Auto-SOF` microframe keepalive generator, and CRC5/CRC16 USB token transceiver wired internally to `caliptra_ss_top`'s ULPI interface—enabling end-to-end High-Speed USB enumeration and hardware-assisted OCP Recovery v1.1 on a stock VCK-190 with zero external daughter cards or loopback cables.

![](./images/caliptra_ss_fpga_block_diagram.svg)

### Requirements: ###
 - Vivado
   - Version v2022.2 or 2024.2
 - PetaLinux Tools
   - Version must match Vivado
 - FPGA
   - [VCK190](https://www.xilinx.com/products/boards-and-kits/vck190.html)

### Versal ###
#### Processing system one time setup: ####
1. Download VCK-190 image
   - **Recommended**: A development image is built each week and uploaded by [this](https://github.com/chipsalliance/caliptra-sw/actions/workflows/fpga-image.yml) GitHub Action Job. You will want the image with the `-dev` postfix. This image is an almost exact replica of the image used for the Caliptra CI.
     - This is a debian based image and should make a similar user experience to the AMD image.
   - Ubuntu VCK190 SD card image and install to a microSD card. The Versal is packaged with a blank microSD card in the box that can be used for the OS.
1. Insert the OS SD card into the slot on top of the board.
  - The slot below the board is for the System Controller and the card there should be left inserted.
  - https://ubuntu.com/download/amd-xilinx
1. Configure SW1 to boot from SD1: [Image](./images/versal_boot_switch.jpg)
   - Mode SW1[4:1]: OFF, OFF, OFF, ON
1. Boot from the SD card.
   - Initial boot requires connecting over serial. The first serial port is for the PS. See below for settings.
   - Initial credentials (when using Ubuntu image)
     - User: ubuntu Pass: ubuntu
   - Update the date to avoid apt/git failures
     ```
     sudo dpkg-reconfigure tzdata
     sudo date -s 'yyyy-mm-dd hh:mm'
     ```
   - Install software dependencies - *Do not update the system*
     ```shell
     sudo apt update
     sudo apt install make gcc
     ```
   - Install rustup using Unix directions: https://rustup.rs/#
     ```
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
     ```
   - [Optional] Assign a hostname for SSH access.
   - [Optional] Save uboot environment variables to avoid the MAC being randomized each boot.
     - When connected to the serial port interrupt uboot at the message "Hit any key to stop autoboot:  0"
     - Issue ```saveenv``` command to uboot, which creates an env file in the boot partition for use in subsequent boots.

#### Serial port configuration: ####
The USB Type-C connecter J207 on the VCK190 provides UART and JTAG access to the board using an FTDI USB to quad UART/Serial converter.
1. VCK190 JTAG chain for waveform capture and management.
2. PS UART (First COM port) is a serial port used to access the operating system running on the ARM core.
3. PL UART (Currently unused)
4. System Controller UART (Third COM port)

Serial port settings for the PS UART:
 - Speed: 115200
 - Data bits: 8
 - Stop bits: 1
 - Parity: None
 - Flow control: None

### FPGA build steps: ###
The FPGA build process uses Vivado's batch mode to procedurally create the Vivado project using fpga_configuration.tcl and optionally create the caliptra_build/caliptra_fpga.xsa needed for the next step.
This script provides a number of configuration options for features that can be enabled using "-tclargs OPTION=VALUE OPTION=VALUE"

`vivado -nolog -nojournal -mode batch -source fpga_configuration.tcl -tclargs BUILD=TRUE`

| Option      | Purpose
| ------      | -------
| BUILD=TRUE  | Automatically start building the FPGA.
| GUI=TRUE    | Open the Vivado GUI.

The build applies additional placement spreading and congestion settings when
Vivado exposes the `STEPS.PLACE_DESIGN.ARGS.SUBDIRECTIVE` run property. Otherwise,
it prints a warning and uses the `Explore` directive alone. Check placement and
timing results before using the generated image.

This checkout uses Caliptra SS `cadc77b6` and its pinned `third_party/usb2`
(`97aa9616`) submodule. The FPGA wrapper preserves the existing I3C and backdoor
ROM/OTP interfaces, provides the 4 KiB MCU ROM-patch SRAM, and uses TRNG source 0
with source 1 disabled. In **Architecture B**, the FPGA fabric also instantiates
`caliptra_fpga_ulpi_host` (`0xA401_4000`), an internal synthesizable ULPI USB3320
PHY responder + USB 2.0 High-Speed (`480 Mbps`) Host loopback wired directly to
the Caliptra 2.2 USB Compound Wrapper (`0xA420_0000`, OCP Recovery at `0xA420_0800`)
and 64 KiB `dev0_mem` Block RAM (`0xA430_0000`). No external ULPI FMC/PMOD daughter
card or loopback cable is required on the VCK-190 to run High-Speed USB 2.0
enumeration or hardware-assisted OCP USB Recovery v1.1 alongside I3C recovery.
The IP packager preserves the `lib/` and `generated/` header paths used by
the Core RTL and USB sources, so their relative includes resolve during synthesis.

### Build boot.bin: ###

Note: If using the Calptra CI Image (or PetaLinux image), you can skip this step. Instead use a segmented bitstream and load the PDI file directly.

Here is a link with more information about segmented bitstreams: https://github.com/Xilinx/Vivado-Design-Tutorials/tree/2024.2/Versal/Boot_and_Config/Segmented_Configuration

 - Source PetaLinux tools from the PetaLinux installation directory. *PetaLinux Tools must match Vivado version*
   - `source settings.sh`
 - Execute [create_boot_bin.sh](create_boot_bin.sh) to create a BOOT.BIN
   - `./create_boot_bin.sh caliptra_build/caliptra_fpga.xsa`
 - (Optional) After the BOOT.BIN is created once, update_boot_bin.sh can be used to incorporate a new xsa.
   - `./update_boot_bin.sh caliptra_build/caliptra_fpga.xsa`
 - Copy petalinux_project/images/linux/BOOT.BIN to the boot partition as boot1900.bin
   - If the Ubuntu image is booted, it will mount the boot partition at /boot/firmware/
   - If boot1900.bin fails to boot the system will fallback to the default boot1901.bin
   - [!WARNING]
     ```reboot``` seems to skip the image selector and will load from the same filename as the previous boot. If the fallback image is the last one booted then the proper procedure is ```shutdown``` and to toggle the power switch. In the serial boot log the fallback image uses PLM from 2022 while for any valid Caliptra FPGA image the PLM will be 2024.
   ```shell
   sudo su
   cp BOOT.BIN /boot/firmware/boot1900.bin
   reboot
   # OR
   shutdown
   # Toggle power switch
   ```

- Verify the correct image is loaded by checking FPGA wrapper registers.
   - fpga_magic (0xA4010000) contains 0x52545043.
   - fpga_version (0xA4010004) contains the hash of the git HEAD commit.

### Compiling and running Caliptra tests for the FPGA: ###

Please checkout the FPGA section of the MCU [spec](https://chipsalliance.github.io/caliptra-mcu-sw/fpga.html).

### Adding registers to the FPGA wrapper. ###
The FPGA wrapper module contains several registers that interface with the
hardware model to enable various test cases to drive signals/data in/out of the
Caliptra Subsystem toplevel. To add additional registers simply:

1. Ensure you have the `peakrdl` and `peakrdl-markdown` python packages installed: `pip install peakrdl peakrdl-markdown`.
2. Modify the RDL file in `hw/latest/fpga/src/caliptra_fpga_realtime_regs.rdl` to add the new register descriptions.
3. rerun the autogeneration script:
    a. `cd hw/latest/fpga/src`
    b. `./gen.sh`
4. [optional]: connect the new registers Caliptra Subsystem toplevel if needed
5. Rebuild the bitstream. 

### Common Issues ###
- Caliptra logic missing or system hang when attempting to access FPGA Wrapper
  - ```sudo shutdown now``` and use power switch to reboot system
- Failures accessing GitHub or package repositories
  - Date incorrect. Fix date using: ```sudo date -s 'yyyy-mm-dd hh::mm'```

### Processing System - Programmable Logic interfaces ###
[FPGA Wrapper Registers](fpga_wrapper_regs.md)

#### Versal Memory Map ####
| IP/Peripheral                       | Accessibility        | Address size | Start address | End address |
| :---------------------------------- | -------------------- | :----------- | :------------ | :---------- |
| Caliptra core ROM Backdoor          | Always               | 96 KiB       | 0xB000_0000   | 0xB001_7FFF |
| MCU ROM Backdoor                    | Always               | 128 KiB      | 0xB002_0000   | 0xB003_FFFF |
| MCU ROM AXI Sub (provided by SS)    | cptra_ss_rst_b       | 128 KiB      | 0xB004_0000   | 0xB005_FFFF |
| MCU SRAM                            | Always               | 96 KiB       | 0xB008_0000   | 0xB005_FFFF |
| FPGA Wrapper Registers              | Always               | 16 KiB       | 0xA401_0000   | 0xA401_3FFF |
| FPGA Internal ULPI USB 2.0 HS Host  | Always               | 16 KiB       | 0xA401_4000   | 0xA401_7FFF |
| SS I3C                              | cptra_ss_rst_b       | 8 KiB        | 0xA403_0000   | 0xA403_1FFF |
| LCC                                 | cptra_ss_rst_b       | 8 KiB        | 0xA404_0000   | 0xA404_1FFF |
| OTP                                 | cptra_ss_rst_b       | 8 KiB        | 0xA406_0000   | 0xA406_1FFF |
| Xilinx I3C                          | cptra_ss_rst_b       | 4 KiB        | 0xA408_0000   | 0xA408_0FFF |
| AXI Firewall Control                | Always               | 4 KiB        | 0xA409_0000   | 0xA409_0FFF |
| Caliptra                            | SS reset to Caliptra | 1 MiB        | 0xA410_0000   | 0xA41F_FFFF |
| Caliptra 2.2 USB Combo + OCP Recv   | cptra_ss_rst_b       | 64 KiB       | 0xA420_0000   | 0xA420_FFFF |
| Caliptra 2.2 USB Dev0 Block RAM     | cptra_ss_rst_b       | 64 KiB       | 0xA430_0000   | 0xA430_FFFF |
| MCI                                 | cptra_ss_rst_b       | 16 MiB       | 0xA800_0000   | 0xA8FF_FFFF |

### Caliptra 2.2 USB Architecture B (Internal ULPI PHY & High-Speed Host Loopback) ###

The VCK-190 board does not populate a physical ULPI USB transceiver on its FMC/PMOD headers out of the box. **Architecture B** solves this purely inside the Versal programmable logic so that unmodified Caliptra 2.2 USB compound RTL (`ip_xxx_3511_hs_mem_compound_wrapper`), Caliptra Core AXI DMA recovery, and the MCU ROM `LpcipUsbDriver` can be validated end-to-end on any stock VCK-190 alongside XI3C recovery—with **zero external breakout cards, cables, Linux kernel module edits, or device-tree changes**.

#### How It Works ####

1. **Synthesizable ULPI USB3320 PHY + High-Speed Host (`src/caliptra_fpga_ulpi_host.sv`)**
   - **ULPI Register & `RXCMD` Emulation:** Connects directly to `caliptra_ss_top`'s synchronous 8-bit SDR ULPI signals (`DATA[7:0]`, `DIR`, `NXT`, `STP`) on `core_clk` (`18 MHz`). Emulates a Microchip USB3320 PHY register file (`VID = 0x0424`, `PID = 0x0007`, `FuncCtrl`, `OtgCtrl`, `Scratch`) with set (`+0x01`) and clear (`+0x02`) aliases, and emits `RXCMD` status bytes (`VbusValid`, `HostDisconnect`, `LineState`) whenever the bus transitions.
   - **USB 2.0 High-Speed Reset & Chirp Handshake:** Assertions of `OP_BUS_RESET_HS` drive `SE0`, detect the Device Chirp `K` transmitted by the LPCIP controller (`XcvrSelect = HS`, `TermSelect = FS`, `OpMode = DisableBitStuffing`), reply with the alternating `K-J-K-J-K-J` Host Chirp sequence, and latch `hs_active = 1` once the device switches to High-Speed terminations (`USB_G_SIM_CHIRP_TIMERS = 1` scales chirp timers for `18 MHz` FPGA operation).
   - **Autonomous `Auto-SOF` Keepalive:** When `CTRL.AUTO_SOF_EN` is set in High-Speed mode, the RTL autonomously injects CRC5-checked `SOF` tokens between host transactions. Without continuous microframe `SOF` activity, the LPCIP USB device controller enters High-Speed suspend (`DSUS` after `3 ms` of idle) while Caliptra Core spends tens of milliseconds verifying SHA-384, ECC-384, and LMS firmware signatures.
   - **Hardware Token & Packet Engine:** Generates bit-stuffed/CRC5 `SETUP`, `IN`, and `OUT` tokens plus CRC16 `DATA0`/`DATA1` payloads from a 64-byte TX buffer (`+0x40`), captures device `DATA0`/`DATA1` responses into a 64-byte RX buffer (`+0x80`), automatically returns host `ACK` on valid `IN` data, and reports handshake PIDs (`ACK`, `NAK`, `NYET`, `STALL`).

2. **Zero-Kernel-Change AXI Demux & Subsystem Memory Wiring (`src/caliptra_wrapper_top.sv`, `src/usb_bram_64_512.sv`, `fpga_configuration.tcl`)**
   - **1-to-2 AXI4-Lite Wrapper Demux (`M06_AXI`):** Widens `S_AXI_WRAPPER` to `32 KiB` and routes `addr[14] == 0` (`0xA401_0000..0xA401_3FFF`) to `caliptra_fpga_realtime_regs` and `addr[14] == 1` (`0xA401_4000..0xA401_7FFF`) to `caliptra_fpga_ulpi_host`. Because `/dev/uio0` `map0` already maps `64 KiB` at `0xA401_0000` in the standard CI image, `ModelFpgaRealtime` accesses the USB host at `uio0 map0 + 0x4000` with no kernel or DTB rebuild.
   - **USB CSRs & Dual-Accessed Block RAM (`M14_AXI` & `M15_AXI`):** Maps `S_AXI_USB_COMBO` at `0xA420_0000` (with hardware OCP Recovery registers strapped at `0xA420_0800` via `cptra_ss_strap_usb_recovery_ifc_base_addr_i`) and a parameterized byte-lane synchronous Block RAM (`usb_bram_64_512`, `64 KiB` at `0xA430_0000` for `dev0_mem` plus internal `4 KiB` for `dev1_mem`) across `M_AXI_ARM`, `M_AXI_MCU_*`, `M_AXI_CALIPTRA`, and `axi_cdma_0`.
   - **Hardware OCP Recovery Sideband Loopback:** Connects `cptra_ss_usb_recovery_payload_available_o` and `cptra_ss_usb_recovery_image_activated_o` back into `caliptra_ss_top` so Caliptra Core's AXI DMA engine drains firmware images directly from the USB OCP FIFO into ICCM/DCCM and MCU SRAM.

3. **MCU ROM, Host MMIO Driver & OCP Recovery v1.1 Transport**
   - **FPGA MCU ROM (`platforms/fpga/rom/src/usb.rs`, `rom/src/recovery/usb.rs`):** Configures `UsbParams` (`0xA420_0000` / `0xA430_0000`), initializes the emulated USB3320 PHY over ULPI, serves EP0 descriptors (Device, Configuration, Microsoft OS / WCID, and OCP Recovery functional descriptors), and enables hardware OCP Recovery on Device 0 when USB recovery is selected.
   - **Host Driver & Recovery Agent (`hw/model/src/fpga_ulpi_usb.rs`, `tests/integration/src/test_fpga_usb_arch_b.rs`):** `FpgaUlpiUsbHost` (`ModelFpgaRealtime::ulpi_usb_host()`) drives VBUS attach, High-Speed bus reset + Chirp, `Auto-SOF`, and `SETUP`/`DATA`/`STATUS` control transfers with automatic `NAK` retry. `FpgaUlpiRecoveryTransport` implements `caliptra_mcu_usb_recovery::RecoveryTransport`, enabling the unmodified `RecoveryAgent` to discover `PROT_CAP` (`v1.1`), stream all 3 signed images (`caliptra_fw` + `soc_manifest` + `mcu_runtime`, `~396 KiB` over `>6,190` High-Speed USB packets), verify `RecoveryOutcome::Confirmed`, and warm-reset the MCU into authenticated SRAM runtime.

#### `caliptra_fpga_ulpi_host` Register Map (`0xA401_4000`) ####

| Offset | Name | Access | Description |
| :----- | :--- | :----- | :---------- |
| `0x00` | `MAGIC` | RO | Constant `0x5553_4248` (`"USBH"`) identifying Architecture B bitstream support |
| `0x04` | `CTRL` | RW | `[0]` `VBUS_VALID`, `[1]` `AUTO_SOF_EN`, `[2]` `SOFT_RESET` (self-clearing) |
| `0x08` | `STATUS` | RO | `[0]` `busy`, `[1]` `done`, `[2]` `timeout_err`, `[3]` `ulpi_init_done`, `[4]` `dev_connected`, `[5]` `hs_active`, `[6]` `recovery_payload_avail`, `[7]` `recovery_image_activated`, `[11:8]` `rx_pid`, `[19:12]` `rx_len`, `[27:20]` `ulpi_func_ctrl`, `[31:28]` `hl_state` |
| `0x0C` | `CMD` | WO | `[2:0]` `op` (`1=BUS_RESET_HS`, `2=SETUP`, `3=OUT`, `4=IN`), `[9:3]` `dev_addr`, `[13:10]` `endp`, `[14]` `data_pid` (`0=DATA0`, `1=DATA1`), `[22:16]` `tx_len` |
| `0x10` | `TIMEOUT` | RW | Per-transaction ULPI response timeout in `core_clk` cycles |
| `0x14` | `DIAG` | RO | `[15:0]` `sof_count`, `[23:16]` `ulpi_reg_op_count`, `[31:24]` `last_ulpi_cmd` |
| `0x40..0x7F` | `TX_BUF` | RW | 64-byte (`16 x u32`) host-to-device packet payload buffer |
| `0x80..0xBF` | `RX_BUF` | RO | 64-byte (`16 x u32`) device-to-host packet payload buffer |

#### Running Architecture B on VCK-190 (`caliptra-fpga`) ####

A prebuilt segmented bitstream (`FPGA_VERSION = 0xa22b0001`, compatible with `ss_golden_segmented_routed.dcp` via `pr_verify`) is configured in [`bitstream_manifests/subsystem.toml`](bitstream_manifests/subsystem.toml) (and directly downloadable at `https://storage.googleapis.com/carl-caliptra-github-ci-bitstreams/usb_arch_b_runtime_a22b0001.pdi`, SHA-256 `ec97272525e0336e05a93bd28211bcd2a027e7e76d168672b204ac6028876e47`):

```shell
# 1. Program the Architecture B segmented PDI onto the VCK-190
CALIPTRA_HW_REV=latest cargo xtask-fpga fpga bootstrap --target-host caliptra-fpga

# 2. Build & sync FPGA firmware bundle and integration test archive
CALIPTRA_HW_REV=latest cargo run --package caliptra-mcu-xtask \
  --features=fpga_realtime,parallel-build -- fpga build --target-host caliptra-fpga
CALIPTRA_HW_REV=latest cargo xtask-fpga fpga build-test --target-host caliptra-fpga \
  --package-filter "package(caliptra-mcu-tests-integration)"

# 3. Run High-Speed USB 2.0 enumeration (~0.17s) and full 3-stage OCP Recovery boot (~7.4s)
CALIPTRA_HW_REV=latest cargo xtask-fpga fpga test --target-host caliptra-fpga --test-output \
  --test-filter "package(caliptra-mcu-tests-integration) & test(test_fpga_usb_arch_b)"
```

Reference logs captured from Vivado 2024.2 and live VCK-190 (`caliptra-fpga`) hardware are committed under [`logs/`](logs/):
- [`logs/vivado_build_and_pr_verify_summary.txt`](logs/vivado_build_and_pr_verify_summary.txt) — Synthesis/implementation runtime, `PR_VERIFY` compatibility, router overlap check, post-route timing summary, and resource utilization.
- [`logs/fpga_usb_arch_b_enumeration.txt`](logs/fpga_usb_arch_b_enumeration.txt) — Live VCK-190 High-Speed USB 2.0 ULPI PHY init, Chirp handshake, `Auto-SOF`, and descriptor enumeration log.
- [`logs/fpga_usb_arch_b_ocp_recovery_boot.txt`](logs/fpga_usb_arch_b_ocp_recovery_boot.txt) — Live VCK-190 3-stage signed OCP USB Recovery v1.1 streaming boot (`caliptra_fw` + `soc_manifest` + `mcu_runtime`) and warm-reset execution log.
- [`logs/fpga_i3c_coexistence_rom_hooks.txt`](logs/fpga_i3c_coexistence_rom_hooks.txt) — Live VCK-190 XI3C streaming recovery + `ENTDAA` coexistence log on the same `runtime_a22b0001.pdi` bitstream.

To rebuild `runtime_a22b0001.pdi` from RTL in Vivado 2024.2:

```shell
cd hw/latest/fpga
vivado -mode batch -source fpga_configuration.tcl \
  -tclargs BUILD=TRUE SEGMENTED=TRUE VERSION=a22b0001
```

### Waveform Debug ###
If built with DEBUG=TRUE common signals for debug will be connected to ILAs. In addition images may be built with additional debug signals. This is a general procedure for loading a probes file when consuming an image built by someone else. If the image was built locally, this is unnecessary because the probes file will be loaded automatically.
- Open Vivado 2024.2. Under "Tasks" there is an option for "Open Hardware Manager"
- Open target
  - If the machine running Vivado is directly connected over USB it can be opened automatically. Alternatively Vivado can connect to a remote host running the hw-server that is connected to the FPGA.
- Load the ltx
  - Under the "Hardware Device Properties" menu specify the "Probes file" by selecting the "..." button on the right.
- Open the ILA in the main window to view the waveform window.

### JTAG debug
Requirements:
- Security state must have either debug_locked == false or lifecycle == manuf.
- Set "debug = true" in firmware profile to provide line information to GDB.
- openocd 0.12.0 (must be configured with --enable-sysfsgpio)
- gdb-multiarch

#### Debugger launch procedure ####
JTAG connectivity is provided using EMIO GPIO pins bridging the PS and PL. OpenOCD is run on the ARM core and uses SysFs to interface with the GPIO pins. The Caliptra, MCU, and LCC JTAGs are each connected to their own set of EMIO pins and can be used independently.
1. Invoke OpenOCD server
    - `./caliptra-mcu-sw/hw/latest/fpga/launch_openocd.sh [core/mcu/lcc]`
1. Connect client(s) for debug
    - GDB: `gdb-multiarch [bin] -ex 'target remote localhost:3333'`
    - Telnet: `telnet localhost 4444`

#### Caliptra SoC interface registers ####
Over Telnet connection to OpenOCD: `riscv.cpu riscv dmi_read [addr]`

#### JTAG testing ####
Test requirements for both OpenOCD and GDB:
- JTAG port is accessible when debug_locked == true or lifecycle == manufacturing. The port is inaccessible otherwise.
- Read access to ROM space using 8, 16, 32, and 64 bit reads.
- Read and write access to DCCM using 8, 16, 32, and 64 bit accesses.
- Access to ICCM using 32 and 64 bit reads, 32 bit writes.
- Access to VEER core registers.
- HW and SW breakpoints halt the CPU.
- Watchpoints on DCCM and Caliptra register access halt the CPU.
 
Test requirements exclusive to GDB:
- Basic commands all work (step, next, frame, info, bt, ni, si, etc.).
 
Test requirements exclusive to OpenOCD:
- Basic commands all work (reg, step, resume, etc.).
- Access to VEER CSRs.
- Access to Debug Module registers.
- Caliptra registers exposed to JTAG RW/RO status matches.
