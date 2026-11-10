// Licensed under the Apache-2.0 license

//! End-to-End Hardware Verification on VCK-190 FPGA for "Architecture B":
//! Zero-cable internal ULPI USB3320 PHY + USB 2.0 High-Speed Host Loopback
//! (`caliptra_fpga_ulpi_host` at `0xA401_4000`) connected to Caliptra 2.2's
//! `ip_xxx_3511_hs_mem_compound_wrapper` (`0xA420_0000` / `0xA430_0000`).

#[cfg(test)]
mod test {
    use crate::test::TEST_LOCK;
    use anyhow::Result;
    use caliptra_image_types::FwVerificationPqcKeyType;
    use caliptra_mcu_builder::FirmwareBinaries;
    use caliptra_mcu_hw_model::fpga_ulpi_usb::{FpgaUlpiUsbHost, ULPI_HOST_MAGIC};
    use caliptra_mcu_hw_model::{
        new, new_unbooted, DefaultHwModel, Fuses, InitParams, McuHwModel,
    };
    use caliptra_mcu_ocp::protocol::RecoveryCommand;
    use caliptra_mcu_romtime::McuBootMilestones;
    use caliptra_mcu_usb_recovery::{
        RecoveryAgent, RecoveryImages, RecoveryOptions, RecoveryOutcome, RecoveryTransport,
        CONTROL_MAX_BYTES,
    };
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    struct FpgaUlpiRecoveryTransport<'a> {
        hw: &'a mut DefaultHwModel,
        host: FpgaUlpiUsbHost,
    }

    impl RecoveryTransport for FpgaUlpiRecoveryTransport<'_> {
        fn read(
            &mut self,
            command: RecoveryCommand,
            response: &mut [u8; CONTROL_MAX_BYTES],
            timeout: Duration,
        ) -> Result<usize> {
            let addr = self.host.device_address();
            let ifc = u16::from(self.host.ocp_interface());
            let hw = &mut *self.hw;
            self.host.control_read_raw(
                addr,
                0xA1,
                0x00,
                command as u16,
                ifc,
                CONTROL_MAX_BYTES as u16,
                response,
                || hw.step(),
                timeout,
            )
        }

        fn write(&mut self, command: RecoveryCommand, data: &[u8], timeout: Duration) -> Result<()> {
            let addr = self.host.device_address();
            let ifc = u16::from(self.host.ocp_interface());
            let hw = &mut *self.hw;
            self.host.control_write_raw(
                addr,
                0x21,
                0x00,
                command as u16,
                ifc,
                data,
                || hw.step(),
                timeout,
            )
        }

        fn wait(&mut self, duration: Duration) -> Result<()> {
            let start = Instant::now();
            while start.elapsed() < duration {
                self.hw.step();
                std::thread::sleep(Duration::from_millis(1).min(duration));
            }
            Ok(())
        }
    }

    fn vendor_pk_hash_words(bytes: &[u8; 48]) -> [u32; 12] {
        let mut out = [0u32; 12];
        for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
            out[idx] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        out
    }

    // ---------------------------------------------------------------------
    // Linux `caliptra_fpga_hcd` helpers
    // ---------------------------------------------------------------------
    const FPGA_HCD_MODULE: &str = "caliptra_fpga_hcd";
    const CALIPTRA_USB_VID: u16 = 0xffff;
    const CALIPTRA_USB_PID: u16 = 0xffff;

    fn fpga_hcd_loaded() -> bool {
        std::path::Path::new(&format!("/sys/module/{FPGA_HCD_MODULE}")).exists()
    }

    fn find_fpga_hcd_ko() -> Option<std::path::PathBuf> {
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(p) = std::env::var("CPTRA_FPGA_HCD_KO") {
            candidates.push(p.into());
        }
        for base in ["./", "../", "/home/runner/", "/root/"] {
            candidates.push(format!("{base}{FPGA_HCD_MODULE}.ko").into());
        }
        candidates.into_iter().find(|p| p.is_file())
    }

    /// Unload the Linux HCD so the raw `FpgaUlpiUsbHost` driver owns the engine.
    fn unload_fpga_hcd() {
        if fpga_hcd_loaded() {
            let st = std::process::Command::new("rmmod")
                .arg(FPGA_HCD_MODULE)
                .status()
                .expect("spawn rmmod");
            assert!(st.success(), "rmmod {FPGA_HCD_MODULE} failed");
            println!("[arch-b] unloaded {FPGA_HCD_MODULE}");
        }
    }

    /// (Re)load the Linux HCD from a clean state. Must run *before* the MCU ROM
    /// programs the emulated ULPI PHY, because the HCD soft-resets the engine.
    fn load_fpga_hcd_fresh() {
        unload_fpga_hcd();
        let ko = find_fpga_hcd_ko().expect(
            "caliptra_fpga_hcd.ko not found (set CPTRA_FPGA_HCD_KO or copy it next to all-fw.zip)",
        );
        let st = std::process::Command::new("insmod")
            .arg(&ko)
            .status()
            .expect("spawn insmod");
        assert!(st.success(), "insmod {} failed", ko.display());
        assert!(fpga_hcd_loaded(), "{FPGA_HCD_MODULE} did not stay loaded");
        println!("[arch-b] loaded {}", ko.display());
    }

    /// Poll sysfs until Linux has enumerated *and configured* the Caliptra USB
    /// device through `caliptra_fpga_hcd`. Returns the sysfs device directory.
    fn wait_linux_enumeration(
        hw: &mut DefaultHwModel,
        timeout: Duration,
    ) -> std::path::PathBuf {
        let deadline = Instant::now() + timeout;
        loop {
            for entry in std::fs::read_dir("/sys/bus/usb/devices").into_iter().flatten() {
                let Ok(entry) = entry else { continue };
                let dir = entry.path();
                let rd = |f: &str| {
                    std::fs::read_to_string(dir.join(f))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default()
                };
                if rd("idVendor") == format!("{CALIPTRA_USB_VID:04x}")
                    && rd("idProduct") == format!("{CALIPTRA_USB_PID:04x}")
                    && rd("bConfigurationValue") == "1"
                {
                    println!(
                        "[arch-b-hcd] Linux enumerated {} : speed={} Mb/s devnum={} bcdDevice={} bNumInterfaces={} manufacturer={:?} product={:?}",
                        dir.display(),
                        rd("speed"),
                        rd("devnum"),
                        rd("bcdDevice"),
                        rd("bNumInterfaces"),
                        rd("manufacturer"),
                        rd("product"),
                    );
                    return dir;
                }
            }
            assert!(
                Instant::now() < deadline,
                "Linux did not enumerate+configure {CALIPTRA_USB_VID:04x}:{CALIPTRA_USB_PID:04x} within {timeout:?}; dmesg: {}",
                String::from_utf8_lossy(
                    &std::process::Command::new("dmesg")
                        .output()
                        .map(|o| o.stdout)
                        .unwrap_or_default()
                )
                .lines()
                .rev()
                .take(40)
                .collect::<Vec<_>>()
                .join("\n")
            );
            for _ in 0..50 {
                hw.step();
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Stock libusb transport, with the hardware model stepped around each
    /// transfer so UART output keeps flowing into the test log.
    struct SteppingLibusbTransport<'a> {
        hw: &'a mut DefaultHwModel,
        inner: caliptra_mcu_usb_recovery::libusb::LibusbTransport,
    }

    impl RecoveryTransport for SteppingLibusbTransport<'_> {
        fn read(
            &mut self,
            command: RecoveryCommand,
            response: &mut [u8; CONTROL_MAX_BYTES],
            timeout: Duration,
        ) -> Result<usize> {
            self.hw.step();
            self.inner.read(command, response, timeout)
        }

        fn write(&mut self, command: RecoveryCommand, data: &[u8], timeout: Duration) -> Result<()> {
            self.hw.step();
            self.inner.write(command, data, timeout)
        }

        fn wait(&mut self, duration: Duration) -> Result<()> {
            let start = Instant::now();
            while start.elapsed() < duration {
                self.hw.step();
                std::thread::sleep(Duration::from_millis(1).min(duration));
            }
            Ok(())
        }
    }

    /// End-to-end OCP USB Recovery v1.1 boot where **Linux `usbcore`** (via the
    /// `caliptra_fpga_hcd` host controller driver) performs the bus reset, HS
    /// chirp and Chapter 9 enumeration, and the unmodified libusb
    /// `RecoveryTransport` streams the images—i.e. the exact software path a
    /// physical USB host would use. No raw MMIO USB access from the test.
    #[test]
    fn test_fpga_usb_arch_b_linux_hcd_recovery_boot() {
        let lock = TEST_LOCK.lock().unwrap();
        let binaries = FirmwareBinaries::from_env().expect("CPTRA_FIRMWARE_BUNDLE must be set");
        assert!(
            binaries.has_test_feature_rom("test-lpcip-usb-ocp-recovery"),
            "all-fw.zip missing prebuilt test-lpcip-usb-ocp-recovery MCU ROM"
        );
        let mcu_rom = binaries.test_feature_rom("test-lpcip-usb-ocp-recovery");
        let vpk = binaries
            .vendor_pk_hash()
            .expect("missing vendor_pk_hash in firmware bundle");

        // The HCD must own the engine from before the device attaches.
        load_fpga_hcd_fresh();

        let mut hw = new(InitParams {
            fuses: Fuses {
                fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
                vendor_pk_hash: vendor_pk_hash_words(&vpk),
                ..Default::default()
            },
            caliptra_rom: &binaries.caliptra_rom,
            mcu_rom: &mcu_rom,
            caliptra_firmware: &[],
            soc_manifest: &[],
            mcu_firmware: &[],
            vendor_pk_hash: Some(vpk),
            vendor_pqc_type: Some(FwVerificationPqcKeyType::LMS),
            active_mode: true,
            enable_mcu_uart_log: true,
            flash_boot: false,
            check_booted_to_runtime: false,
            ..Default::default()
        })
        .expect("Failed to boot ModelFpgaRealtime into USB OCP recovery mode");

        let fpga_version = unsafe { hw.base.wrapper.ptr.add(1).read_volatile() };
        println!("[arch-b-hcd] FPGA wrapper version = 0x{fpga_version:08x}");

        let sysfs_dev = wait_linux_enumeration(&mut hw, Duration::from_secs(60));
        if let Ok(desc) = std::fs::read(sysfs_dev.join("descriptors")) {
            println!(
                "[arch-b-hcd] sysfs descriptors ({} bytes): {}",
                desc.len(),
                desc.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
            );
        }
        // `sudo` may strip the NixOS profile from PATH; try the system path too.
        for lsusb in ["lsusb", "/run/current-system/sw/bin/lsusb", "/usr/bin/lsusb"] {
            if let Ok(out) = std::process::Command::new(lsusb).output() {
                if !out.stdout.is_empty() {
                    println!("[arch-b-hcd] lsusb:\n{}", String::from_utf8_lossy(&out.stdout));
                    break;
                }
            }
        }

        let inner = caliptra_mcu_usb_recovery::libusb::LibusbTransport::open(
            caliptra_mcu_usb_recovery::libusb::DeviceSelector {
                vendor_id: CALIPTRA_USB_VID,
                product_id: CALIPTRA_USB_PID,
                bus: None,
                address: None,
            },
        )
        .expect("open Caliptra USB device through libusb");
        let transport = SteppingLibusbTransport { hw: &mut hw, inner };

        let options = RecoveryOptions {
            cms: 0,
            transfer_timeout: Duration::from_secs(5),
            progress_timeout: Duration::from_secs(45),
            overall_timeout: Duration::from_secs(180),
            poll_interval: Duration::from_millis(5),
        };
        let mut agent = RecoveryAgent::new(transport, options).expect("RecoveryAgent::new");
        let discovery = agent.probe().expect("OCP Recovery probe over libusb failed");
        println!("[arch-b-hcd] OCP Discovery = {discovery:?}");

        let images = RecoveryImages {
            caliptra_fmc_rt: &binaries.caliptra_fw,
            soc_manifest: &binaries.soc_manifest,
            mcu_runtime: &binaries.mcu_runtime,
        };
        println!(
            "[arch-b-hcd] Streaming 3 signed images through Linux usbcore + libusb: caliptra_fw={}B, soc_manifest={}B, mcu_runtime={}B",
            images.caliptra_fmc_rt.len(),
            images.soc_manifest.len(),
            images.mcu_runtime.len()
        );
        let start = Instant::now();
        let outcome = agent
            .run(&images)
            .expect("OCP Recovery over Linux usbcore/libusb failed");
        let elapsed = start.elapsed();
        let transport = agent.into_transport();
        transport.inner.close().expect("release OCP interface");
        println!("[arch-b-hcd] RecoveryAgent outcome={outcome:?} in {elapsed:.2?}");
        assert_eq!(outcome, RecoveryOutcome::Confirmed);

        let boot_deadline = Instant::now() + Duration::from_secs(20);
        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || Instant::now() >= boot_deadline
        });
        assert_eq!(hw.mci_fw_fatal_error(), None, "MCU reported fatal error after USB recovery");
        assert!(
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE),
            "Expected FIRMWARE_BOOT_FLOW_COMPLETE after Linux-hosted USB OCP Recovery; milestones=0x{:04x}",
            u16::from(hw.mci_boot_milestones())
        );
        println!(
            "[arch-b-hcd] SUCCESS! Linux usbcore enumerated the Caliptra 2.2 USB device and libusb streamed FMC+RT + SoC Manifest + MCU Runtime end-to-end!"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn test_fpga_usb_arch_b_enumeration() {
        let lock = TEST_LOCK.lock().unwrap();
        let binaries = FirmwareBinaries::from_env().expect("CPTRA_FIRMWARE_BUNDLE must be set");
        assert!(
            binaries.has_test_feature_rom("test-lpcip-usb-enumeration"),
            "all-fw.zip missing prebuilt test-lpcip-usb-enumeration MCU ROM"
        );
        let mcu_rom = binaries.test_feature_rom("test-lpcip-usb-enumeration");
        let vpk = binaries
            .vendor_pk_hash()
            .expect("missing vendor_pk_hash in firmware bundle");

        // This test drives the engine directly; keep the Linux HCD off it.
        unload_fpga_hcd();

        let mut hw = new_unbooted(InitParams {
            fuses: Fuses {
                fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
                vendor_pk_hash: vendor_pk_hash_words(&vpk),
                ..Default::default()
            },
            caliptra_rom: &binaries.caliptra_rom,
            mcu_rom: &mcu_rom,
            vendor_pk_hash: Some(vpk),
            vendor_pqc_type: Some(FwVerificationPqcKeyType::LMS),
            active_mode: true,
            enable_mcu_uart_log: true,
            check_booted_to_runtime: false,
            ..Default::default()
        })
        .expect("Failed to initialize ModelFpgaRealtime for USB enumeration");

        let fpga_version = unsafe { hw.base.wrapper.ptr.add(1).read_volatile() };
        println!("[arch-b-enum] FPGA wrapper version = 0x{fpga_version:08x}");

        let mut host = hw
            .ulpi_usb_host()
            .expect("Failed to attach to caliptra_fpga_ulpi_host at 0xA401_4000");
        assert_eq!(host.magic(), ULPI_HOST_MAGIC);
        println!(
            "[arch-b-enum] Initial ULPI host status={:?}, diag={:?}",
            host.status(),
            host.diag()
        );

        let enum_dev = host
            .wait_and_enumerate(7, || hw.step(), Duration::from_secs(15))
            .expect("USB 2.0 High-Speed enumeration failed on FPGA");

        println!(
            "[arch-b-enum] Enumerated Caliptra 2.2 USB Device at addr={} VID:PID={:04x}:{:04x} bcdDevice=0x{:04x} ocp_ifc={} status={:?} diag={:?}",
            enum_dev.address,
            enum_dev.vendor_id,
            enum_dev.product_id,
            enum_dev.bcd_device,
            enum_dev.ocp_interface,
            host.status(),
            host.diag()
        );
        assert_eq!(enum_dev.address, 7);
        assert_eq!(enum_dev.vendor_id, 0xffff);
        assert_eq!(enum_dev.product_id, 0xffff);
        assert_eq!(enum_dev.bcd_device, 0x0100);
        assert_eq!(enum_dev.ocp_interface, 0);
        assert!(host.status().hs_active, "Expected High-Speed mode active");
        assert!(
            host.diag().sof_count > 0,
            "Expected Auto-SOF microframes to be transmitted"
        );

        // Step briefly so `[usb-enumeration-test] configured` flushes to console output
        let flush_start = Instant::now();
        while flush_start.elapsed() < Duration::from_millis(50) {
            hw.step();
        }
        assert_eq!(
            hw.mci_fw_fatal_error(),
            None,
            "MCU ROM reported fatal error during USB enumeration"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn test_fpga_usb_arch_b_ocp_recovery_boot() {
        let lock = TEST_LOCK.lock().unwrap();
        let binaries = FirmwareBinaries::from_env().expect("CPTRA_FIRMWARE_BUNDLE must be set");
        assert!(
            binaries.has_test_feature_rom("test-lpcip-usb-ocp-recovery"),
            "all-fw.zip missing prebuilt test-lpcip-usb-ocp-recovery MCU ROM"
        );
        let mcu_rom = binaries.test_feature_rom("test-lpcip-usb-ocp-recovery");
        let vpk = binaries
            .vendor_pk_hash()
            .expect("missing vendor_pk_hash in firmware bundle");

        // This test drives the engine directly; keep the Linux HCD off it.
        unload_fpga_hcd();

        // Pass empty firmware slices + flash_boot=false so ModelFpgaRealtime::boot()
        // sets mci_generic_input_wires=[0, 0xc000_0000] and skips I3C recovery,
        // allowing our internal FPGA ULPI USB 2.0 High-Speed host to drive the entire
        // hardware-assisted OCP Recovery v1.1 boot!
        let mut hw = new(InitParams {
            fuses: Fuses {
                fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
                vendor_pk_hash: vendor_pk_hash_words(&vpk),
                ..Default::default()
            },
            caliptra_rom: &binaries.caliptra_rom,
            mcu_rom: &mcu_rom,
            caliptra_firmware: &[],
            soc_manifest: &[],
            mcu_firmware: &[],
            vendor_pk_hash: Some(vpk),
            vendor_pqc_type: Some(FwVerificationPqcKeyType::LMS),
            active_mode: true,
            enable_mcu_uart_log: true,
            flash_boot: false,
            check_booted_to_runtime: false,
            ..Default::default()
        })
        .expect("Failed to boot ModelFpgaRealtime into USB OCP recovery mode");

        let fpga_version = unsafe { hw.base.wrapper.ptr.add(1).read_volatile() };
        println!("[arch-b-recovery] FPGA wrapper version = 0x{fpga_version:08x}");

        let mut host = hw
            .ulpi_usb_host()
            .expect("Failed to attach to caliptra_fpga_ulpi_host at 0xA401_4000");

        let enum_dev = host
            .wait_and_enumerate(7, || hw.step(), Duration::from_secs(20))
            .expect("USB 2.0 High-Speed enumeration failed during OCP recovery boot");
        println!(
            "[arch-b-recovery] Enumerated Caliptra USB Device at addr={} ocp_ifc={} diag={:?}",
            enum_dev.address,
            enum_dev.ocp_interface,
            host.diag()
        );

        let options = RecoveryOptions {
            cms: 0,
            transfer_timeout: Duration::from_secs(5),
            progress_timeout: Duration::from_secs(45),
            overall_timeout: Duration::from_secs(180),
            poll_interval: Duration::from_millis(5),
        };
        let transport = FpgaUlpiRecoveryTransport {
            hw: &mut hw,
            host,
        };
        let mut agent = RecoveryAgent::new(transport, options).expect("RecoveryAgent::new");

        let discovery = agent.probe().expect("OCP Recovery probe (PROT_CAP + DEVICE_STATUS) failed");
        println!("[arch-b-recovery] OCP Discovery = {discovery:?}");

        let images = RecoveryImages {
            caliptra_fmc_rt: &binaries.caliptra_fw,
            soc_manifest: &binaries.soc_manifest,
            mcu_runtime: &binaries.mcu_runtime,
        };
        println!(
            "[arch-b-recovery] Streaming 3 signed images over internal FPGA ULPI High-Speed USB: caliptra_fw={}B, soc_manifest={}B, mcu_runtime={}B",
            images.caliptra_fmc_rt.len(),
            images.soc_manifest.len(),
            images.mcu_runtime.len()
        );

        let start = Instant::now();
        let outcome = agent
            .run(&images)
            .expect("Hardware-assisted USB 2.2 OCP Recovery failed on FPGA");
        let elapsed = start.elapsed();
        let transport = agent.into_transport();
        println!(
            "[arch-b-recovery] RecoveryAgent outcome={outcome:?} in {elapsed:.2?}, final ULPI diag={:?}",
            transport.host.diag()
        );
        assert_eq!(outcome, RecoveryOutcome::Confirmed);

        // Wait for MCU ROM to jump into the authenticated MCU Runtime in SRAM (0xA8C0_0000)
        let boot_deadline = Instant::now() + Duration::from_secs(20);
        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || Instant::now() >= boot_deadline
        });

        assert_eq!(
            hw.mci_fw_fatal_error(),
            None,
            "MCU reported fatal error after USB recovery"
        );
        assert!(
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE),
            "Expected FIRMWARE_BOOT_FLOW_COMPLETE after USB OCP Recovery boot; milestones=0x{:04x}",
            u16::from(hw.mci_boot_milestones())
        );
        println!(
            "[arch-b-recovery] SUCCESS! Caliptra FMC+RT + SoC Manifest + MCU Runtime booted end-to-end over Architecture B internal FPGA USB 2.2!"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
