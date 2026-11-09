// Licensed under the Apache-2.0 license

#[cfg(feature = "test-lpcip-usb-enumeration")]
pub fn enumeration_test() -> ! {
    caliptra_mcu_usb_common::enumeration_test(test_parameters())
}

pub const FPGA_USB_COMBO_ADDR: usize = 0xa420_0000;
pub const FPGA_USB_DEV0_MEM_ADDR: usize = 0xa430_0000;

pub fn test_parameters() -> caliptra_mcu_usb_common::UsbParams {
    use caliptra_mcu_romtime::StaticRef;
    use caliptra_mcu_usb_common::UsbParams;

    // Architecture B internal FPGA ULPI USB3320 PHY + High-Speed Host Loopback:
    // S_AXI_USB_COMBO is mapped at 0xA420_0000 and S_AXI_USB_DEV0_MEM at 0xA430_0000.
    UsbParams {
        registers: unsafe { StaticRef::new(FPGA_USB_COMBO_ADDR as *const _) },
        packet_memory: unsafe { StaticRef::new(FPGA_USB_DEV0_MEM_ADDR as *const _) },
        vendor_id: 0xffff,
        product_id: 0xffff,
        device_revision: 0x0100,
        self_powered: true,
        max_power_2ma: 0,
        remote_wakeup: false,
        force_full_speed: false,
        poll_limit: 1_000_000,
    }
}
