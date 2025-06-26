// Licensed under the Apache-2.0 license

pub mod flash_api;
pub mod flash_ctrl;

#[cfg(any(
    feature = "test-mcu-rom-flash-access",
    feature = "test-flash-based-boot"
))]
pub mod flash_test;
