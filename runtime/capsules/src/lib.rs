// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![forbid(unsafe_code)]

pub mod test;

pub mod dma;
pub mod flash_partition;
pub mod mailbox;
pub mod mctp;
