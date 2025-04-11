// Licensed under the Apache-2.0 license

use crate::static_ref::StaticRef;
use registers_generated::mci;
use tock_registers::interfaces::{Readable, Writeable};

pub const MCI_BASE: StaticRef<mci::regs::Mci> =
    unsafe { StaticRef::new(mci::MCI_REG_ADDR as *const mci::regs::Mci) };

pub struct Mci {
    registers: StaticRef<mci::regs::Mci>,
}

impl Mci {
    pub const fn new(registers: StaticRef<mci::regs::Mci>) -> Self {
        Mci { registers }
    }

    pub fn caliptra_boot_go(&self) {
        self.registers.cptra_boot_go.set(1);
    }

    pub fn flow_status(&self) -> u32 {
        self.registers.fw_flow_status.get()
    }
}
