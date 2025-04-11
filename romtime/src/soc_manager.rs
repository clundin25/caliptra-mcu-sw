// Licensed under the Apache-2.0 license

use core::mem;

use caliptra_api::{mailbox::MailboxRespHeader, CaliptraApiError, SocManager};
use registers_generated::{mbox, soc};
use ureg::RealMmioMut;

pub struct CaliptraSoC {
    _private: (), // ensure that this struct cannot be instantiated directly except through new
}

impl SocManager for CaliptraSoC {
    /// Address of the mailbox
    const SOC_MBOX_ADDR: u32 = mbox::MBOX_CSR_ADDR;

    /// Address of the SoC interface
    const SOC_IFC_ADDR: u32 = soc::SOC_IFC_REG_ADDR;

    /// Address of the SoC TRNG interface
    const SOC_IFC_TRNG_ADDR: u32 = soc::SOC_IFC_REG_ADDR;

    const SOC_SHA512_ACC_ADDR: u32 = soc::SOC_IFC_REG_ADDR; // TODO: remove this

    /// Maximum number of wait cycles.
    const MAX_WAIT_CYCLES: u32 = 400_000;

    /// Type alias for mutable memory-mapped I/O.
    type TMmio<'a> = RealMmioMut<'a>;

    /// Returns a mutable reference to the memory-mapped I/O.
    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        ureg::RealMmioMut::default()
    }

    /// Provides a delay function to be invoked when polling mailbox status.
    fn delay(&mut self) {}
}

impl CaliptraSoC {
    #[allow(clippy::new_without_default)] // we don't want people to create new ones with Default
    pub const fn new() -> Self {
        CaliptraSoC { _private: () }
    }

    pub fn is_mailbox_busy(&mut self) -> bool {
        self.soc_mbox().status().read().status().cmd_busy()
    }

    /// Send a command to the mailbox but don't wait for the response
    pub fn start_mailbox_req(
        &mut self,
        cmd: u32,
        len_bytes: usize,
        buf: impl Iterator<Item = u32>,
    ) -> core::result::Result<(), CaliptraApiError> {
        const MAILBOX_SIZE: usize = 256 * 1024;
        if len_bytes > MAILBOX_SIZE {
            return Err(CaliptraApiError::BufferTooLargeForMailbox);
        }

        // Read a 0 to get the lock
        if self.soc_mbox().lock().read().lock() {
            return Err(CaliptraApiError::UnableToLockMailbox);
        }

        // Mailbox lock value should read 1 now
        // If not, the reads are likely being blocked by the PAUSER check or some other issue
        if !(self.soc_mbox().lock().read().lock()) {
            return Err(CaliptraApiError::UnableToReadMailbox);
        }

        self.soc_mbox().cmd().write(|_| cmd);

        self.soc_mbox().dlen().write(|_| len_bytes as u32);

        for word in buf {
            self.soc_mbox().datain().write(|_| word);
        }

        // Ask Caliptra to execute this command
        self.soc_mbox().execute().write(|w| w.execute(true));

        Ok(())
    }

    /// Finished a mailbox request, validating the checksum of the response.
    pub fn finish_mailbox_resp(
        &mut self,
        resp_min_size: usize,
        resp_size: usize,
    ) -> core::result::Result<Option<CaliptraMailboxResponse>, CaliptraApiError> {
        if resp_size < mem::size_of::<MailboxRespHeader>() {
            return Err(CaliptraApiError::MailboxRespTypeTooSmall);
        }
        if resp_min_size < mem::size_of::<MailboxRespHeader>() {
            return Err(CaliptraApiError::MailboxRespTypeTooSmall);
        }

        // Wait for the microcontroller to finish executing
        let mut timeout_cycles = Self::MAX_WAIT_CYCLES; // 100ms @400MHz
        while self.soc_mbox().status().read().status().cmd_busy() {
            self.delay();
            timeout_cycles -= 1;
            if timeout_cycles == 0 {
                return Err(CaliptraApiError::MailboxTimeout);
            }
        }
        let status = self.soc_mbox().status().read().status();
        if status.cmd_failure() {
            self.soc_mbox().execute().write(|w| w.execute(false));
            let soc_ifc = self.soc_ifc();
            return Err(CaliptraApiError::MailboxCmdFailed(
                if soc_ifc.cptra_fw_error_fatal().read() != 0 {
                    soc_ifc.cptra_fw_error_fatal().read()
                } else {
                    soc_ifc.cptra_fw_error_non_fatal().read()
                },
            ));
        }
        if status.cmd_complete() {
            self.soc_mbox().execute().write(|w| w.execute(false));
            return Ok(None);
        }
        if !status.data_ready() {
            return Err(CaliptraApiError::UnknownCommandStatus(status as u32));
        }

        let dlen_bytes = self.soc_mbox().dlen().read();

        if dlen_bytes % 4 != 0 {
            return Err(CaliptraApiError::MailboxUnexpectedResponseLen {
                expected_min: dlen_bytes.next_multiple_of(4),
                expected_max: dlen_bytes.next_multiple_of(4),
                actual: dlen_bytes,
            });
        }

        let expected_checksum = self.soc_mbox().dataout().read();

        Ok(Some(CaliptraMailboxResponse {
            soc_mbox: self.soc_mbox(),
            idx: 0,
            dlen_words: dlen_bytes as usize / 4,
            checksum: 0,
            expected_checksum,
        }))
    }
}

pub struct CaliptraMailboxResponse<'a> {
    soc_mbox: caliptra_registers::mbox::RegisterBlock<RealMmioMut<'a>>,
    idx: usize,
    dlen_words: usize,
    checksum: u32,
    expected_checksum: u32,
}

impl CaliptraMailboxResponse<'_> {
    pub fn verify_checksum(&self) -> Result<(), CaliptraApiError> {
        let checksum = 0u32.wrapping_sub(self.checksum);
        if checksum == self.expected_checksum {
            Ok(())
        } else {
            Err(CaliptraApiError::MailboxRespInvalidChecksum {
                expected: self.expected_checksum,
                actual: checksum,
            })
        }
    }

    pub fn len(&self) -> usize {
        self.dlen_words * 4
    }

    pub fn is_empty(&self) -> bool {
        self.dlen_words == 0
    }
}

impl Iterator for CaliptraMailboxResponse<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.dlen_words {
            None
        } else if self.idx == 0 {
            self.idx += 1;
            Some(self.expected_checksum)
        } else {
            self.idx += 1;
            let data = self.soc_mbox.dataout().read();
            for x in data.to_le_bytes() {
                self.checksum = self.checksum.wrapping_add(x as u32);
            }
            Some(data)
        }
    }
}

impl Drop for CaliptraMailboxResponse<'_> {
    fn drop(&mut self) {
        // Release the lock
        self.soc_mbox.execute().write(|w| w.execute(false));
    }
}
