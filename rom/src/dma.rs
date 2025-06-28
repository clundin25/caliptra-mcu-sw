// Licensed under the Apache-2.0 license


/// DMA Route configuration for Read/Write routes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DmaRoute {
    Disabled,
    AxiToAxi,
}

    /// Represents the current status of the DMA transfer.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DMAStatus {
    TxnDone,        // Transaction complete
    RdFifoNotEmpty, // Read FIFO has data
    RdFifoFull,     // Read FIFO is full
    WrFifoNotFull,  // Write FIFO has room for more data
    WrFifoEmpty,    // Write FIFO is empty
}

/// Represents possible DMA errors.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DMAError {
    CommandError,     // General command error
    AxiReadError,     // AXI Read error
    AxiWriteError,    // AXI Write error
    MailboxNotLocked, // Mailbox lock not acquired
    RdFifoOverflow,   // Data overflow in Read FIFO
    RdFifoUnderflow,  // Data underflow in Read FIFO
    WrFifoOverflow,   // Data overflow in Write FIFO
    WrFifoUnderflow,  // Data underflow in Write FIFO
}
pub trait Dma {
    fn configure_transfer(
        &self,
        byte_count: usize,
        block_size: usize,
        src_addr: Option<u64>,
        dest_addr: Option<u64>,
    ) -> Result<(), DMAError>;

    fn start_transfer(
        &self,
        route: DmaRoute,
    ) -> Result<(), DMAError>;

    fn wait_transaction_done(&self) -> Result<DMAStatus, DMAError>;

    fn write_fifo(&self, data: &[u8]) -> Result<(), DMAError>;

}