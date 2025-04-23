// Licensed under the Apache-2.0 license

// Component for DMA driver.

use core::mem::MaybeUninit;
use dma_driver::hil::DMA;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;



pub struct DmaComponent {
    driver: &'static dma_driver::dma_ctrl::EmulatedDmaCtrl<'static>,
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
}

impl DmaComponent {
    pub fn new(
        driver: &'static dma_driver::dma_ctrl::EmulatedDmaCtrl<'static>,
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,

    ) -> Self {
        Self {
            driver,
            board_kernel,
            driver_num,

        }
    }
}


impl Component for DmaComponent {
    type StaticInput = &'static mut MaybeUninit<capsules_runtime::dma::Dma<'static>>;

    type Output = &'static capsules_runtime::dma::Dma<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let dma: &capsules_runtime::dma::Dma<'_> =
            static_buffer
                .write(capsules_runtime::dma::Dma::new(
                    self.driver,
                    self.board_kernel.create_grant(self.driver_num, &grant_cap),
                ));
        self.driver.set_client(dma);
        dma
    }
}
