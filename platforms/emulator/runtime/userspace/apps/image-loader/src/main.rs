// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

mod config;

use core::fmt::Write;
use libtock_console::Console;
use libtock_platform::ErrorCode;
use libtockasync::TockExecutor;
#[allow(unused)]
use pldm_lib::daemon::PldmService;

use embassy_sync::lazy_lock::LazyLock;
use libapi_caliptra::image_loading::{ImageLoaderAPI, ImageSource, PldmDeviceParams};
use libsyscall_caliptra::DefaultSyscalls;

#[cfg(target_arch = "riscv32")]
mod riscv;

pub(crate) struct EmulatorExiter {}
pub(crate) static mut EMULATOR_EXITER: EmulatorExiter = EmulatorExiter {};
impl romtime::Exit for EmulatorExiter {
    fn exit(&mut self, code: u32) {
        // Safety: This is a safe memory address to write to for exiting the emulator.
        unsafe {
            // By writing to this address we can exit the emulator.
            core::ptr::write_volatile(0x1000_2000 as *mut u32, code);
        }
    }
}

static EXECUTOR: LazyLock<TockExecutor> = LazyLock::new(TockExecutor::new);

#[cfg(not(target_arch = "riscv32"))]
pub(crate) fn kernel() -> libtock_unittest::fake::Kernel {
    use libtock_unittest::fake;
    let kernel = fake::Kernel::new();
    let console = fake::Console::new();
    kernel.add_driver(&console);
    kernel
}

#[cfg(not(target_arch = "riscv32"))]
fn main() {
    // build a fake kernel so that the app will at least start without Tock
    let _kernel = kernel();
    // call the main function
    libtockasync::start_async(start());
}

#[embassy_executor::task]
async fn start() {
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_exiter(&mut EMULATOR_EXITER);
    }
    async_main().await;
}

pub(crate) async fn async_main() {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "IMAGE_LOADER_APP: Hello async world!").unwrap();
    EXECUTOR
        .get()
        .spawner()
        .spawn(image_loading_task())
        .unwrap();

    loop {
        EXECUTOR.get().poll();
    }
}

#[embassy_executor::task]
async fn image_loading_task() {
    match image_loading().await {
        Ok(_) => romtime::test_exit(0),
        Err(_) => romtime::test_exit(1),
    }
}

pub async fn image_loading() -> Result<(), ErrorCode> {
    if cfg!(feature = "test-pldm-streaming-boot") {
        let fw_params = PldmDeviceParams {
            descriptors: &config::DESCRIPTOR.get()[..],
            fw_params: config::STREAMING_BOOT_FIRMWARE_PARAMS.get(),
        };
        let pldm_image_loader: ImageLoaderAPI =
            ImageLoaderAPI::new(ImageSource::Pldm(fw_params), EXECUTOR.get().spawner());
        pldm_image_loader
            .load_and_authorize(config::IMAGE_ID1)
            .await?;
        pldm_image_loader
            .load_and_authorize(config::IMAGE_ID2)
            .await?;
        pldm_image_loader.finalize().await?;
    } else if cfg!(feature = "test-flash-streaming-boot") {
        let flash_image_loader: ImageLoaderAPI =
            ImageLoaderAPI::new(ImageSource::Flash, EXECUTOR.get().spawner());
        flash_image_loader
            .load_and_authorize(config::IMAGE_ID2)
            .await?;
        flash_image_loader.finalize().await?;
    }
    Ok(())
}
