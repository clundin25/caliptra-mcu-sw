// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

use core::fmt::Write;
use libtock_console::Console;
use libtock_platform::Syscalls;
use libtockasync::TockExecutor;
#[allow(unused)]
use pldm_lib::daemon::PldmService;

use libapi_caliptra::image_loading::{ImageLoaderAPI, ImageSource};
use pldm_common::protocol::firmware_update::{Descriptor, DescriptorType};
use embassy_sync::lazy_lock::LazyLock;

#[cfg(target_arch = "riscv32")]
mod riscv;

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

#[cfg(target_arch = "riscv32")]
#[embassy_executor::task]
async fn start() {
    async_main::<libtock_runtime::TockSyscalls>().await;
}

pub const DEVICE_UUID: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];
static DESCRIPTOR: embassy_sync::lazy_lock::LazyLock<[Descriptor; 1]> =
    embassy_sync::lazy_lock::LazyLock::new(|| {
        [Descriptor::new(DescriptorType::Uuid, &DEVICE_UUID).unwrap()]
    });


static EXECUTOR: LazyLock<TockExecutor> = LazyLock::new(TockExecutor::new);

#[cfg(not(target_arch = "riscv32"))]
#[embassy_executor::task]
async fn start() {
    use pldm_common::protocol::firmware_update::DescriptorType;

    async_main::<libtock_unittest::fake::Syscalls>().await;
}


#[cfg(target_arch = "riscv32")]
#[embassy_executor::task]
pub async fn image_loading_task() {
    image_loading::<libtock_runtime::TockSyscalls>().await;
}

#[cfg(not(target_arch = "riscv32"))]
#[embassy_executor::task]
async fn image_loading_task() {
    image_loading::<libtock_unittest::fake::Syscalls>().await;
}

pub async fn image_loading<S: Syscalls>() {
    let image_loader: ImageLoaderAPI<S> =
        ImageLoaderAPI::new(ImageSource::Pldm(&DESCRIPTOR.get()[..]), EXECUTOR.get().spawner()).await;
    image_loader.load_and_authorize(1).await.unwrap();
//    image_loader.load_and_authorize(2).await.unwrap();
    image_loader.finalize().await.unwrap();

}


pub(crate) async fn async_main<S: Syscalls>() {
    let mut console_writer = Console::<S>::writer();
    writeln!(console_writer, "PLDM_APP: Hello PLDM async world!").unwrap();
    EXECUTOR
    .get()
    .spawner()
    .spawn(image_loading_task())
    .unwrap();


    loop {
        EXECUTOR.get().poll();
    }
}
