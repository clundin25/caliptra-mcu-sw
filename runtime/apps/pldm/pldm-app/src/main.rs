// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

use embassy_sync::lazy_lock::LazyLock;
use libtockasync::TockExecutor;
use core::fmt::Write;
use libtock::alarm::Milliseconds;
use libtock_console::Console;
use libtock_platform::Syscalls;
use pldm_lib::timer::AsyncAlarm;

static EXECUTOR: LazyLock<TockExecutor> = LazyLock::new(TockExecutor::new);

#[allow(unused)]
use pldm_lib::daemon::PldmService;

#[allow(unused)]
use pldm_lib::firmware_device::fd_ops_mock::FdOpsObject;
use pldm_lib::firmware_device::fd_ops::FdOps;

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

#[cfg(not(target_arch = "riscv32"))]
#[embassy_executor::task]
async fn start() {
    async_main::<libtock_unittest::fake::Syscalls>().await;
}

#[cfg(target_arch = "riscv32")]
#[embassy_executor::task]
pub async fn pldm_service_task() {
    pldm_service::<libtock_runtime::TockSyscalls>().await;
}

#[cfg(not(target_arch = "riscv32"))]
#[embassy_executor::task]
async fn pldm_service_task() {
    pldm_service::<libtock_unittest::fake::Syscalls>().await;
}

pub async fn pldm_service<S: Syscalls>() {
    let mut console_writer = Console::<S>::writer();
    let fdops = FdOpsObject::<S>::new();
    let mut pldm_service = PldmService::<S>::init(&fdops, EXECUTOR.get().spawner());
    writeln!(
        console_writer,
        "PLDM_APP: Starting PLDM service for testing..."
    )
    .unwrap();
    if let Err(e) = pldm_service.start().await {
        writeln!(
            console_writer,
            "PLDM_APP: Error starting PLDM service: {:?}",
            e
        )
        .unwrap();
    }

}


pub(crate) async fn async_main<S: Syscalls>() {
    let mut console_writer = Console::<S>::writer();
    writeln!(console_writer, "PLDM_APP: Hello PLDM async world!").unwrap();

    // Print out alarm
    writeln!(
        console_writer,
        "PLDM_APP: Alarm: {:?}",
        AsyncAlarm::<S>::exists()
    )
    .unwrap();
    writeln!(
        console_writer,
        "PLDM_APP: Alarm frequency: {:?}",
        AsyncAlarm::<S>::get_frequency()
    )
    .unwrap();

    EXECUTOR.get().spawner().spawn(pldm_service_task()).unwrap();

    // sleep for 1 second
    AsyncAlarm::<S>::sleep(Milliseconds(1000)).await;

    loop {
        EXECUTOR.get().poll();
    }


        

        

}
