// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

use core::fmt::Write;
#[cfg(feature = "test-flash-usermode")]
use libsyscall_caliptra::flash::{driver_num as par_driver_num, FlashCapacity, SpiFlash};
use libtock::alarm::*;
use libtock_console::Console;
use libtock_platform::{self as platform};
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

#[cfg(feature = "test-pldm-request-response")]
mod test_pldm_request_response;

mod test_caliptra_mailbox;

mod test_get_image_info;

mod test_dma;

#[cfg(target_arch = "riscv32")]
mod riscv;

#[cfg(not(target_arch = "riscv32"))]
pub(crate) fn kernel() -> libtock_unittest::fake::Kernel {
    use libtock_unittest::fake;
    let kernel = fake::Kernel::new();
    let alarm = fake::Alarm::new(1_000_000);
    let console = fake::Console::new();
    kernel.add_driver(&alarm);
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

pub(crate) async fn async_main<S: Syscalls>() {
    let mut console_writer = Console::<S>::writer();
    writeln!(console_writer, "Hello async world!").unwrap();
    writeln!(
        console_writer,
        "Timer frequency: {}",
        AsyncAlarm::<S>::get_frequency().unwrap().0
    )
    .unwrap();

    match AsyncAlarm::<S>::exists() {
        Ok(()) => {}
        Err(e) => {
            writeln!(
                console_writer,
                "Alarm capsule not available, so skipping sleep loop: {:?}",
                e
            )
            .unwrap();
            return;
        }
    };

    for _ in 0..5 {
        writeln!(console_writer, "Sleeping for 1 millisecond").unwrap();
        sleep::<S>(Milliseconds(1)).await;
        writeln!(console_writer, "async sleeper woke").unwrap();
    }

    #[cfg(feature = "test-mctp-user-loopback")]
    {
        writeln!(
            console_writer,
            "Running test-mctp-user-loopback test for CALIPTRA message type"
        )
        .unwrap();

        test_mctp_loopback::<S>().await;
    }

    #[cfg(feature = "test-flash-usermode")]
    {
        writeln!(console_writer, "flash usermode test starts").unwrap();
        let mut user_r_buf: [u8; flash_test::BUF_LEN] = [0u8; flash_test::BUF_LEN];
        // Fill the write buffer with a pattern
        let user_w_buf: [u8; flash_test::BUF_LEN] = {
            let mut buf = [0u8; flash_test::BUF_LEN];
            for i in 0..buf.len() {
                buf[i] = (i % 256) as u8;
            }
            buf
        };

        let mut test_cfg_1 = flash_test::FlashTestConfig {
            drv_num: par_driver_num::ACTIVE_IMAGE_PARTITION,
            expected_capacity: flash_test::EXPECTED_CAPACITY,
            expected_chunk_size: flash_test::EXPECTED_CHUNK_SIZE,
            e_offset: 0,
            e_len: flash_test::BUF_LEN,
            w_offset: 20,
            w_len: 1000,
            w_buf: &user_w_buf,
            r_buf: &mut user_r_buf,
        };
        flash_test::simple_test::<S>(&mut test_cfg_1).await;
        writeln!(
            console_writer,
            "flash usermode test on active image par succeeds"
        )
        .unwrap();

        let mut test_cfg_2 = flash_test::FlashTestConfig {
            drv_num: par_driver_num::RECOVERY_IMAGE_PARTITION,
            expected_capacity: flash_test::EXPECTED_CAPACITY,
            expected_chunk_size: flash_test::EXPECTED_CHUNK_SIZE,
            e_offset: 0,
            e_len: flash_test::BUF_LEN,
            w_offset: 20,
            w_len: 1000,
            w_buf: &user_w_buf,
            r_buf: &mut user_r_buf,
        };
        flash_test::simple_test::<S>(&mut test_cfg_2).await;
        writeln!(
            console_writer,
            "flash usermode test on recovery image par succeeds"
        )
        .unwrap();

        // Terminate the emulator explicitly after the test is completed within app.
        unsafe {
            // By writing to this address we can exit the emulator.
            core::ptr::write_volatile(0x1000_2000 as *mut u32, 0);
        }
    }
    #[cfg(feature = "test-pldm-request-response")]
    {
//        test_pldm_request_response::test::test_pldm_request_response::<S>().await;
//        test_get_image_info::test_get_image_info::<S>().await;
//        test_get_image_info::test_authorize_and_stash::<S>().await;
        test_dma::test_dma::<S>().await;
    }
    #[cfg(feature = "test-caliptra-mailbox")]
    {
        test_caliptra_mailbox::test_caliptra_mailbox::<S>().await;
        test_caliptra_mailbox::test_caliptra_mailbox_bad_command::<S>().await;
        test_caliptra_mailbox::test_caliptra_mailbox_fail::<S>().await;
        romtime::test_exit(0);
    }

    writeln!(console_writer, "app finished").unwrap();
}

#[allow(dead_code)]
async fn test_mctp_loopback<S: Syscalls>() {
    use libsyscall_caliptra::mctp::{driver_num, Mctp};
    let mctp_spdm = Mctp::<S>::new(driver_num::MCTP_CALIPTRA);
    loop {
        let mut msg_buffer: [u8; 1024] = [0; 1024];

        assert!(mctp_spdm.exists());
        let max_msg_size = mctp_spdm.max_message_size();
        assert!(max_msg_size.is_ok());
        assert!(max_msg_size.unwrap() > 0);

        let result = mctp_spdm.receive_request(&mut msg_buffer).await;
        assert!(result.is_ok());
        let (msg_len, msg_info) = result.unwrap();
        let msg_len = msg_len as usize;
        assert!(msg_len <= msg_buffer.len());

        let result = mctp_spdm
            .send_response(&msg_buffer[..msg_len], msg_info)
            .await;
        assert!(result.is_ok());
    }
}

#[cfg(feature = "test-flash-usermode")]
pub mod flash_test {
    use super::*;
    pub const BUF_LEN: usize = 1024;
    pub const EXPECTED_CAPACITY: FlashCapacity = FlashCapacity(0x200_0000);
    pub const EXPECTED_CHUNK_SIZE: usize = 512;

    pub struct FlashTestConfig<'a> {
        pub drv_num: u32,
        pub expected_capacity: FlashCapacity,
        pub expected_chunk_size: usize,
        pub e_offset: usize,
        pub e_len: usize,
        pub w_offset: usize,
        pub w_len: usize,
        pub w_buf: &'a [u8],
        pub r_buf: &'a mut [u8],
    }

    pub async fn simple_test<'a, S: Syscalls>(test_cfg: &'a mut FlashTestConfig<'a>) {
        let flash_par = SpiFlash::<S>::new(test_cfg.drv_num);
        assert_eq!(
            flash_par.get_capacity().unwrap(),
            test_cfg.expected_capacity
        );
        assert_eq!(
            flash_par.get_chunk_size().unwrap(),
            test_cfg.expected_chunk_size
        );

        let ret = flash_par.erase(test_cfg.e_offset, test_cfg.e_len).await;
        assert_eq!(ret, Ok(()));

        // Write test region partially
        let ret = flash_par
            .write(test_cfg.w_offset, test_cfg.w_len, test_cfg.w_buf as &[u8])
            .await;
        assert_eq!(ret, Ok(()));

        // Read the written region
        let ret = flash_par
            .read(
                test_cfg.w_offset,
                test_cfg.w_len,
                test_cfg.r_buf as &mut [u8],
            )
            .await;
        assert_eq!(ret, Ok(()));

        // Data compare read and write
        for i in 0..test_cfg.w_len {
            assert_eq!(
                test_cfg.r_buf[i], test_cfg.w_buf[i],
                "data mismatch at {}",
                i
            );
        }

        // Reset read buffer
        test_cfg.r_buf.iter_mut().for_each(|x| *x = 0);

        // Read whole test region
        let ret = flash_par
            .read(
                test_cfg.e_offset,
                test_cfg.e_len,
                test_cfg.r_buf as &mut [u8],
            )
            .await;
        assert_eq!(ret, Ok(()));

        // Data integrity check
        {
            for i in 0..test_cfg.w_offset.min(test_cfg.r_buf.len()) {
                assert_eq!(test_cfg.r_buf[i], 0xFF, "data mismatch at {}", i);
            }
            for i in
                test_cfg.w_offset..(test_cfg.w_offset + test_cfg.w_len).min(test_cfg.r_buf.len())
            {
                assert_eq!(
                    test_cfg.r_buf[i],
                    test_cfg.w_buf[i - test_cfg.w_offset],
                    "data mismatch at {}",
                    i
                );
            }

            for i in (test_cfg.w_offset + test_cfg.w_len).min(test_cfg.r_buf.len())
                ..test_cfg.e_len.min(test_cfg.r_buf.len())
            {
                assert_eq!(test_cfg.r_buf[i], 0xFF, "data mismatch at {}", i);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

const DRIVER_NUM: u32 = 0;

// Command IDs
#[allow(unused)]
mod command {
    pub const EXISTS: u32 = 0;
    pub const FREQUENCY: u32 = 1;
    pub const TIME: u32 = 2;
    pub const STOP: u32 = 3;

    pub const SET_RELATIVE: u32 = 5;
    pub const SET_ABSOLUTE: u32 = 6;
}

#[allow(unused)]
mod subscribe {
    pub const CALLBACK: u32 = 0;
}

pub(crate) async fn sleep<S: Syscalls>(time: Milliseconds) {
    let x = AsyncAlarm::<S>::sleep_for(time).await;
    writeln!(Console::<S>::writer(), "Async sleep done {:?}", x).unwrap();
}

pub struct AsyncAlarm<S: Syscalls, C: platform::subscribe::Config = DefaultConfig>(S, C);

impl<S: Syscalls, C: platform::subscribe::Config> AsyncAlarm<S, C> {
    /// Run a check against the console capsule to ensure it is present.
    #[inline(always)]
    #[allow(dead_code)]
    pub fn exists() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, command::EXISTS, 0, 0).to_result()
    }

    pub fn get_frequency() -> Result<Hz, ErrorCode> {
        S::command(DRIVER_NUM, command::FREQUENCY, 0, 0)
            .to_result()
            .map(Hz)
    }

    #[allow(dead_code)]
    pub fn get_ticks() -> Result<u32, ErrorCode> {
        S::command(DRIVER_NUM, command::TIME, 0, 0).to_result()
    }

    #[allow(dead_code)]
    pub fn get_milliseconds() -> Result<u64, ErrorCode> {
        let ticks = Self::get_ticks()? as u64;
        let freq = (Self::get_frequency()?).0 as u64;

        Ok(ticks.saturating_div(freq / 1000))
    }

    pub async fn sleep_for<T: Convert>(time: T) -> Result<(), ErrorCode> {
        let freq = Self::get_frequency()?;
        let ticks = time.to_ticks(freq).0;
        writeln!(Console::<S>::writer(), "Sleeping for {} ticks", ticks).unwrap();
        let sub = TockSubscribe::subscribe::<S>(DRIVER_NUM, 0);
        S::command(DRIVER_NUM, command::SET_RELATIVE, ticks, 0)
            .to_result()
            .map(|_when: u32| ())?;
        sub.await.map(|_| ())
    }
}

#[cfg(test)]
mod test {
    use super::{command, kernel, sleep};
    use libtock_alarm::Milliseconds;
    use libtock_unittest::fake;
    use libtock_unittest::fake::Alarm;
    use libtockasync::TockExecutor;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{LazyLock, Mutex};

    #[test]
    fn test_frequency() {
        use fake::SyscallDriver;
        let alarm = Alarm::new(10);

        assert_eq!(
            alarm.command(command::FREQUENCY, 1, 2).get_success_u32(),
            Some(10)
        );
    }

    static SLEEP_COUNTER: LazyLock<Mutex<AtomicU32>> =
        LazyLock::new(|| Mutex::new(AtomicU32::new(0)));

    #[embassy_executor::task]
    async fn run_sleep() {
        sleep::<fake::Syscalls>(Milliseconds(1)).await;
        SLEEP_COUNTER
            .lock()
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);
        // ensure there is always an upcall scheduled
        loop {
            sleep::<fake::Syscalls>(Milliseconds(1)).await;
        }
    }

    #[test]
    fn test_async_sleep() {
        let kernel = kernel();
        let mut executor = TockExecutor::new();
        // Safety: we are upgrading the executor for the lifetime of the test only.
        // This needs to be in the same scope as the test for the static upgrade to work.
        let executor: &'static mut TockExecutor = unsafe { core::mem::transmute(&mut executor) };

        executor.spawner().spawn(run_sleep()).unwrap();
        for _ in 0..10 {
            executor.poll();
        }
        assert_eq!(SLEEP_COUNTER.lock().unwrap().load(Ordering::Relaxed), 1);
        drop(kernel);
    }
}
