// Licensed under the Apache-2.0 license

use crate::cmd_interface::CmdInterface;
use crate::config;
use crate::firmware_device::fd_context::FirmwareDeviceContext;
use crate::timer::AsyncAlarm;
use libtock_alarm::Milliseconds;

use crate::transport::MctpTransport;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use libsyscall_caliptra::mctp::driver_num;

use libtock_platform::Syscalls;
use libtockasync::{self, TockExecutor};

// Debug usage
use core::fmt::Write;
use libtock_console::Console;

pub const MAX_MCTP_PLDM_MSG_SIZE: usize = 1024;

#[derive(Debug)]
pub enum PldmServiceError {
    StartError,
    StopError,
}

/// Represents a PLDM (Platform Level Data Model) service.
///
/// The `PldmService` struct encapsulates the command interface and the running state
/// of the PLDM service.
///
/// # Type Parameters
///
/// * `'a` - A lifetime parameter for the command interface.
/// * `S` - A type that implements the `Syscalls` trait, representing the system calls
///   used by the command interface.
///
/// # Fields
///
/// * `cmd_interface` - The command interface used by the PLDM service.
/// * `running` - An atomic boolean indicating whether the PLDM service is currently running.
/// * `initiator_signal` - A signal used to activate the PLDM initiator task.
pub struct PldmService<S: Syscalls> {
    cmd_interface: CmdInterface<'static, S>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
}

// Note: This implementation is a starting point for integration testing.
// It will be extended and refactored to support additional PLDM commands in both responder and requester modes.
impl<S: Syscalls> PldmService<S> {
    pub fn init() -> Self {
        let cmd_interface = CmdInterface::new(
            //driver_num::MCTP_PLDM,
            config::PLDM_PROTOCOL_CAPABILITIES.get(),
            FirmwareDeviceContext::new(),
        );
        Self {
            cmd_interface,
            running: {
                static RUNNING: AtomicBool = AtomicBool::new(false);
                &RUNNING
            },
            initiator_signal: {
                static INITIATOR_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
                &INITIATOR_SIGNAL
            },
        }
    }

    pub async fn start(&mut self) -> Result<(), PldmServiceError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(PldmServiceError::StartError);
        }

        self.running.store(true, Ordering::SeqCst);

        let mut responder_executor = TockExecutor::new();
        let responder_executor: &'static mut TockExecutor =
            unsafe { core::mem::transmute(&mut responder_executor) };

        let cmd_interface: &'static CmdInterface<'static, libtock_runtime::TockSyscalls> =
            unsafe { core::mem::transmute(&self.cmd_interface) };

        responder_executor
            .spawner()
            .spawn(pldm_responder_task(
                cmd_interface,
                self.running,
                self.initiator_signal,
            ))
            .unwrap();

        let mut initiator_executor = TockExecutor::new();
        let initiator_executor: &'static mut TockExecutor =
            unsafe { core::mem::transmute(&mut initiator_executor) };
        initiator_executor
            .spawner()
            .spawn(pldm_initiator_task(
                cmd_interface,
                self.running,
                self.initiator_signal,
            ))
            .unwrap();

        loop {
            responder_executor.poll();
            initiator_executor.poll();
        }
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[embassy_executor::task]
pub async fn pldm_initiator_task(
    cmd_interface: &'static CmdInterface<'static, libtock_runtime::TockSyscalls>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    pldm_initiator::<libtock_runtime::TockSyscalls>(cmd_interface, running, initiator_signal).await;
}

#[embassy_executor::task]
pub async fn pldm_responder_task(
    cmd_interface: &'static CmdInterface<'static, libtock_runtime::TockSyscalls>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    pldm_responder::<libtock_runtime::TockSyscalls>(cmd_interface, running, initiator_signal).await;
}

pub async fn pldm_initiator<S: Syscalls>(
    cmd_interface: &'static CmdInterface<'static, S>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    // Wait for signal from responder before starting the loop
    initiator_signal.wait().await;

    let mut msg_buffer = [0; MAX_MCTP_PLDM_MSG_SIZE];

    let mut transport = MctpTransport::<S>::new(driver_num::MCTP_PLDM);

    // Print out message that the initiator task has started
    let mut console_writer = Console::<S>::writer();
    writeln!(
        console_writer,
        "[xs debug]pldm_dameon: Initiator task started"
    )
    .unwrap();

    while running.load(Ordering::SeqCst) {
        let _ = cmd_interface
            .initiate_firmware_request(&mut transport, &mut msg_buffer)
            .await;

        // Sleep for a short duration to avoid busy waiting
        // AsyncAlarm::<S>::sleep(Milliseconds(1)).await;
    }
}

pub async fn pldm_responder<S: Syscalls>(
    cmd_interface: &'static CmdInterface<'static, S>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    let mut transport = MctpTransport::<S>::new(driver_num::MCTP_PLDM);

    let mut msg_buffer = [0; MAX_MCTP_PLDM_MSG_SIZE];

    // Print out message that the initiator task has started
    let mut console_writer = Console::<S>::writer();
    writeln!(
        console_writer,
        "[xs debug]pldm_dameon: responder task started"
    )
    .unwrap();

    while running.load(Ordering::SeqCst) {
        // Directly access cmd_interface without locking
        let _ = cmd_interface
            .handle_msg(&mut transport, &mut msg_buffer)
            .await;

        // When FD state is download state, signal the initiator task
        if cmd_interface.is_start_initiator_mode().await && !initiator_signal.signaled() {
            initiator_signal.signal(());
        }
    }
}
