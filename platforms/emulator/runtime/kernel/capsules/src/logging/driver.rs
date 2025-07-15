// Licensed under the Apache-2.0 license

//! This provides the logging syscall driver

//use core::cmp;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::hil::log::{LogRead, LogReadClient, LogWrite, LogWriteClient};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{ErrorCode, ProcessId};

pub const LOGGING_FLASH_DRIVER_NUM: usize = 0x9000_0001;

pub const BUF_LEN: usize = 512;

/// IDs for subscribed upcalls.
mod upcall {
    pub const READ_DONE: usize = 0;
    pub const SEEK_DONE: usize = 1;
    pub const APPEND_DONE: usize = 2;
    pub const SYNC_DONE: usize = 3;
    pub const ERASE_DONE: usize = 4;
    /// Number of upcalls.
    pub const COUNT: u8 = 5;
}

/// Ids for read-only allow buffers
mod ro_allow {
    /// Setup a buffer to write bytes to the flash storage.
    pub const APPEND: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

/// Ids for read-write allow buffers
mod rw_allow {
    /// Setup a buffer to read from the flash storage into.
    pub const READ: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

mod logging_cmd {
    pub const READ: u32 = 1;
    pub const APPEND: u32 = 2;
    pub const SEEK: u32 = 3;
    pub const SYNC: u32 = 4;
    pub const ERASE: u32 = 5;
    pub const GET_CAP: u32 = 6;
}

// Define logging commands

#[derive(Clone, Copy, PartialEq)]
pub enum LoggingOps {
    Idle,
    Read,
    Seek,
    Apend,
    Sync,
    Erase,
}

pub struct App {
    pending_command: bool,
    command: LoggingOps,
    arg1: usize, // For buffer length or entry_id
    arg2: usize, // For future use or extra param
}

impl Default for App {
    fn default() -> App {
        App {
            pending_command: false,
            command: LoggingOps::Idle,
            arg1: 0,
            arg2: 0,
        }
    }
}

pub trait LogReadWrite<'a>: LogRead<'a, EntryID = usize> + LogWrite<'a> {}
impl<'a, T: LogRead<'a, EntryID = usize> + LogWrite<'a>> LogReadWrite<'a> for T {}

pub struct LoggingFlashDriver<'a> {
    driver: &'a dyn LogReadWrite<'a>,
    // Per-app state.
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    // Internal buffer for copying appslices into.
    buffer: TakeCell<'static, [u8]>,
    current_app: OptionalCell<ProcessId>,
}

impl<'a> LoggingFlashDriver<'a> {
    pub fn new(
        driver: &'a dyn LogReadWrite<'a>,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        buffer: &'static mut [u8],
    ) -> LoggingFlashDriver<'a> {
        LoggingFlashDriver {
            driver,
            apps: grant,
            buffer: TakeCell::new(buffer),
            current_app: OptionalCell::empty(),
        }
    }

    // Check if any command is pending. If not, this command is executed.
    // If so, this command is queued and will be run when the pending
    // command is completed.
    /*
    fn enqueue_command(
        &self,
        command: FlashStorageCommand,
        offset: usize,
        length: usize,
        processid: Option<ProcessId>,
    ) -> Result<(), ErrorCode> {
        // Do bounds check. Userspace sees memory that starts at address 0 even if it
        // is offset in the physical memory.
        if offset >= self.length || length > self.length || offset + length > self.length {
            return Err(ErrorCode::INVAL);
        }

        if self.buffer.is_none() {
            return Err(ErrorCode::RESERVE);
        }

        processid.map_or(Err(ErrorCode::FAIL), |processid| {
            self.apps
                .enter(processid, |app, kernel_data| {
                    // Get the length of the correct allowed buffer.
                    let allow_buf_len = match command {
                        FlashStorageCommand::Read => kernel_data
                            .get_readwrite_processbuffer(rw_allow::READ)
                            .map_or(0, |read| read.len()),
                        FlashStorageCommand::Write => kernel_data
                            .get_readonly_processbuffer(ro_allow::WRITE)
                            .map_or(0, |read| read.len()),
                        _ => 0,
                    };

                    if command != FlashStorageCommand::Erase && allow_buf_len == 0 {
                        return Err(ErrorCode::RESERVE);
                    }

                    // Shorten the length if the application gave us nowhere to
                    // put it.
                    let active_len = if let FlashStorageCommand::Erase = command {
                        length
                    } else {
                        cmp::min(length, allow_buf_len)
                    };

                    // Check if this command can be executed immediately or queued.
                    if self.current_app.is_none() {
                        // No app is currently using the underlying storage.
                        // Mark this app as active, and then execute the command.
                        self.current_app.set(processid);

                        // Need to copy bytes if this is a write.
                        if command == FlashStorageCommand::Write {
                            let _ = kernel_data
                                .get_readonly_processbuffer(ro_allow::WRITE)
                                .and_then(|write| {
                                    write.enter(|app_buffer| {
                                        self.buffer.map(|kernel_buffer| {
                                            // Check that the internal buffer and the buffer that was
                                            // allowed are long enough.
                                            let write_len =
                                                cmp::min(active_len, kernel_buffer.len());

                                            let d = &app_buffer[0..write_len];
                                            d.copy_to_slice(&mut kernel_buffer[0..write_len]);
                                        });
                                    })
                                });
                        }

                        self.userspace_call_driver(command, offset, active_len)
                    } else if app.pending_command {
                        // No more room in the queue, nowhere to store this request.
                        Err(ErrorCode::NOMEM)
                    } else {
                        // Queue this request.
                        app.pending_command = true;
                        app.command = command;
                        app.offset = offset;
                        app.length = active_len;
                        Ok(())
                    }
                })
                .unwrap_or_else(|err| Err(err.into()))
        })
    }*/

    // Enqueue a log command, following the pattern from flash_partition.rs
    fn enqueue_command(
        &self,
        command: LoggingOps,
        processid: Option<ProcessId>,
        arg1: usize, // For buffer length or entry_id
        arg2: usize, // For future use or extra param
    ) -> Result<(), ErrorCode> {
        processid.map_or(Err(ErrorCode::FAIL), |processid| {
            self.apps
                .enter(processid, |app, kernel_data| {
                    let (needs_buffer, allow_buf_len) = match command {
                        LoggingOps::Read => (
                            true,
                            kernel_data
                                .get_readwrite_processbuffer(rw_allow::READ)
                                .map_or(0, |read| read.len()),
                        ),
                        LoggingOps::Apend => (
                            true,
                            kernel_data
                                .get_readonly_processbuffer(ro_allow::APPEND)
                                .map_or(0, |write| write.len()),
                        ),
                        _ => (false, 0),
                    };
                    if needs_buffer && (allow_buf_len == 0 || self.buffer.is_none()) {
                        return Err(ErrorCode::RESERVE);
                    }

                    if self.current_app.is_none() {
                        self.current_app.set(processid);
                        if command == LoggingOps::Apend {
                            let _ = kernel_data
                                .get_readonly_processbuffer(ro_allow::APPEND)
                                .and_then(|write| {
                                    write.enter(|app_buffer| {
                                        self.buffer.map(|kernel_buffer| {
                                            let write_len =
                                                arg1.min(app_buffer.len()).min(kernel_buffer.len());
                                            let d = &app_buffer[0..write_len];
                                            d.copy_to_slice(&mut kernel_buffer[0..write_len]);
                                        });
                                    })
                                });
                        }
                        self.userspace_call_driver(command, arg1, arg2)
                    } else if app.pending_command {
                        Err(ErrorCode::NOMEM)
                    } else {
                        app.pending_command = true;
                        app.command = command;
                        app.arg1 = arg1;
                        app.arg2 = arg2;
                        Ok(())
                    }
                })
                .unwrap_or_else(|err| Err(err.into()))
        })
    }

    // Actually start the log operation for the current app
    fn userspace_call_driver(
        &self,
        command: LoggingOps,
        arg1: usize,
        _arg2: usize,
    ) -> Result<(), ErrorCode> {
        match command {
            LoggingOps::Read | LoggingOps::Apend => {
                // At this point, buffer is guaranteed to be available and pre-filled if needed
                let buffer = self.buffer.take().ok_or(ErrorCode::RESERVE)?;
                let len = arg1.min(buffer.len());
                let res = match command {
                    LoggingOps::Read => self.driver.read(buffer, len),
                    LoggingOps::Apend => self.driver.append(buffer, len),
                    _ => unreachable!(),
                };
                match res {
                    Ok(()) => Ok(()),
                    Err((ecode, buf)) => {
                        self.buffer.replace(buf);
                        Err(ecode)
                    }
                }
            }
            LoggingOps::Seek => self.driver.seek(arg1),
            LoggingOps::Sync => self.driver.sync(),
            LoggingOps::Erase => self.driver.erase(),
            LoggingOps::Idle => Ok(()),
        }
    }

    fn check_queue(&self) {
        for cntr in self.apps.iter() {
            let processid = cntr.processid();
            let started_command = cntr.enter(|app, _| {
                if app.pending_command {
                    app.pending_command = false;
                    self.current_app.set(processid);
                    matches!(
                        self.userspace_call_driver(app.command, app.arg1, app.arg2),
                        Ok(_)
                    )
                } else {
                    false
                }
            });
            if started_command {
                break;
            }
        }
    }
}

impl<'a> LogReadClient for LoggingFlashDriver<'a> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize, error: Result<(), ErrorCode>) {
        if let Some(pid) = self.current_app.take() {
            let _ = self.apps.enter(pid, |_, kernel_data| {
                let _ = kernel_data
                    .get_readwrite_processbuffer(rw_allow::READ)
                    .and_then(|app_buf| {
                        app_buf.mut_enter(|app_data| {
                            let read_len = length.min(app_data.len());
                            if error.is_ok() {
                                app_data[..read_len].copy_from_slice(&buffer[..read_len]);
                            }
                        })
                    });

                // Replace the buffer that is used to do this read.
                self.buffer.replace(buffer);

                kernel_data
                    .schedule_upcall(
                        upcall::READ_DONE,
                        (length, error.err().map(|e| e as usize).unwrap_or(0), 0),
                    )
                    .ok();
            });
        }

        self.check_queue();
    }

    fn seek_done(&self, error: Result<(), ErrorCode>) {
        if let Some(pid) = self.current_app.take() {
            let _ = self.apps.enter(pid, |_, kernel_data| {
                kernel_data
                    .schedule_upcall(
                        upcall::SEEK_DONE,
                        (error.err().map(|e| e as usize).unwrap_or(0), 0, 0),
                    )
                    .ok();
            });
        }
        self.check_queue();
    }
}

impl<'a> LogWriteClient for LoggingFlashDriver<'a> {
    fn append_done(
        &self,
        buffer: &'static mut [u8],
        length: usize,
        records_lost: bool,
        error: Result<(), ErrorCode>,
    ) {
        if let Some(pid) = self.current_app.take() {
            let _ = self.apps.enter(pid, |_, kernel_data| {
                self.buffer.replace(buffer);
                kernel_data
                    .schedule_upcall(
                        upcall::APPEND_DONE,
                        (
                            length,
                            records_lost as usize,
                            error.err().map(|e| e as usize).unwrap_or(0),
                        ),
                    )
                    .ok();
            });
        }

        self.check_queue();
    }

    fn sync_done(&self, error: Result<(), ErrorCode>) {
        if let Some(pid) = self.current_app.take() {
            let _ = self.apps.enter(pid, |_, kernel_data| {
                kernel_data
                    .schedule_upcall(
                        upcall::SYNC_DONE,
                        (error.err().map(|e| e as usize).unwrap_or(0), 0, 0),
                    )
                    .ok();
            });
        }
        self.check_queue();
    }

    fn erase_done(&self, error: Result<(), ErrorCode>) {
        if let Some(pid) = self.current_app.take() {
            let _ = self.apps.enter(pid, |_, kernel_data| {
                kernel_data
                    .schedule_upcall(
                        upcall::ERASE_DONE,
                        (error.err().map(|e| e as usize).unwrap_or(0), 0, 0),
                    )
                    .ok();
            });
        }
        self.check_queue();
    }
}

// Provide an interface for userland.
impl<'a> SyscallDriver for LoggingFlashDriver<'a> {
    fn command(
        &self,
        command_num: usize,
        arg1: usize,
        arg2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_num as u32 {
            0 => CommandReturn::success(),

            logging_cmd::GET_CAP => {
                // For demonstration, just return a dummy capacity value.
                // Replace with actual logic if needed.
                CommandReturn::success_u32(self.driver.get_size() as u32)
            }
            logging_cmd::READ => {
                match self.enqueue_command(LoggingOps::Read, Some(processid), arg1, arg2) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            logging_cmd::APPEND => {
                match self.enqueue_command(LoggingOps::Apend, Some(processid), arg1, arg2) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            logging_cmd::SEEK => {
                match self.enqueue_command(LoggingOps::Seek, Some(processid), arg1, arg2) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            logging_cmd::SYNC => {
                match self.enqueue_command(LoggingOps::Sync, Some(processid), arg1, arg2) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            logging_cmd::ERASE => {
                match self.enqueue_command(LoggingOps::Erase, Some(processid), arg1, arg2) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
