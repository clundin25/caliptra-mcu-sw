// Licensed under the Apache-2.0 license

use alloc::boxed::Box;
use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use libtock_platform::exit_on_drop::ExitOnDrop;
use libtock_platform::*;
use romtime::println;
/// TockSubscribe is a future implementation that performs a Tock subscribe call and
/// is ready when the subscribe upcall happens.
///
/// When the future is ready, it will contain arguments the upcall was called with.
///
/// Use like: `TockSubscribe::<TockSyscalls>::subscribe(driver_num, subscribe_num).await`.
pub struct TockSubscribe {
    result: Cell<Option<(u32, u32, u32)>>,
    waker: Cell<Option<Waker>>,
    error: Option<ErrorCode>,
}

impl TockSubscribe {
    fn new() -> TockSubscribe {
        TockSubscribe {
            result: Cell::new(None),
            waker: Cell::new(None),
            error: None,
        }
    }

    fn set_err(&mut self, err: ErrorCode) {
        self.error = Some(err);
    }

    pub fn subscribe_allow_rw<S: Syscalls, C: allow_rw::Config>(
        driver_num: u32,
        subscribe_num: u32,
        buffer_num: u32,
        buffer: &mut [u8],
    ) -> impl Future<Output = Result<(u32, u32, u32), ErrorCode>> {
        // Pinning is necessary since we are passing a pointer to the TockSubscribe to the kernel.
        let mut f = Pin::new(Box::new(TockSubscribe::new()));
        let upcall_fcn = (kernel_upcall::<S> as *const ()) as usize;
        let upcall_data = (&*f as *const TockSubscribe) as usize;

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, r2, _] = unsafe {
            S::syscall4::<{ syscall_class::ALLOW_RW }>([
                driver_num.into(),
                buffer_num.into(),
                buffer.as_mut_ptr().into(),
                buffer.len().into(),
            ])
        };

        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                f.set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                f.set_err(ErrorCode::Fail);
            }
        }

        let returned_buffer: (usize, usize) = (r1.into(), r2.into());
        if returned_buffer != (0, 0) {
            C::returned_nonzero_buffer(driver_num, buffer_num);
        }

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe_num.into(),
                upcall_fcn.into(),
                upcall_data.into(),
            ])
        };
        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                f.set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                f.set_err(ErrorCode::Fail);
            }
        }
        f
    }

    pub fn subscribe_allow_ro<S: Syscalls, C: allow_ro::Config>(
        driver_num: u32,
        subscribe_num: u32,
        buffer_num: u32,
        buffer: &[u8],
    ) -> impl Future<Output = Result<(u32, u32, u32), ErrorCode>> {
        // Pinning is necessary since we are passing a pointer to the TockSubscribe to the kernel.
        let mut f = Pin::new(Box::new(TockSubscribe::new()));
        let upcall_fcn = (kernel_upcall::<S> as *const ()) as usize;
        let upcall_data = (&*f as *const TockSubscribe) as usize;

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, r2, _] = unsafe {
            S::syscall4::<{ syscall_class::ALLOW_RO }>([
                driver_num.into(),
                buffer_num.into(),
                buffer.as_ptr().into(),
                buffer.len().into(),
            ])
        };

        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                f.set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                f.set_err(ErrorCode::Fail);
            }
        }

        let returned_buffer: (usize, usize) = (r1.into(), r2.into());
        if returned_buffer != (0, 0) {
            C::returned_nonzero_buffer(driver_num, buffer_num);
        }

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe_num.into(),
                upcall_fcn.into(),
                upcall_data.into(),
            ])
        };
        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                f.set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                f.set_err(ErrorCode::Fail);
            }
        }
        f
    }

    pub fn subscribe_allow_ro_rw<S: Syscalls, C: allow_rw::Config>(
        driver_num: u32,
        subscribe_num: u32,
        buffer_ro_num: u32,
        buffer_ro: &[u8],
        buffer_rw_num: u32,
        buffer_rw: &mut [u8],
    ) -> impl Future<Output = Result<(u32, u32, u32), ErrorCode>> {
        // Pinning is necessary since we are passing a pointer to the TockSubscribe to the kernel.
        let mut f = Pin::new(Box::new(TockSubscribe::new()));
        let upcall_fcn = (kernel_upcall::<S> as *const ()) as usize;
        let upcall_data = (&*f as *const TockSubscribe) as usize;

        // Allow RO
        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, r2, _] = unsafe {
            S::syscall4::<{ syscall_class::ALLOW_RO }>([
                driver_num.into(),
                buffer_ro_num.into(),
                buffer_ro.as_ptr().into(),
                buffer_ro.len().into(),
            ])
        };

        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                f.set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                f.set_err(ErrorCode::Fail);
            }
        }

        let returned_buffer: (usize, usize) = (r1.into(), r2.into());
        if returned_buffer != (0, 0) {
            C::returned_nonzero_buffer(driver_num, buffer_ro_num);
        }

        // Allow RW
        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, r2, _] = unsafe {
            S::syscall4::<{ syscall_class::ALLOW_RW }>([
                driver_num.into(),
                buffer_rw_num.into(),
                buffer_rw.as_mut_ptr().into(),
                buffer_rw.len().into(),
            ])
        };

        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                f.set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                f.set_err(ErrorCode::Fail);
            }
        }

        let returned_buffer: (usize, usize) = (r1.into(), r2.into());
        if returned_buffer != (0, 0) {
            C::returned_nonzero_buffer(driver_num, buffer_rw_num);
        }

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe_num.into(),
                upcall_fcn.into(),
                upcall_data.into(),
            ])
        };
        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                f.set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                f.set_err(ErrorCode::Fail);
            }
        }
        f
    }

    pub fn subscribe<S: Syscalls>(
        driver_num: u32,
        subscribe_num: u32,
    ) -> impl Future<Output = Result<(u32, u32, u32), ErrorCode>> {
        // Pinning is necessary since we are passing a pointer to the TockSubscribe to the kernel.
        let mut f = Pin::new(Box::new(TockSubscribe::new()));
        let upcall_fcn = (kernel_upcall::<S> as *const ()) as usize;
        let upcall_data = (&*f as *const TockSubscribe) as usize;

        println!("syscall subscribe f={:08x}", &f as *const _ as usize);

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe_num.into(),
                upcall_fcn.into(),
                upcall_data.into(),
            ])
        };
        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                f.set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
                println!("syscall error");
            }
            _ => {
                f.set_err(ErrorCode::Fail);
                println!("syscall error2");
            }
        }
        f
    }
}

extern "C" fn kernel_upcall<S: Syscalls>(arg0: u32, arg1: u32, arg2: u32, data: Register) {
    let exit: ExitOnDrop<S> = Default::default();
    let upcall: *mut TockSubscribe = data.into();
    // Safety: we set the pointer to a pinned TockSubscribe instance in the subscribe.
    // If the subscribe call had failed, then the error would have been set this upcall
    // will never be called.
    // If the reference to the TockSubscribe is dropped before the upcall, then we panic
    // in the Drop instead of dereferencing into an invalid pointer.
    println!("kernel_upcalle f={:08x}", upcall as *const _ as usize);
    unsafe { (*upcall).result.set(Some((arg0, arg1, arg2))) };
    if let Some(waker) = unsafe { (*upcall).waker.take() } {
        waker.wake();
    }
    core::mem::forget(exit);
}

impl Future for TockSubscribe {
    type Output = Result<(u32, u32, u32), ErrorCode>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(err) = self.error {
            return Poll::Ready(Err(err));
        }
        if let Some(ret) = self.result.get() {
            Poll::Ready(Ok(ret))
        } else {
            // set ourselves to wake when the upcall happens
            self.waker.replace(Some(cx.waker().clone()));
            // we don't call yield ourself, but let the executor call yield
            Poll::Pending
        }
    }
}

impl Drop for TockSubscribe {
    fn drop(&mut self) {
        if self.result.get().is_none() && self.error.is_none() {
            panic!("The TockSubscribe future was dropped before the upcall happened.");
        }
    }
}
