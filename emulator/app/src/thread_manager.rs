// Licensed under the Apache-2.0 license

//! This module is a wrapper for spawning threads and tracking them.
//!
//! It provides functionality to spawn threads while keeping track of their handles,
//! and offers an interface to wait for all the threads to finish execution. The module
//! uses synchronization primitives such as `std::sync::Mutex` to ensure safe access
//! to shared resources across multiple threads.
use std::sync::Mutex;
use std::thread::{self, JoinHandle};

lazy_static::lazy_static! {
    static ref THREAD_HANDLES: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());
}

pub fn spawn<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    let handle = thread::spawn(f);
    THREAD_HANDLES.lock().unwrap().push(handle);
}

pub fn wait_for_threads() {
    let handles = THREAD_HANDLES.lock().unwrap().drain(..).collect::<Vec<_>>();
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

