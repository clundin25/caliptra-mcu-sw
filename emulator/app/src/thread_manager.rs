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

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Disable parallel tests to avoid global state conflict
    #[test]
    fn test_spawn_and_wait_for_threads() {
        // Clean up global state (important if tests are run together)
        THREAD_HANDLES.lock().unwrap().clear();

        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        // Spawn 5 tracked threads
        for _ in 0..5 {
            spawn(|| {
                COUNTER.fetch_add(1, Ordering::SeqCst);
            });
        }

        wait_for_threads();

        // Verify all threads ran
        assert_eq!(COUNTER.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn test_spawn_multiple_batches() {
        // Clean up global state
        THREAD_HANDLES.lock().unwrap().clear();

        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        // First batch
        for _ in 0..3 {
            spawn(|| {
                COUNTER.fetch_add(1, Ordering::SeqCst);
            });
        }

        wait_for_threads();

        assert_eq!(COUNTER.load(Ordering::SeqCst), 3);
        assert!(THREAD_HANDLES.lock().unwrap().is_empty());

        // Second batch
        for _ in 0..2 {
            spawn(|| {
                COUNTER.fetch_add(1, Ordering::SeqCst);
            });
        }

        wait_for_threads();

        assert_eq!(COUNTER.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn test_spawn_with_long_running_thread() {
        // Clean up global state
        THREAD_HANDLES.lock().unwrap().clear();

        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        // Spawn a long-running thread
        spawn(|| {
            thread::sleep(std::time::Duration::from_secs(2));
            COUNTER.fetch_add(1, Ordering::SeqCst);
        });

        // Spawn a long-running thread
        spawn(|| {
            thread::sleep(std::time::Duration::from_secs(3));
            COUNTER.fetch_add(1, Ordering::SeqCst);
        });

        // Spawn a short-running thread
        spawn(|| {
            COUNTER.fetch_add(1, Ordering::SeqCst);
        });

        wait_for_threads();

        // Verify both threads ran
        assert_eq!(COUNTER.load(Ordering::SeqCst), 3);
    }
}
