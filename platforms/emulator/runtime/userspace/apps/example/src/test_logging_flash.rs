// Licensed under the Apache-2.0 license

use core::fmt::Write;
use libsyscall_caliptra::logging::LoggingSyscall;
use libtock_platform::ErrorCode;
use romtime::println;

pub async fn test_logging_flash_simple() {
    println!("[xs debug] test_logging_flash_simple started");

    let log: LoggingSyscall = LoggingSyscall::new();

    // driver exists
    assert!(log.exists().is_ok(), "Logging driver doesn't exist");

    // Read logging capacity
    let capacity = log.get_capacity();
    println!("[xs debug] Logging capacity: {:?}", capacity);

    // seek beginning
    let seek_result = log.seek_beginning().await;
    println!("[xs debug] Seek beginning test result: {:?}", seek_result);

    // Erase empty log
    let erase_result = log.clear().await;
    println!("[xs debug] Erase empty log result: {:?}", erase_result);

    //  Write log entries
    let entry1 = b"Entry 1: Hello";
    let entry2 = b"Entry 2: World";
    let append_result1 = log.append_entry(entry1).await;
    println!("[xs debug]Append result 1: {:?}", append_result1);

    let append_result2 = log.append_entry(entry2).await;
    println!("[xs debug]Append result 2: {:?}", append_result2);

    // 3) Read back entries and compare
    let mut buffer = [0u8; 128];
    let read_result1 = log.read_entry(&mut buffer).await;
    println!("[xs debug] Read entry 0 result: {:?}", read_result1);

    if let Ok(len) = read_result1 {
        let entry_str = core::str::from_utf8(&buffer[..len]).unwrap_or("");
        println!("Entry 0 contents: {:?}", entry_str);
        assert_eq!(entry_str, "Entry 1: Hello");
    }

    // reset buffer
    buffer.fill(0);
    let read_result2 = log.read_entry(&mut buffer).await;
    println!("Read entry 1 result: {:?}", read_result2);
    if let Ok(len) = read_result2 {
        let entry_str = core::str::from_utf8(&buffer[..len]).unwrap_or("");
        println!("Entry 1 contents: {:?}", entry_str);
        assert_eq!(entry_str, "Entry 2: World");
    }

    // sync to ensure data is flushed
    let sync_result = log.sync().await;
    println!("[xs debug] Sync result: {:?}", sync_result);

    // 4) Clear entries
    let clear_result = log.clear().await;
    println!("[xs debug] Clear result: {:?}", clear_result);

    // 5) Read back to ensure empty
    let read_after_clear = log.read_entry(&mut buffer).await;
    println!("Read after clear: {:?}", read_after_clear);
    assert!(read_after_clear.is_err(), "Log should be empty after clear");

    romtime::println!("[xs debug] test_logging_flash_simple completed");
}

pub async fn test_logging_flash_various_entries() {
    println!("[xs debug] test_logging_flash_various_entries started");

    let log: LoggingSyscall = LoggingSyscall::new();
    assert!(log.exists().is_ok(), "Logging driver doesn't exist");

    let capacity = log.get_capacity();
    println!("[xs debug] Logging capacity: {:?}", capacity);

    // Seek to beginning and clear log
    log.seek_beginning().await.ok();
    log.clear().await.ok();

    // Define entries
    let small_entries: [&[u8]; 4] = [b"Small 1", b"Small 2", b"Small 3", b"Small 4"];
    let medium_entries: [&[u8]; 4] = [
        b"Medium entry 1: abcdefghijklmnop",
        b"Medium entry 2: qrstuvwxyz012345",
        b"Medium entry 3: 6789abcdefghij",
        b"Medium entry 4: klmnopqrstuvwx",
    ];
    let large_entries: [&[u8]; 4] = [
        &[b'L'; 100][..], // 100 bytes
        &[b'M'; 120][..], // 120 bytes
        &[b'N'; 127][..], // 127 bytes
        &[b'O'; 128][..], // 128 bytes (assuming page size >= 128)
    ];

    // Append small entries
    for (i, entry) in small_entries.iter().enumerate() {
        let res = log.append_entry(entry).await;
        println!("[xs debug] Append small entry {}: {:?}", i, res);
        assert!(res.is_ok(), "Failed to append small entry {}", i);
    }

    // Append medium entries
    for (i, entry) in medium_entries.iter().enumerate() {
        let res = log.append_entry(entry).await;
        println!("[xs debug] Append medium entry {}: {:?}", i, res);
        assert!(res.is_ok(), "Failed to append medium entry {}", i);
    }

    // Append large entries
    for (i, entry) in large_entries.iter().enumerate() {
        let res = log.append_entry(entry).await;
        println!("[xs debug] Append large entry {}: {:?}", i, res);
        assert!(res.is_ok(), "Failed to append large entry {}", i);
    }

    // Read back and compare
    let mut buffer = [0u8; 128];
    let total_entries = 12;
    for i in 0..total_entries {
        buffer.fill(0);
        let read_result = log.read_entry(&mut buffer).await;
        println!("[xs debug] Read entry {} result: {:?}", i, read_result);
        assert!(read_result.is_ok(), "Failed to read entry {}", i);
        let len = read_result.unwrap();
        let expected: &[u8] = if i < 4 {
            small_entries[i]
        } else if i < 8 {
            medium_entries[i - 4]
        } else {
            large_entries[i - 8]
        };
        assert_eq!(&buffer[..len], expected, "Entry {} contents mismatch", i);
    }

    // Sync to ensure data is flushed
    let sync_result = log.sync().await;
    println!("[xs debug] Sync result: {:?}", sync_result);
    assert!(sync_result.is_ok(), "Sync failed");

    // Clear entries
    let clear_result = log.clear().await;
    println!("[xs debug] Clear result: {:?}", clear_result);
    assert!(clear_result.is_ok(), "Clear failed");

    // Read back to ensure empty
    buffer.fill(0);
    let read_after_clear = log.read_entry(&mut buffer).await;
    println!("[xs debug] Read after clear: {:?}", read_after_clear);
    assert!(read_after_clear.is_err(), "Log should be empty after clear");

    romtime::println!("[xs debug] test_logging_flash_various_entries completed");
}

pub async fn test_logging_flash_empty_log() {
    println!("[xs debug] test_logging_flash_empty_log started");

    let log: LoggingSyscall = LoggingSyscall::new();
    assert!(log.exists().is_ok(), "Logging driver doesn't exist");

    let seek_result = log.seek_beginning().await;
    println!("[xs debug] Seek beginning result: {:?}", seek_result);
    assert!(
        seek_result.is_ok(),
        "Seek beginning failed: {:?}",
        seek_result
    );

    let mut buffer = [0u8; 128];
    let read_result = log.read_entry(&mut buffer).await;
    println!("[xs debug] Read from empty log result: {:?}", read_result);
    assert!(
        read_result == Err(ErrorCode::Fail),
        "Read from empty log should return error"
    );

    // sync empty log
    let sync_result = log.sync().await;
    println!("[xs debug] Sync empty log result: {:?}", sync_result);
    assert!(
        sync_result.is_ok(),
        "Sync empty log failed: {:?}",
        sync_result
    );

    // Erase empty log
    let erase_result = log.clear().await;
    println!("[xs debug] Erase empty log result: {:?}", erase_result);
    assert!(
        erase_result.is_ok(),
        "Erase empty log failed: {:?}",
        erase_result
    );

    println!("[xs debug] test_logging_flash_read_empty_log completed");
}

pub async fn test_logging_flash_write_when_full() {
    println!("[xs debug] test_logging_flash_write_when_full started");

    let log: LoggingSyscall = LoggingSyscall::new();
    assert!(log.exists().is_ok(), "Logging driver doesn't exist");

    log.seek_beginning().await.ok();
    log.clear().await.ok();

    let capacity = log.get_capacity();
    println!("[xs debug] Logging capacity: {:?}", capacity);

    // Fill the log to capacity
    let entry = &[b'F'; 64][..];
    let mut count = 0;
    let max_entries = 756; // assuming each entry is 64 bytes + 4 bytes.
    loop {
        let res = log.append_entry(entry).await;
        if res.is_err() {
            println!("[xs debug] Log full after {} entries", count);
            break;
        }
        count += 1;
        if count > max_entries as usize + 2 {
            // avoid infinite loop
            println!("[xs debug] Unexpected: log did not fill as expected");
            break;
        }
    }

    // Try to append one more entry
    let res = log.append_entry(entry).await;
    println!("[xs debug] Append after full result: {:?}", res);

    println!("[xs debug] test_logging_flash_write_when_full completed");
}

pub async fn test_logging_flash_very_large_entry() {
    println!("[xs debug] test_logging_flash_very_large_entry started");

    let log: LoggingSyscall = LoggingSyscall::new();
    assert!(log.exists().is_ok(), "Logging driver doesn't exist");

    log.seek_beginning().await.ok();
    log.clear().await.ok();

    // Entry larger than buffer/page size
    let large_entry = &[b'X'; 1024][..]; // 1KB entry, likely too large
    let res = log.append_entry(large_entry).await;
    println!("[xs debug] Append very large entry result: {:?}", res);
    assert!(res.is_err(), "Should not append very large entry");

    println!("[xs debug] test_logging_flash_very_large_entry completed");
}

pub async fn test_logging_flash_invalid_inputs() {
    println!("[xs debug] test_logging_flash_invalid_inputs started");

    let log: LoggingSyscall = LoggingSyscall::new();
    assert!(log.exists().is_ok(), "Logging driver doesn't exist");

    log.seek_beginning().await.ok();
    log.clear().await.ok();

    // Try to append empty entry
    let empty_entry: &[u8] = &[];
    let res = log.append_entry(empty_entry).await;
    println!("[xs debug] Append empty entry result: {:?}", res);
    assert!(res.is_err(), "Should not append empty entry");

    // Try to read with zero-sized buffer
    let mut zero_buf = [];
    let read_res = log.read_entry(&mut zero_buf).await;
    println!(
        "[xs debug] Read with zero-sized buffer result: {:?}",
        read_res
    );
    assert!(read_res.is_err(), "Should not read with zero-sized buffer");

    println!("[xs debug] test_logging_flash_invalid_inputs completed");
}
