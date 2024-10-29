use pldm::dummy_transport::{DummyEndpoint, DummyEndpointId, DummyTransport};
use pldm::transport::{Endpoint, TransportError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_send_and_receive_success() {
    let transport = DummyTransport::new();

    // Create and add endpoint 1
    let id1 = DummyEndpointId::new(1);
    let mut endpoint1 = DummyEndpoint::new(&id1, &transport);

    // Send a packet to endpoint 1
    let packet = vec![0x01, 0x02, 0x03];
    let send_result = endpoint1.send(&id1, &packet);
    assert!(send_result.is_ok(), "Sending should be successful");

    // Prepare buffer to receive the packet
    let mut receive_buffer = [0u8; 5];
    let receive_result = endpoint1.receive(&id1, &mut receive_buffer, None);
    assert!(receive_result.is_ok(), "Receiving should be successful");

    // Verify the received data
    let bytes_received = receive_result.unwrap();
    assert_eq!(bytes_received, 3, "3 bytes should be received");
    assert_eq!(
        &receive_buffer[..bytes_received],
        &[0x01, 0x02, 0x03],
        "Received data should match the sent packet"
    );
}

#[test]
fn test_receive_with_timeout() {
    let transport = DummyTransport::new();

    // Create and add endpoint 2
    let id = DummyEndpointId::new(2);
    let mut endpoint = DummyEndpoint::new(&id, &transport);

    // Prepare buffer to receive the packet (but don't send anything)
    let mut receive_buffer = [0u8; 5];

    // Attempt to receive with a 1 second timeout
    let timeout = Some(Duration::from_secs(1));
    let receive_result = endpoint.receive(&id, &mut receive_buffer, timeout);

    // Expect a timeout error
    assert!(
        matches!(receive_result, Err(TransportError::Timeout)),
        "Receiving should timeout"
    );
}

#[test]
fn test_receive_with_insufficient_buffer() {
    let transport = DummyTransport::new();

    // Create and add endpoint 3
    let id = DummyEndpointId::new(3);
    let mut endpoint = DummyEndpoint::new(&id, &transport);

    // Send a packet with more bytes than the receive buffer can handle
    let packet = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let send_result = endpoint.send(&id, &packet);
    assert!(send_result.is_ok(), "Sending should be successful");

    // Prepare a smaller buffer (only 3 bytes) for receiving
    let mut receive_buffer = [0u8; 3];
    let receive_result = endpoint.receive(&id, &mut receive_buffer, None);

    // Verify only 3 bytes are received
    let bytes_received = receive_result.unwrap();
    assert_eq!(bytes_received, 3, "Only 3 bytes should be received");
    assert_eq!(
        &receive_buffer[..bytes_received],
        &[0xAA, 0xBB, 0xCC],
        "Received data should match the first 3 bytes of the sent packet"
    );
}

#[test]
fn test_threads_send_and_receive_between_endpoints() {
    let transport = Arc::new(DummyTransport::new());
    // Create two endpoints, one for each thread
    let id1 = Arc::new(DummyEndpointId::new(1));
    let id2 = Arc::new(DummyEndpointId::new(2));

    let mut endpoint1 = DummyEndpoint::new(id1.as_ref(), transport.as_ref());
    let mut endpoint2 = DummyEndpoint::new(id2.as_ref(), transport.as_ref());

    // Define the message for each thread to send
    let message_from_thread1 = Arc::new(vec![0x11, 0x22, 0x33]);
    let message_from_thread2 = Arc::new(vec![0xAA, 0xBB, 0xCC]);

    // Spawn thread 1: Send message to endpoint 2 and receive message from endpoint 2
    let id2_t1 = id2.clone();
    let message1_t1 = message_from_thread1.clone();
    let message2_t1 = message_from_thread2.clone();

    let handle1 = thread::spawn(move || {
        // Send a message from endpoint 1 to endpoint 2
        endpoint1
            .send(id2_t1.as_ref(), &message1_t1)
            .expect("Thread 1 failed to send message");

        // Prepare a buffer to receive the message from endpoint 2
        let mut receive_buffer = [0u8; 3];

        // Receive the message from endpoint 2 with no timeout
        let received_bytes = endpoint1
            .receive(id2_t1.as_ref(), &mut receive_buffer, None)
            .expect("Thread 1 failed to receive message");

        // Verify the received message is correct
        assert_eq!(received_bytes, 3, "Thread 1 should receive 3 bytes");
        assert_eq!(
            &receive_buffer[..received_bytes],
            &message2_t1.to_vec(),
            "Thread 1 received incorrect message"
        );
    });

    // Spawn thread 2: Send message to endpoint 1 and receive message from endpoint 1
    let message1_t2 = message_from_thread1.clone();
    let message2_t2 = message_from_thread2.clone();
    let id1_t2 = id1.clone();
    let handle2 = thread::spawn(move || {
        // Send a message from endpoint 2 to endpoint 1
        endpoint2
            .send(id1_t2.as_ref(), &message2_t2)
            .expect("Thread 2 failed to send message");

        // Prepare a buffer to receive the message from endpoint 1
        let mut receive_buffer = [0u8; 3];

        // Receive the message from endpoint 1 with no timeout
        let received_bytes = endpoint2
            .receive(id1_t2.as_ref(), &mut receive_buffer, None)
            .expect("Thread 2 failed to receive message");

        // Verify the received message is correct
        assert_eq!(received_bytes, 3, "Thread 2 should receive 3 bytes");
        assert_eq!(
            &receive_buffer[..received_bytes],
            &message1_t2.to_vec(),
            "Thread 2 received incorrect message"
        );
    });

    // Wait for both threads to complete
    handle1.join().expect("Thread 1 panicked");
    handle2.join().expect("Thread 2 panicked");
}
