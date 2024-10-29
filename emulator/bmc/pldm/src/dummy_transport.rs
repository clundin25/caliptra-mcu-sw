// This module provides a dummy transport implementation for in-process PLDM packet
// exchange using Tokio's broadcast channel. This transport layer is suitable for testing
// PLDM functionality within a single process, simulating endpoint communication without
// relying on external IPC or network layers. The `DummyTransport` struct handles message
// broadcasting, and `DummyEndpoint` allows for sending and receiving packets.

use crate::transport::{Endpoint, EndpointId, TransportError};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use std::any::Any;
use tokio::runtime::Runtime;
use tokio::sync::broadcast::{self, Receiver};
use tokio::time::timeout;

const TRANSPORT_BUFFER_SIZE: usize = 1024; // Maximum buffer size for broadcast messages

// Struct representing a message with source endpoint ID and packet data
#[derive(Debug, Clone)]
struct Message {
    src_endpoint_id: u32, // ID of the sending endpoint
    packet: Vec<u8>,      // Packet data as a byte vector
}

// Example implementation of an EndpointId, used to identify each dummy endpoint
#[derive(Debug, Clone)]
pub struct DummyEndpointId {
    pub id: u32, // Unique identifier for the endpoint
}

impl EndpointId for DummyEndpointId {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl DummyEndpointId {
    // Creates a new DummyEndpointId with the specified ID
    pub fn new(id: u32) -> Self {
        DummyEndpointId { id }
    }
}

// DummyTransport handles broadcasting messages to multiple endpoints
pub struct DummyTransport {
    transport: broadcast::Sender<Message>, // Sender for broadcasting messages
}

impl Default for DummyTransport {
    // Provides a default implementation for DummyTransport, creating a new instance
    fn default() -> Self {
        Self::new()
    }
}

impl DummyTransport {
    // Creates a new DummyTransport with a broadcast channel for message exchange
    pub fn new() -> DummyTransport {
        let (transport, _) = broadcast::channel(TRANSPORT_BUFFER_SIZE);
        DummyTransport { transport }
    }
}

// DummyEndpoint represents a transport endpoint, managing sending and receiving
// of PLDM packets through the broadcast channel
pub struct DummyEndpoint {
    id: Box<DummyEndpointId>,               // Unique identifier for the endpoint
    tx_ch: Arc<broadcast::Sender<Message>>, // Shared sender for message broadcasting
    rx_ch: Receiver<Message>,               // Receiver for incoming messages
}

impl DummyEndpoint {
    // Creates a new DummyEndpoint using the provided DummyEndpointId and DummyTransport
    pub fn new(id: &DummyEndpointId, tx_ch: &DummyTransport) -> Self {
        DummyEndpoint {
            id: Box::new(id.clone()),                 // Clone the endpoint ID
            tx_ch: Arc::new(tx_ch.transport.clone()), // Share the transport sender
            rx_ch: tx_ch.transport.subscribe(),       // Subscribe to the broadcast channel
        }
    }
}

impl Endpoint for DummyEndpoint {
    // Sends a packet to the specified endpoint
    fn send(&mut self, _endpoint: &dyn EndpointId, packet: &[u8]) -> Result<(), TransportError> {
        let message = Message {
            src_endpoint_id: self.id.id, // Set source endpoint ID
            packet: packet.to_vec(),     // Copy packet data into a new message
        };
        println!("Sending message: {:?}", message);

        // Send the message through the broadcast channel, handling any errors
        self.tx_ch
            .send(message)
            .map_err(|_| TransportError::OperationFailed)?;
        Ok(())
    }

    // Receives a packet from the specified endpoint, with an optional timeout
    fn receive(
        &mut self,
        endpoint: &dyn EndpointId,
        buffer: &mut [u8],
        timeout_duration: Option<StdDuration>,
    ) -> Result<usize, TransportError> {
        // Cast the endpoint to a DummyEndpointId, required for ID comparison
        let endpoint = endpoint
            .as_any()
            .downcast_ref::<DummyEndpointId>()
            .ok_or(TransportError::OperationFailed)?;
        println!("Receiving from endpoint id: {:?}", endpoint.id);

        // Initialize a Tokio runtime to manage async tasks
        let rt = Runtime::new().map_err(|_| TransportError::OperationFailed)?;
        let receiver = &mut self.rx_ch;

        // If a timeout duration is specified, wait with a timeout
        if let Some(duration) = timeout_duration {
            let result = rt.block_on(async {
                // Timeout block for receiving messages
                timeout(duration, async {
                    loop {
                        // Wait for a message to be received
                        if let Ok(message) = receiver.recv().await {
                            // Check if the message is from the target endpoint
                            if message.src_endpoint_id == endpoint.id {
                                let length = message.packet.len().min(buffer.len());
                                buffer[..length].copy_from_slice(&message.packet[..length]); // Copy data to buffer
                                println!("Received message: {:?}", message);
                                return Ok(length); // Return the length of the received data
                            }
                        }
                    }
                })
                .await
            });
            // Handle timeout or successful message receipt
            result.map_err(|_| TransportError::Timeout)?
        } else {
            // Receive without timeout, looping until a message is received from the target endpoint
            rt.block_on(async {
                loop {
                    if let Ok(message) = receiver.recv().await {
                        // Check if the message is from the target endpoint
                        if message.src_endpoint_id == endpoint.id {
                            let length = message.packet.len().min(buffer.len());
                            buffer[..length].copy_from_slice(&message.packet[..length]);
                            println!("Received message: {:?}", message);
                            return Ok::<usize, TransportError>(length);
                        }
                    }
                }
            })
        }
    }
}
