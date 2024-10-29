// This module defines the traits and structures required to implement a transport layer
// for PLDM communication. The `Endpoint` trait represents a communication interface that
// can send and receive PLDM packets, while `EndpointId` is an abstract identifier for each
// endpoint. The `TransportError` enum provides a comprehensive set of error conditions
// that may occur during transport operations, such as timeouts, connection issues, and
// invalid packets.

use core::fmt;
use std::any::Any;
use std::time::Duration;

// Trait representing a unique identifier for a transport endpoint.
// The `EndpointId` trait is implemented by any type that can serve as an endpoint identifier.
pub trait EndpointId: Any + fmt::Debug {
    // Allows the endpoint ID to be downcast to a concrete type if needed.
    fn as_any(&self) -> &dyn Any;
}

// Trait defining the interface for a transport endpoint.
// This trait includes methods to send and receive PLDM packets, with error handling.
pub trait Endpoint {
    // Sends a PLDM packet to the specified endpoint.
    // Takes a reference to an `EndpointId` and a byte slice representing the packet data.
    fn send(&mut self, endpoint: &dyn EndpointId, packet: &[u8]) -> Result<(), TransportError>;

    // Receives a PLDM packet from the specified endpoint.
    // Fills the provided buffer with the received data and may specify a timeout duration.
    fn receive(
        &mut self,
        endpoint: &dyn EndpointId,
        buffer: &mut [u8],
        timeout: Option<Duration>,
    ) -> Result<usize, TransportError>;
}

// Enum representing various errors that can occur during transport operations.
// These errors provide details about potential issues, such as timeouts and connection losses.
#[derive(Debug)]
pub enum TransportError {
    /// The operation timed out.
    Timeout,

    /// The connection to the endpoint was lost.
    ConnectionLost,

    /// The packet received or sent was invalid.
    InvalidPacket,

    /// The specified endpoint was unavailable.
    EndpointUnavailable,

    /// Operation failed
    OperationFailed,
}
