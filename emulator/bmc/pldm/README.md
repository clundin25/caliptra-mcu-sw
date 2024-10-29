# PLDM RUST Library

This Rust package implements the Platform Level Data Model (PLDM) protocol, supporting its integration into various firmware and hardware solutions. The library is designed to facilitate communication using the PLDM protocol by providing a flexible and modular API.

## Directory Structure

.
├── src
│   ├── firmware_update            # Module for PLDM firmware update operations
│   ├── dummy_transport.rs         # Example transport layer for testing purposes
│   ├── lib.rs                     # Library entry point
│   ├── packet.rs                  # Module for PLDM packet encoding/decoding
│   └── transport.rs               # Transport abstraction layer for PLDM
├── tests
│   ├── package                    # Test data for firmware update testing
│   │   ├── firmware_package.bin   # Sample firmware package
│   │   ├── img_00.bin             # Firmware image file
│   │   ├── img_01.bin             # Another firmware image file
│   │   └── manifest.toml          # Sample manifest for firmware package
│   ├── test_dummy_transport.rs    # Unit tests for dummy transport
│   ├── test_packet.rs             # Unit tests for packet encoding/decoding
│   └── test_query_device_identifier.rs # Tests for querying device identifiers
└── Cargo.toml                     # Package manifest


## Features

- **Packet Management**: Encoding and decoding of PLDM packets in compliance with the standard.
- **Firmware Update Support**: Functionality to manage firmware packages, utilizing `.bin` image files and manifest files.
- **Transport Abstraction**: A flexible transport layer to interface with various transport protocols, making it adaptable to different hardware setups.
- **Logging Support**: Configurable logging through `logger.rs` for easier debugging.
- **Testing Framework**: A dedicated `tests` directory with multiple test files and sample data for comprehensive unit testing.

## Getting Started

# Implement a Transport layer

The PLDM Transport layer is required to be implemented according to the provided `transport.rs` interface. This layer defines how packets are sent and received, allowing for flexibility in choosing specific transport protocols. Refer to `dummy_transport.rs` as a reference implementation.

Note that the `EndpointId` is a unique identifier for a device in a PLDM network. This could be an unsigned integer as used in MCTP, or IP address in TCP/IP network, UUID, etc. This will depend on the transport implementation.

The implementation in dummy_transport.rs is used for in-process exchange of PLDM packets between different threads within the same process. If inter-process communication (IPC) or a network-based transport is needed, you should create another implementation of the Endpoint trait that meets those requirements.

# Firmware Update

This module implements an Update Agent which provides a firmware update service for a PLDM terminus.


