use pldm_fw_pkg::Descriptor;
use std::io::{Cursor, Error, ErrorKind, Result};

// Enum defining the various PLDM commands supported by Firmware Update
pub enum PldmCommand {
    // Inventory Commands
    QueryDeviceIdentifiers = 0x01, // Command to query device identifiers
    GetFirmwareParameters = 0x02,  // Command to get firmware parameters
    QueryDownstreamDevices = 0x03, // Command to query downstream devices
    QueryDownstreamIdentifiers = 0x04, // Command to query downstream device identifiers
    GetDownstreamFirmwareParameters = 0x05, // Command to get firmware parameters of downstream devices

    // Update Commands
    RequestUpdate = 0x10,         // Initiates a firmware update request
    GetPackageData = 0x11,        // Command to retrieve package data
    GetDeviceMetaData = 0x12,     // Command to retrieve device metadata
    PassComponentTable = 0x13,    // Command to pass component table for updates
    UpdateComponent = 0x14,       // Command to update a specific component
    RequestFirmwareData = 0x15,   // Requests data for firmware update
    TransferComplete = 0x16,      // Indicates completion of data transfer
    VerifyComplete = 0x17,        // Indicates completion of verification process
    ApplyComplete = 0x18,         // Indicates completion of applying update
    GetMetaData = 0x19,           // Command to get metadata for update
    ActivateFirmware = 0x1A,      // Command to activate new firmware
    GetStatus = 0x1B,             // Retrieves the status of the update process
    CancelUpdateComponent = 0x1C, // Command to cancel update of a component
    CancelUpdate = 0x1D,          // Command to cancel the firmware update
    ActivatePendingComponentImageSet = 0x1E, // Activates pending component image set
    ActivatePendingComponentImage = 0x1F, // Activates a specific pending component image
    RequestDownstreamDeviceUpdate = 0x20, // Requests firmware update for downstream device
    GetComponentOpaqueData = 0x21, // Retrieves opaque data for a component
    UpdateSecurityRevision = 0x22, // Updates security revision of the firmware
}

// Struct representing the response to a QueryDeviceIdentifiers command
#[derive(Debug)]
pub struct QueryDeviceIdentifierResponse {
    pub completion_code: u8, // Completion code indicating success or failure (1 byte)
    pub descriptor_count: u8, // Number of descriptors in the response (1 byte)
    pub descriptors: Vec<Descriptor>, // List of descriptors (variable length)
}

impl QueryDeviceIdentifierResponse {
    // Function to decode a QueryDeviceIdentifierResponse from a byte buffer
    pub fn decode(buffer: &[u8]) -> Result<Option<Self>> {
        if buffer.len() < 6 {
            // Not enough data for the fixed fields
            return Err(Error::new(ErrorKind::InvalidData, "Buffer too short"));
        }

        let completion_code = buffer[0]; // First byte is the completion code
        let device_identifiers_length = u32::from_le_bytes([
            // Next 4 bytes represent length of device identifiers
            buffer[1], buffer[2], buffer[3], buffer[4],
        ]);
        let descriptor_count = buffer[5]; // Next byte is the descriptor count

        // Descriptors start at index 6 and are variable length
        let mut descriptors = Vec::new();
        let mut cursor = Cursor::new(&buffer[6..]); // Initialize a cursor to read variable-length descriptors
        let mut expected_device_identifiers_length = 0;

        for _ in 0..descriptor_count {
            let descriptor = Descriptor::decode(&mut cursor)?; // Decode each descriptor and add to the list
            expected_device_identifiers_length += descriptor.total_bytes(); // Track total bytes for validation
            descriptors.push(descriptor);
        }

        // Verify that the total descriptor length matches the expected length
        if (device_identifiers_length as usize) != expected_device_identifiers_length {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Device identifiers length mismatch",
            ));
        }

        // Return a decoded QueryDeviceIdentifierResponse struct
        Ok(Some(Self {
            completion_code,
            descriptor_count,
            descriptors,
        }))
    }

    // Function to encode a QueryDeviceIdentifierResponse into a byte buffer
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Encode completion_code (1 byte)
        buffer.push(self.completion_code);

        // Calculate and encode device_identifiers_length (4 bytes in little-endian)
        let mut device_identifiers_length = 0;
        for descriptor in &self.descriptors {
            device_identifiers_length += descriptor.total_bytes();
        }
        buffer.extend_from_slice(&(device_identifiers_length as u32).to_le_bytes());

        // Encode descriptor_count (1 byte)
        buffer.push(self.descriptor_count);

        // Encode each descriptor and append to buffer (variable length)
        for descriptor in &self.descriptors {
            descriptor.encode(&mut buffer)?; // Encode each descriptor into the buffer
        }

        Ok(buffer) // Return the encoded byte buffer
    }
}
