use super::packet::PldmCommand;
use super::packet::QueryDeviceIdentifierResponse;
use crate::packet::{PldmCompletionCode, PldmPacket, PldmType, PLDM_HEADER_VERSION};
use crate::transport::{Endpoint, EndpointId, TransportError};
use log::info;
use pldm_fw_pkg::{Descriptor, FirmwareManifest};
use std::sync::{Arc, Mutex};

// The UpdateAgent struct represents the PLDM Update Agent, responsible for managing
// firmware updates on a target device.
pub struct UpdateAgent<'a> {
    iid: u8,                                 // Instance ID for packet tracking
    firmware_device_eid: &'a dyn EndpointId, // Endpoint ID of the firmware device
    endpoint: Arc<Mutex<dyn Endpoint>>,      // Transport endpoint for communication
    #[allow(dead_code)]
    firmware_package: Arc<FirmwareManifest>, // Firmware package to be used in updates
    device_descriptors: Option<Vec<Descriptor>>, // Cached descriptors of the target device
}

impl<'a> UpdateAgent<'a> {
    // Constructor to create a new UpdateAgent instance
    pub fn new(
        firmware_device_eid: &'a dyn EndpointId,
        endpoint: Arc<Mutex<dyn Endpoint>>,
        firmware_package: Arc<FirmwareManifest>,
    ) -> Self {
        UpdateAgent {
            iid: 0, // Initialize instance ID to 0
            firmware_device_eid,
            endpoint,
            firmware_package,
            device_descriptors: None, // No descriptors initially
        }
    }

    // Sends a PLDM request to the target device using the specified command and optional payload
    pub fn send_pldm_request(
        &mut self,
        pldm_command: u8,
        payload: Option<Vec<u8>>,
    ) -> Result<(), TransportError> {
        let packet = PldmPacket::new(
            true,                           // Request bit set to true
            false,                          // No data transfer bit
            self.iid,                       // Use current instance ID
            PLDM_HEADER_VERSION,            // PLDM header version
            PldmType::FirmwareUpdate as u8, // PLDM type for firmware update
            pldm_command,                   // PLDM command
            payload,                        // Optional payload
        );
        // Send the encoded packet through the endpoint
        self.endpoint
            .lock()
            .unwrap()
            .send(self.firmware_device_eid, packet.encode().as_slice())
    }

    // Receives a PLDM response from the target device and verifies it
    pub fn receive_pldm_response(&mut self) -> Result<PldmPacket, TransportError> {
        let mut buffer = [0u8; 1024]; // Buffer to store the received data
        let num =
            self.endpoint
                .lock()
                .unwrap()
                .receive(self.firmware_device_eid, &mut buffer, None)?;

        // Decode the received buffer into a PLDM packet
        let packet =
            PldmPacket::decode(&buffer[..num]).map_err(|_| TransportError::InvalidPacket)?;

        // Validate the packet by checking request, data transfer, and header version fields
        if (packet.rq || packet.d) && packet.hdr_ver == PLDM_HEADER_VERSION {
            return Err(TransportError::InvalidPacket);
        }
        // Ensure the instance ID matches the expected value
        if packet.instance_id != self.iid {
            return Err(TransportError::InvalidPacket);
        }
        self.iid += 1; // Increment instance ID for the next request
        Ok(packet)
    }

    // Queries the target device for its identifiers and caches them
    pub fn query_device_identifiers(&mut self) -> Result<(), TransportError> {
        info!("Querying device identifiers...");

        // Send the QueryDeviceIdentifiers command
        self.send_pldm_request(PldmCommand::QueryDeviceIdentifiers as u8, None)?;

        // Receive the response packet and validate the command
        let packet = self.receive_pldm_response()?;
        if packet.pldm_command != PldmCommand::QueryDeviceIdentifiers as u8 {
            return Err(TransportError::InvalidPacket);
        }

        // Decode the response payload into a QueryDeviceIdentifierResponse struct
        let response = QueryDeviceIdentifierResponse::decode(packet.payload.as_ref().unwrap())
            .map_err(|_| TransportError::InvalidPacket)?;

        // Validate completion code and descriptor count, then cache descriptors
        if let Some(response) = response {
            if response.completion_code != PldmCompletionCode::Success.to_u8() {
                return Err(TransportError::OperationFailed);
            }
            if response.descriptor_count == 0 {
                return Err(TransportError::InvalidPacket);
            }
            self.device_descriptors = Some(response.descriptors.clone());
        }
        Ok(())
    }

    // Initiates the firmware update process by first querying the device identifiers
    pub fn update(&mut self) -> Result<(), UpdateAgentError> {
        info!("Starting firmware update...");
        self.query_device_identifiers()
            .map_err(|_| UpdateAgentError::OperationFailed)
    }

    // Retrieves the cached device descriptors, if available
    pub fn get_device_descriptors(&self) -> &Option<Vec<Descriptor>> {
        &self.device_descriptors
    }
}

// Enum representing various errors that can occur within the UpdateAgent
pub enum UpdateAgentError {
    TransportError(TransportError), // Errors originating from transport operations
    OperationFailed,                // General error indicating operation failure
}
