use pldm::dummy_transport::{DummyEndpoint, DummyEndpointId, DummyTransport};
use pldm::firmware_update::packet::{PldmCommand, QueryDeviceIdentifierResponse};
use pldm::firmware_update::UpdateAgent;
use pldm::packet::{PldmCompletionCode, PldmPacket, PldmType, PLDM_HEADER_VERSION};
use pldm::transport::Endpoint;
use pldm_fw_pkg::{Descriptor, FirmwareManifest};
use std::sync::Arc;
use std::thread;

const FIRMWARE_DEVICE_ENDPOINT_ID: u32 = 1;
const UPDATE_AGENT_ENDPOINT_ID: u32 = 2;

fn setup() {
    if std::env::var("RUST_LOG").is_ok() {
        env_logger::init();
    }
}

#[test]
fn test_query_device_identifier() -> Result<(), ()> {
    setup();

    let transport = Arc::new(DummyTransport::new());
    let fd_id = DummyEndpointId::new(FIRMWARE_DEVICE_ENDPOINT_ID);
    let ua_id = DummyEndpointId::new(UPDATE_AGENT_ENDPOINT_ID);
    let mut fd_endpoint = DummyEndpoint::new(&fd_id, &transport);
    let ua_endpoint = DummyEndpoint::new(&ua_id, &transport);

    let firmware_package = Arc::new(
        FirmwareManifest::decode_firmware_package(
            &String::from("tests/package/firmware_package.bin"),
            &String::from("tests/package"),
        )
        .map_err(|e| {
            panic!("Error decoding firmware package: {:?}", e);
        })
        .unwrap(),
    );
    let mut ua = UpdateAgent::new(
        &fd_id,
        Arc::new(std::sync::Mutex::new(ua_endpoint)),
        firmware_package.clone(),
    );

    let ua_id_clone = ua_id.clone();
    let firmware_package_clone = firmware_package.clone();
    let handle1 = thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        let res = fd_endpoint.receive(&ua_id_clone, &mut buffer, None);
        assert!(res.is_ok(), "Receiving should be successful");

        let pldm_pkt =
            PldmPacket::decode(&buffer[..res.unwrap()]).expect("Unable to decode packet");
        println!("Received packet: {:?}", pldm_pkt);

        let mut all_device_records: Vec<Descriptor> = Vec::new();
        all_device_records.push(
            firmware_package_clone.firmware_device_id_records[0]
                .initial_descriptor
                .clone(),
        );
        if let Some(additional_descriptors) =
            &firmware_package_clone.firmware_device_id_records[0].additional_descriptors
        {
            all_device_records.extend(additional_descriptors.clone());
        }

        let response: QueryDeviceIdentifierResponse = QueryDeviceIdentifierResponse {
            completion_code: PldmCompletionCode::Success.to_u8(),
            descriptor_count: all_device_records.len() as u8,
            descriptors: all_device_records,
        };

        let packet = PldmPacket::new(
            false,
            false,
            pldm_pkt.instance_id,
            PLDM_HEADER_VERSION,
            PldmType::FirmwareUpdate as u8,
            PldmCommand::QueryDeviceIdentifiers as u8,
            response.encode().ok(),
        );
        assert!(
            fd_endpoint.send(&ua_id_clone, &packet.encode()).is_ok(),
            "Sending should be successful"
        );
    });

    ua.query_device_identifiers()
        .expect("Unable to received Query Device Identifier response");

    if let Some(ua_descriptors) = ua.get_device_descriptors() {
        let mut all_device_records: Vec<Descriptor> = Vec::new();
        all_device_records.push(
            firmware_package.firmware_device_id_records[0]
                .initial_descriptor
                .clone(),
        );
        if let Some(additional_descriptors) =
            &firmware_package.firmware_device_id_records[0].additional_descriptors
        {
            all_device_records.extend(additional_descriptors.clone());
        }
        assert_eq!(
            ua_descriptors.len(),
            all_device_records.len(),
            "Device descriptor count should be 1"
        );
        for i in 0..ua_descriptors.len() {
            assert_eq!(
                ua_descriptors[i].descriptor_type, all_device_records[i].descriptor_type,
                "Descriptor type should be the same"
            );
        }
    } else {
        panic!("Device descriptors should not be None");
    }

    handle1.join().expect("Client thread panicked");
    Ok(())
}
