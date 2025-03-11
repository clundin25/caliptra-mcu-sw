// Licensed under the Apache-2.0 license

#[cfg(feature = "test-pldm-fw-update-inventory")]
pub mod test {
    use core::fmt::Write;
    use libsyscall_caliptra::mctp::{driver_num, Mctp, MessageInfo};
    use libtock_console::ConsoleWriter;
    use libtock_platform::Syscalls;
    use pldm_common::codec::PldmCodec;
    use pldm_common::message::firmware_update::get_fw_params::{
        FirmwareParameters, GetFirmwareParametersRequest, GetFirmwareParametersResponse,
    };
    use pldm_common::message::firmware_update::query_devid::{
        QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse,
    };
    use pldm_common::message::firmware_update::request_cancel::CancelUpdateRequest;
    use pldm_common::protocol::base::{PldmBaseCompletionCode, PldmMsgHeader, PldmMsgType};
    use pldm_common::protocol::firmware_update::{
        ComponentActivationMethods, ComponentClassification, ComponentParameterEntry,
        ComponentParameterEntryFixed, DescriptorType, FirmwareDeviceCapability, FwUpdateCmd,
        PldmFirmwareString, VersionStringType, PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN,
    };

    const MAX_MCTP_PACKET_SIZE: usize = 512;
    const MCTP_PLDM_COMMON_HEADER: u8 = 0x01;

    const COMPONENT_ACTIVE_VER_STR: &str = "1.1.0";
    const CALIPTRA_FW_COMP_IDENTIFIER: u16 = 0x0001;
    const CALIPTRA_FW_ACTIVE_COMP_STAMP: u32 = 0x00010105;
    const CALIPTRA_FW_ACTIVE_VER_STR: &str = "caliptra-fmc-1.1.0";
    const CALIPTRA_FW_RELEASE_DATE: [u8; 8] = *b"20250210";

    const SOC_MANIFEST_COMP_IDENTIFIER: u16 = 0x0003;
    const SOC_MANIFEST_ACTIVE_COMP_STAMP: u32 = 0x00010101;
    const SOC_MANIFEST_ACTIVE_VER_STR: &str = "caliptra-fmc-1.1.0";
    const SOC_MANIFEST_RELEASE_DATE: [u8; 8] = *b"20250210";
    const EMPTY_RELEASE_DATE: [u8; 8] = *b"\0\0\0\0\0\0\0\0";

    const TEST_EXPECTED_UUID: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
        0xF0,
    ];

    const TEST_UNEXPECTED_UUID: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
        0xFF,
    ];

    fn build_descriptor(
        descriptor_type: DescriptorType,
        value: &[u8],
    ) -> Result<pldm_common::protocol::firmware_update::Descriptor, ()> {
        let descriptor = pldm_common::protocol::firmware_update::Descriptor {
            descriptor_type: descriptor_type as u16,
            descriptor_length: value.len() as u16,
            descriptor_data: {
                let mut array = [0u8; 64];
                let data_slice = value;
                let len = data_slice.len().min(64);
                array[..len].copy_from_slice(&data_slice[..len]);
                array
            },
        };
        Ok(descriptor)
    }
    pub async fn receive_request<S: Syscalls, P: PldmCodec>(
        console_writer: &mut ConsoleWriter<S>,
        mctp_pldm: &Mctp<S>,
        msg_buffer: &mut [u8],
        cmd_code: u8,
    ) -> Result<(P, MessageInfo), ()> {
        let (length, info) = mctp_pldm.receive_request(msg_buffer).await.unwrap();

        writeln!(
            console_writer,
            "device: in Received request length {} buffer:{:?}",
            length,
            &msg_buffer[0..length as usize]
        )
        .unwrap();

        let header = PldmMsgHeader::decode(&msg_buffer[1..length as usize]).map_err(|_| ())?;
        writeln!(console_writer, "device: Request received").unwrap();

        if !header.is_hdr_ver_valid() {
            return Err(());
        }
        if header.cmd_code() != cmd_code {
            writeln!(
                console_writer,
                "device: cmd_code {} expected {}",
                header.cmd_code(),
                cmd_code
            )
            .unwrap();
            return Err(());
        }

        let decoded_mesg = P::decode(&msg_buffer[1..length as usize]).map_err(|_| ())?;

        writeln!(
            console_writer,
            "device: successful received cmd_code {}",
            header.cmd_code()
        )
        .unwrap();

        Ok((decoded_mesg, info))
    }

    pub async fn send_response<S: Syscalls, P: PldmCodec>(
        console_writer: &mut ConsoleWriter<S>,
        mctp_pldm: &Mctp<S>,
        msg_buffer: &mut [u8],
        response: &P,
        msg_info: &MessageInfo,
    ) -> Result<(), ()> {
        msg_buffer[0] = MCTP_PLDM_COMMON_HEADER;
        let sz = response.encode(&mut msg_buffer[1..]).unwrap();
        writeln!(
            console_writer,
            "device: Sending response {:?}",
            &msg_buffer[1..sz + 1 as usize]
        )
        .unwrap();

        mctp_pldm
            .send_response(&msg_buffer[..sz + 1], msg_info.clone())
            .await
            .map_err(|_| ())
    }

    pub async fn send_cancel<S: Syscalls>(
        console_writer: &mut ConsoleWriter<S>,
        mctp_pldm: &Mctp<S>,
        msg_buffer: &mut [u8],
        msg_info: &MessageInfo,
    ) -> Result<(), ()> {
        let request = CancelUpdateRequest::new(0x01, PldmMsgType::Request);
        send_response::<S, CancelUpdateRequest>(
            console_writer,
            mctp_pldm,
            msg_buffer,
            &request,
            &msg_info,
        )
        .await
    }

    pub async fn test_unrecognized_descriptor<S: Syscalls>(
        console_writer: &mut ConsoleWriter<S>,
    ) -> Result<(), ()> {
        let mctp_pldm = Mctp::<S>::new(driver_num::MCTP_PLDM);
        let mut msg_buffer: [u8; MAX_MCTP_PACKET_SIZE] = [0; MAX_MCTP_PACKET_SIZE];

        writeln!(
            console_writer,
            "device: test_unrecognized_descriptor Waiting for request"
        )
        .unwrap();

        // Wait for a QueryIdentifers request
        let (request, info) = receive_request::<S, QueryDeviceIdentifiersRequest>(
            console_writer,
            &mctp_pldm,
            &mut msg_buffer,
            FwUpdateCmd::QueryDeviceIdentifiers as u8,
        )
        .await?;

        writeln!(
            console_writer,
            "device: test_unrecognized_descriptor Request received"
        )
        .unwrap();

        // Send a response with UUID2 instead of UUID1
        let initial_descriptor =
            build_descriptor(DescriptorType::Uuid, TEST_UNEXPECTED_UUID.as_slice())?;

        let response = QueryDeviceIdentifiersResponse::new(
            request.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            core::mem::size_of::<pldm_common::protocol::firmware_update::Descriptor>() as u32,
            1,
            &initial_descriptor,
            None,
        )
        .unwrap();

        // Send the response
        send_response::<S, QueryDeviceIdentifiersResponse>(
            console_writer,
            &mctp_pldm,
            &mut msg_buffer,
            &response,
            &info,
        )
        .await?;

        // Indicate to the host that the unit test is done by sending cancel
        send_cancel::<S>(console_writer, &mctp_pldm, &mut msg_buffer, &info).await
    }

    pub async fn test_valid_descriptor<S: Syscalls>(
        console_writer: &mut ConsoleWriter<S>,
    ) -> Result<(), ()> {
        let mctp_pldm = Mctp::<S>::new(driver_num::MCTP_PLDM);
        let mut msg_buffer: [u8; MAX_MCTP_PACKET_SIZE] = [0; MAX_MCTP_PACKET_SIZE];

        writeln!(
            console_writer,
            "device: test_valid_descriptor Waiting for request"
        )
        .unwrap();

        // Wait for a QueryIdentifers request
        let (request, info) = receive_request::<S, QueryDeviceIdentifiersRequest>(
            console_writer,
            &mctp_pldm,
            &mut msg_buffer,
            FwUpdateCmd::QueryDeviceIdentifiers as u8,
        )
        .await?;

        writeln!(
            console_writer,
            "device: test_valid_descriptor Request received"
        )
        .unwrap();

        // Send a response with UUID1
        let initial_descriptor =
            build_descriptor(DescriptorType::Uuid, TEST_EXPECTED_UUID.as_slice())?;

        let response = QueryDeviceIdentifiersResponse::new(
            request.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            core::mem::size_of::<pldm_common::protocol::firmware_update::Descriptor>() as u32,
            1,
            &initial_descriptor,
            None,
        )
        .unwrap();

        // Send the response
        send_response::<S, QueryDeviceIdentifiersResponse>(
            console_writer,
            &mctp_pldm,
            &mut msg_buffer,
            &response,
            &info,
        )
        .await?;

        // Indicate to the host that the unit test is done by sending cancel
        send_cancel::<S>(console_writer, &mctp_pldm, &mut msg_buffer, &info).await
    }

    pub async fn test_one_valid_descriptor_two_components<S: Syscalls>(
        console_writer: &mut ConsoleWriter<S>,
    ) -> Result<(), ()> {
        let mctp_pldm = Mctp::<S>::new(driver_num::MCTP_PLDM);
        let mut msg_buffer: [u8; MAX_MCTP_PACKET_SIZE] = [0; MAX_MCTP_PACKET_SIZE];

        writeln!(
            console_writer,
            "device: test_one_valid_descriptor_two_components Waiting for request"
        )
        .unwrap();

        // Wait for a QueryIdentifers request
        let (request, info) = receive_request::<S, QueryDeviceIdentifiersRequest>(
            console_writer,
            &mctp_pldm,
            &mut msg_buffer,
            FwUpdateCmd::QueryDeviceIdentifiers as u8,
        )
        .await?;

        writeln!(
            console_writer,
            "device: test_one_valid_descriptor_two_components Request received"
        )
        .unwrap();

        // Send a response with UUID1
        let initial_descriptor =
            build_descriptor(DescriptorType::Uuid, TEST_EXPECTED_UUID.as_slice())?;

        let response = QueryDeviceIdentifiersResponse::new(
            request.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            core::mem::size_of::<pldm_common::protocol::firmware_update::Descriptor>() as u32,
            1,
            &initial_descriptor,
            None,
        )
        .unwrap();

        // Send the response
        send_response::<S, QueryDeviceIdentifiersResponse>(
            console_writer,
            &mctp_pldm,
            &mut msg_buffer,
            &response,
            &info,
        )
        .await?;

        // Receive GetFirmwareParameters request
        let (request, info) = receive_request::<S, GetFirmwareParametersRequest>(
            console_writer,
            &mctp_pldm,
            &mut msg_buffer,
            FwUpdateCmd::GetFirmwareParameters as u8,
        )
        .await?;

        writeln!(console_writer, "device: test_one_valid_descriptor_two_components GetFirmwareParameters request received").unwrap();

        // Build GetFirmwareParameters response

        let component1 = ComponentParameterEntry {
            comp_param_entry_fixed: ComponentParameterEntryFixed {
                comp_classification: ComponentClassification::Firmware as u16,
                comp_identifier: CALIPTRA_FW_COMP_IDENTIFIER,
                comp_classification_index: 0u8,
                active_comp_comparison_stamp: CALIPTRA_FW_ACTIVE_COMP_STAMP,
                active_comp_ver_str_type: VersionStringType::Utf8 as u8,
                active_comp_ver_str_len: CALIPTRA_FW_ACTIVE_VER_STR.len() as u8,
                active_comp_release_date: CALIPTRA_FW_RELEASE_DATE,
                pending_comp_comparison_stamp: 0u32,
                pending_comp_ver_str_type: VersionStringType::Unspecified as u8,
                pending_comp_ver_str_len: 0,
                pending_comp_release_date: EMPTY_RELEASE_DATE,
                comp_activation_methods: ComponentActivationMethods(0),
                capabilities_during_update: FirmwareDeviceCapability(0),
            },
            active_comp_ver_str: {
                let mut active_comp_ver_str = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                active_comp_ver_str[..CALIPTRA_FW_ACTIVE_VER_STR.len()]
                    .copy_from_slice(CALIPTRA_FW_ACTIVE_VER_STR.as_bytes());
                active_comp_ver_str
            },
            pending_comp_ver_str: None,
        };

        let component2 = ComponentParameterEntry {
            comp_param_entry_fixed: ComponentParameterEntryFixed {
                comp_classification: ComponentClassification::Other as u16,
                comp_identifier: SOC_MANIFEST_COMP_IDENTIFIER,
                comp_classification_index: 0u8,
                active_comp_comparison_stamp: SOC_MANIFEST_ACTIVE_COMP_STAMP,
                active_comp_ver_str_type: VersionStringType::Utf8 as u8,
                active_comp_ver_str_len: SOC_MANIFEST_ACTIVE_VER_STR.len() as u8,
                active_comp_release_date: SOC_MANIFEST_RELEASE_DATE,
                pending_comp_comparison_stamp: 0u32,
                pending_comp_ver_str_type: VersionStringType::Unspecified as u8,
                pending_comp_ver_str_len: 0,
                pending_comp_release_date: EMPTY_RELEASE_DATE,
                comp_activation_methods: ComponentActivationMethods(0),
                capabilities_during_update: FirmwareDeviceCapability(0),
            },
            active_comp_ver_str: {
                let mut active_comp_ver_str = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                active_comp_ver_str[..SOC_MANIFEST_ACTIVE_VER_STR.len()]
                    .copy_from_slice(SOC_MANIFEST_ACTIVE_VER_STR.as_bytes());
                active_comp_ver_str
            },
            pending_comp_ver_str: None,
        };

        let params = FirmwareParameters::new(
            FirmwareDeviceCapability(0x0010),
            2,
            &PldmFirmwareString::new("UTF-8", COMPONENT_ACTIVE_VER_STR).unwrap(),
            &PldmFirmwareString::new("UTF-8", "").unwrap(),
            &[component1, component2],
        );

        let response = GetFirmwareParametersResponse::new(
            request.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            &params,
        );

        send_response(
            console_writer,
            &mctp_pldm,
            &mut msg_buffer,
            &response,
            &info,
        )
        .await?;

        // Indicate to the host that the unit test is done by sending cancel
        send_cancel::<S>(console_writer, &mctp_pldm, &mut msg_buffer, &info).await?;

        Ok(())
    }

    pub async fn test_pldm_fw_update_inventory<S: Syscalls>(console_writer: &mut ConsoleWriter<S>) {
        writeln!(
            console_writer,
            "device: Running test_pldm_fw_update_inventory"
        )
        .unwrap();
        test_unrecognized_descriptor::<S>(console_writer)
            .await
            .unwrap();
        test_valid_descriptor::<S>(console_writer).await.unwrap();
        test_one_valid_descriptor_two_components::<S>(console_writer)
            .await
            .unwrap();
        writeln!(console_writer, "device: test_pldm_fw_update_inventory done").unwrap();
    }
}
