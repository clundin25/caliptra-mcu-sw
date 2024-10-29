use pldm::packet::PldmPacket;

#[test]
fn test_pldm_packet_encoding_and_decoding() {
    // Create a PLDM packet using the public constructor
    let packet = PldmPacket::new(
        true,                         // Request bit set to 1
        true,                         // Data integrity bit set to 1
        0x03,                         // Instance ID set to 3
        0x00,                         // Header version 0
        0x03, // PLDM Type: 0x03 (example for BIOS Control and Configuration)
        0x24, // Arbitrary command code
        Some(vec![0x00, 0x11, 0x22]), // Payload
    );

    // Encode the PLDM packet
    let encoded_packet = packet.encode();

    // Expected binary representation
    let expected_packet: Vec<u8> = vec![
        0b11000011, // Byte 1: Rq=1, D=1, Reserved=0, Instance ID=3
        0b00000011, // Byte 2: Hdr Ver=0, PLDM Type=0x03
        0x24,       // Byte 3: PLDM Command Code (0x24)
        0x00, 0x11, 0x22, // Payload
    ];

    // Assert that the encoded packet matches the expected value
    assert_eq!(
        encoded_packet, expected_packet,
        "Encoded packet does not match the expected value"
    );

    // Decode the packet
    let decoded_packet = PldmPacket::decode(&encoded_packet).unwrap();

    // Check decoded fields
    assert!(decoded_packet.rq);
    assert!(decoded_packet.d);
    assert_eq!(decoded_packet.instance_id, 0x03);
    assert_eq!(decoded_packet.hdr_ver, 0x00);
    assert_eq!(decoded_packet.pldm_type, 0x03);
    assert_eq!(decoded_packet.pldm_command, 0x24);
    assert_eq!(decoded_packet.payload, Some(vec![0x00, 0x11, 0x22]));
}

#[test]
fn test_pldm_packet_encoding_and_decoding_with_different_instance_and_header() {
    // Create a PLDM packet using different Instance ID and Header Version
    let packet = PldmPacket::new(
        true,                   // Request bit set to 1
        false,                  // Data integrity bit set to 0
        0x1F,                   // Instance ID set to maximum value (0x1F)
        0x03,                   // Header version set to 3 (max for 2 bits)
        0x04,                   // PLDM Type: 0x04 (example for FRU Data)
        0x10,                   // Arbitrary command code
        Some(vec![0xAA, 0xBB]), // Payload
    );

    // Encode the PLDM packet
    let encoded_packet = packet.encode();

    // Expected binary representation
    let expected_packet: Vec<u8> = vec![
        0b10011111, // Byte 1: Rq=1, D=0, Reserved=0, Instance ID=0x1F
        0b11000100, // Byte 2: Hdr Ver=0x03, PLDM Type=0x04 (FRU Data)
        0x10,       // Byte 3: PLDM Command Code (0x10)
        0xAA, 0xBB, // Payload
    ];

    // Assert that the encoded packet matches the expected value
    assert_eq!(
        encoded_packet, expected_packet,
        "Encoded packet does not match the expected value"
    );

    // Decode the packet
    let decoded_packet = PldmPacket::decode(&encoded_packet).unwrap();

    // Check decoded fields
    assert!(decoded_packet.rq);
    assert!(!decoded_packet.d);
    assert_eq!(decoded_packet.instance_id, 0x1F);
    assert_eq!(decoded_packet.hdr_ver, 0x03);
    assert_eq!(decoded_packet.pldm_type, 0x04);
    assert_eq!(decoded_packet.pldm_command, 0x10);
    assert_eq!(decoded_packet.payload, Some(vec![0xAA, 0xBB]));
}

#[test]
fn test_pldm_packet_encoding_and_decoding_without_payload() {
    // Create a PLDM packet with no payload and different command/no completion codes
    let packet = PldmPacket::new(
        false, // Request bit set to 0
        true,  // Data integrity bit set to 1
        0x05,  // Instance ID set to 5
        0x01,  // Header version set to 1
        0x07,  // PLDM Type: 0x07 (example for File Transfer)
        0x55,  // Arbitrary command code
        None,  // No payload
    );

    // Encode the PLDM packet
    let encoded_packet = packet.encode();

    // Expected binary representation
    let expected_packet: Vec<u8> = vec![
        0b01000101, // Byte 1: Rq=0, D=1, Reserved=0, Instance ID=0x05
        0b01000111, // Byte 2: Hdr Ver=0x01, PLDM Type=0x07 (File Transfer)
        0x55,       // Byte 3: PLDM Command Code (0x55)
                    // No payload
    ];

    // Assert that the encoded packet matches the expected value
    assert_eq!(
        encoded_packet, expected_packet,
        "Encoded packet does not match the expected value"
    );

    // Decode the packet
    let decoded_packet = PldmPacket::decode(&encoded_packet).unwrap();

    // Check decoded fields
    assert!(!decoded_packet.rq);
    assert!(decoded_packet.d);
    assert_eq!(decoded_packet.instance_id, 0x05);
    assert_eq!(decoded_packet.hdr_ver, 0x01);
    assert_eq!(decoded_packet.pldm_type, 0x07);
    assert_eq!(decoded_packet.pldm_command, 0x55);
    assert_eq!(decoded_packet.payload, None); // No payload
}
