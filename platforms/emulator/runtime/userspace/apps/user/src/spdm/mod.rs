// Licensed under the Apache-2.0 license

mod cert_slot_mgr;
mod config;

use cert_slot_mgr::cert_store::{initialize_shared_cert_store, SharedCertStore};
use core::fmt::Write;
use embassy_executor::Spawner;
use libsyscall_caliptra::doe;
use libsyscall_caliptra::mctp;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;
use spdm_lib::codec::MessageBuf;
use spdm_lib::context::SpdmContext;
use spdm_lib::protocol::*;
use spdm_lib::transport::common::SpdmTransport;
use spdm_lib::transport::doe::DoeTransport;
use spdm_lib::transport::mctp::MctpTransport;

// Maximum SPDM responder buffer size
const MAX_RESPONDER_BUF_SIZE: usize = 2048;

// Caliptra supported SPDM versions
const SPDM_VERSIONS: &[SpdmVersion] = &[SpdmVersion::V12, SpdmVersion::V13];

// Calitra Crypto timeout exponent (2^20 us)
const CALIPTRA_SPDM_CT_EXPONENT: u8 = 20;

// Caliptra Hash Priority table
static HASH_PRIORITY_TABLE: &[BaseHashAlgoType] = &[
    BaseHashAlgoType::TpmAlgSha512,
    BaseHashAlgoType::TpmAlgSha384,
    BaseHashAlgoType::TpmAlgSha256,
];

#[embassy_executor::task]
pub(crate) async fn spdm_task(spawner: Spawner) {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "SPDM_TASK: Running SPDM-TASK...").unwrap();

    // Initialize the shared certificate store
    if let Err(e) = initialize_shared_cert_store().await {
        writeln!(
            console_writer,
            "SPDM_TASK: Failed to initialize certificate store: {:?}",
            e
        )
        .unwrap();
        return;
    }

    if let Err(e) = spawner.spawn(spdm_mctp_responder()) {
        writeln!(
            console_writer,
            "SPDM_TASK: Failed to spawn spdm_mctp_responder: {:?}",
            e
        )
        .unwrap();
    }
    if let Err(e) = spawner.spawn(spdm_doe_responder()) {
        writeln!(
            console_writer,
            "SPDM_TASK: Failed to spawn spdm_doe_responder: {:?}",
            e
        )
        .unwrap();
    }
}

#[embassy_executor::task]
async fn spdm_mctp_responder() {
    let mut raw_buffer = [0; MAX_RESPONDER_BUF_SIZE];
    let mut cw = Console::<DefaultSyscalls>::writer();
    let mut mctp_spdm_transport: MctpTransport = MctpTransport::new(mctp::driver_num::MCTP_SPDM);

    let max_mctp_spdm_msg_size =
        (MAX_RESPONDER_BUF_SIZE - mctp_spdm_transport.header_size()) as u32;

    let local_capabilities = DeviceCapabilities {
        ct_exponent: CALIPTRA_SPDM_CT_EXPONENT,
        flags: device_capability_flags(),
        data_transfer_size: max_mctp_spdm_msg_size,
        max_spdm_msg_size: max_mctp_spdm_msg_size,
    };

    let local_algorithms = LocalDeviceAlgorithms {
        device_algorithms: device_algorithms(),
        algorithm_priority_table: AlgorithmPriorityTable {
            measurement_specification: None,
            opaque_data_format: None,
            base_asym_algo: None,
            base_hash_algo: Some(HASH_PRIORITY_TABLE),
            mel_specification: None,
            dhe_group: None,
            aead_cipher_suite: None,
            req_base_asym_algo: None,
            key_schedule: None,
        },
    };

    // Create a wrapper for the global certificate store
    let cert_store_wrapper = SharedCertStore::new();

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        &mut mctp_spdm_transport,
        local_capabilities,
        local_algorithms,
        &cert_store_wrapper,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            writeln!(
                cw,
                "SPDM_MCTP_RESPONDER: Failed to create SPDM context: {:?}",
                e
            )
            .unwrap();
            return;
        }
    };

    let mut msg_buffer = MessageBuf::new(&mut raw_buffer);
    loop {
        let result = ctx.process_message(&mut msg_buffer).await;
        match result {
            Ok(_) => {
                writeln!(cw, "SPDM_MCTP_RESPONDER: Process message successfully").unwrap();
            }
            Err(e) => {
                writeln!(cw, "SPDM_MCTP_RESPONDER: Process message failed: {:?}", e).unwrap();
            }
        }
    }
}

#[embassy_executor::task]
async fn spdm_doe_responder() {
    let mut raw_buffer = [0; MAX_RESPONDER_BUF_SIZE];
    let mut cw = Console::<DefaultSyscalls>::writer();
    let mut doe_spdm_transport: DoeTransport = DoeTransport::new(doe::driver_num::DOE_SPDM);

    let max_doe_spdm_msg_size = (MAX_RESPONDER_BUF_SIZE - doe_spdm_transport.header_size()) as u32;

    let local_capabilities = DeviceCapabilities {
        ct_exponent: CALIPTRA_SPDM_CT_EXPONENT,
        flags: device_capability_flags(),
        data_transfer_size: max_doe_spdm_msg_size,
        max_spdm_msg_size: max_doe_spdm_msg_size,
    };

    let local_algorithms = LocalDeviceAlgorithms {
        device_algorithms: device_algorithms(),
        algorithm_priority_table: AlgorithmPriorityTable {
            measurement_specification: None,
            opaque_data_format: None,
            base_asym_algo: None,
            base_hash_algo: Some(HASH_PRIORITY_TABLE),
            mel_specification: None,
            dhe_group: None,
            aead_cipher_suite: None,
            req_base_asym_algo: None,
            key_schedule: None,
        },
    };

    // Create a wrapper for the global certificate store
    let cert_store_wrapper = SharedCertStore::new();

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        &mut doe_spdm_transport,
        local_capabilities,
        local_algorithms,
        &cert_store_wrapper,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            writeln!(
                cw,
                "SPDM_DOE_RESPONDER: Secondary - Failed to create SPDM context: {:?}",
                e
            )
            .unwrap();
            return;
        }
    };

    let mut msg_buffer = MessageBuf::new(&mut raw_buffer);
    loop {
        let result = ctx.process_message(&mut msg_buffer).await;
        match result {
            Ok(_) => {
                writeln!(
                    cw,
                    "SPDM_DOE_RESPONDER: Secondary - Process message successfully"
                )
                .unwrap();
            }
            Err(e) => {
                writeln!(
                    cw,
                    "SPDM_DOE_RESPONDER: Secondary - Process message failed: {:?}",
                    e
                )
                .unwrap();
            }
        }
    }
}

fn device_capability_flags() -> CapabilityFlags {
    let mut capability_flags = CapabilityFlags::default();
    capability_flags.set_cache_cap(0);
    capability_flags.set_cert_cap(1);
    capability_flags.set_chal_cap(1);
    capability_flags.set_meas_cap(MeasCapability::MeasurementsWithSignature as u8);
    capability_flags.set_meas_fresh_cap(0);
    capability_flags.set_encrypt_cap(0);
    capability_flags.set_mac_cap(0);
    capability_flags.set_mut_auth_cap(0);
    capability_flags.set_key_ex_cap(0);
    capability_flags.set_psk_cap(PskCapability::NoPsk as u8);
    capability_flags.set_encap_cap(0);
    capability_flags.set_hbeat_cap(0);
    capability_flags.set_key_upd_cap(0);
    capability_flags.set_handshake_in_the_clear_cap(0);
    capability_flags.set_pub_key_id_cap(0);
    capability_flags.set_chunk_cap(1);
    capability_flags.set_alias_cert_cap(1);

    capability_flags
}

fn device_algorithms() -> DeviceAlgorithms {
    let mut measurement_spec = MeasurementSpecification::default();
    measurement_spec.set_dmtf_measurement_spec(1);

    let other_param_support = OtherParamSupport::default();

    let mut measurement_hash_algo = MeasurementHashAlgo::default();
    measurement_hash_algo.set_tpm_alg_sha_384(1);

    let mut base_asym_algo = BaseAsymAlgo::default();
    base_asym_algo.set_tpm_alg_ecdsa_ecc_nist_p384(1);

    let mut base_hash_algo = BaseHashAlgo::default();
    base_hash_algo.set_tpm_alg_sha_384(1);

    let mut mel_specification = MelSpecification::default();
    mel_specification.set_dmtf_mel_spec(1);

    let dhe_group = DheNamedGroup::default();
    let aead_cipher_suite = AeadCipherSuite::default();
    let req_base_asym_algo = ReqBaseAsymAlg::default();
    let key_schedule = KeySchedule::default();

    DeviceAlgorithms {
        measurement_spec,
        other_param_support,
        measurement_hash_algo,
        base_asym_algo,
        base_hash_algo,
        mel_specification,
        dhe_group,
        aead_cipher_suite,
        req_base_asym_algo,
        key_schedule,
    }
}
