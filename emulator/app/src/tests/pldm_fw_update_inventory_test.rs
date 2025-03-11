use std::cell::RefCell;
use std::process::exit;
// Licensed under the Apache-2.0 license
use log::error;
/// This module tests the PLDM request/response interaction between the emulator and the device.
/// The emulator sends out different PLDM requests and expects a corresponding response for those requests.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use core::time::Duration;
use pldm_common::protocol::firmware_update::ComponentClassification;
use pldm_fw_pkg::manifest::{self, FirmwareDeviceIdRecord};
use pldm_fw_pkg::FirmwareManifest;
use pldm_ua::events::PldmEvents;
use pldm_ua::transport::PldmSocket;

use pldm_ua::daemon::{Options, PldmDaemon};
use pldm_ua::{discovery_sm, update_sm};

use crate::mctp_transport::MctpPldmSocket;

pub struct PldmFwUpdateInventoryTest {
    running: Arc<AtomicBool>,
    daemon: RefCell<PldmDaemon<MctpPldmSocket, CustomDiscoverySm, CustomUpdateSm>>,
    is_cancelled: Arc<AtomicBool>,
}

const DEVICE_TID: u8 = 0x02;

const TEST_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
];

const COMPONENT_IMAGE_SET_VER_STR: &str = "1.2.0";

const CALIPTRA_FW_COMP_IDENTIFIER: u16 = 0x0001;
const CALIPTRA_FW_ACTIVE_COMP_STAMP: u32 = 0x00010106; // Version: 1.1.6

const SOC_MANIFEST_COMP_IDENTIFIER: u16 = 0x0003;
const SOC_MANIFEST_ACTIVE_COMP_STAMP: u32 = 0x00010102; // Version: 1.1.2

/* Override the Discovery SM. Skip the discovery process by starting firmware update immediately when discovery is kicked-off */
pub struct CustomDiscoverySm {}
impl discovery_sm::StateMachineActions for CustomDiscoverySm {
    fn on_start_discovery(
        &self,
        ctx: &discovery_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(update_sm::Events::StartUpdate))
            .map_err(|_| ())?;
        Ok(())
    }
}

pub struct CustomUpdateSm {
    pub is_cancelled: Arc<AtomicBool>,
}
impl update_sm::StateMachineActions for CustomUpdateSm {
    fn on_cancel_update(
        &mut self,
        _ctx: &mut update_sm::InnerContext<impl PldmSocket>,
        _request: pldm_common::message::firmware_update::request_cancel::CancelUpdateRequest,
    ) -> Result<(), ()> {
        self.is_cancelled.store(true, Ordering::SeqCst);
        Ok(())
    }
}

macro_rules! run_test {
    ($self:expr, $test:ident) => {
        $self.test_runner(Self::$test, stringify!($test))
    };
}

impl PldmFwUpdateInventoryTest {
    pub fn new(socket: MctpPldmSocket, running: Arc<AtomicBool>) -> Self {
        let is_cancelled = Arc::new(AtomicBool::new(false));
        let is_cancelled_clone = Arc::new(AtomicBool::new(false));
        // Start the PLDM daemon
        let daemon = PldmDaemon::run(
            socket,
            Options {
                pldm_fw_pkg: Some(FirmwareManifest {
                    ..Default::default()
                }),
                discovery_sm_actions: CustomDiscoverySm {},
                update_sm_actions: CustomUpdateSm {
                    is_cancelled: is_cancelled_clone,
                },
                fd_tid: DEVICE_TID,
                auto_start: false,
            },
        )
        .unwrap();

        Self {
            running,
            daemon: RefCell::new(daemon),
            is_cancelled,
        }
    }

    fn restart_daemon(&mut self, pldm_fw_pkg: FirmwareManifest) {
        self.is_cancelled.store(false, Ordering::SeqCst);
        self.daemon.borrow_mut().restart(Some(Options {
            pldm_fw_pkg: Some(pldm_fw_pkg),
            discovery_sm_actions: CustomDiscoverySm {},
            update_sm_actions: CustomUpdateSm {
                is_cancelled: self.is_cancelled.clone(),
            },
            fd_tid: DEVICE_TID,
            auto_start: true,
        }));
    }
    pub fn wait_cancelled(&self) -> Result<(), ()> {
        let timeout = Duration::from_secs(5);
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout {
            if self.is_cancelled.load(Ordering::SeqCst) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !self.is_cancelled.load(Ordering::SeqCst) {
            error!("Timed out waiting for cancelled");
            return Err(());
        };
        Ok(())
    }

    fn test_unrecognized_descriptor(&mut self) -> Result<(), ()> {
        // Define a PLDM Firmware package containing 1 descriptor with an unrecognized UUID
        let pldm_fw_pkg = FirmwareManifest {
            firmware_device_id_records: vec![FirmwareDeviceIdRecord {
                initial_descriptor: manifest::Descriptor {
                    descriptor_type: manifest::DescriptorType::Uuid,
                    descriptor_data: TEST_UUID.to_vec(),
                },
                component_image_set_version_string_type: pldm_fw_pkg::manifest::StringType::Utf8,
                component_image_set_version_string: Some(COMPONENT_IMAGE_SET_VER_STR.to_string()),
                applicable_components: Some(vec![0, 1]),
                ..Default::default()
            }],
            ..Default::default()
        };

        // Start the PLDM daemon
        self.restart_daemon(pldm_fw_pkg);

        // Wait for the test to be cancelled
        self.wait_cancelled()?;

        if self
            .daemon
            .borrow_mut()
            .update_sm
            .lock()
            .unwrap()
            .context()
            .inner_ctx
            .device_id
            .is_some()
        {
            // If the device ID is set, then it means the update SM received a valid descriptor
            return Err(());
        }

        Ok(())
    }

    fn test_valid_descriptor(&mut self) -> Result<(), ()> {
        // Define a PLDM Firmware package containing 1 descriptor with a recognized UUID
        let pldm_fw_pkg = FirmwareManifest {
            firmware_device_id_records: vec![FirmwareDeviceIdRecord {
                initial_descriptor: manifest::Descriptor {
                    descriptor_type: manifest::DescriptorType::Uuid,
                    descriptor_data: TEST_UUID.to_vec(),
                },
                component_image_set_version_string_type: pldm_fw_pkg::manifest::StringType::Utf8,
                component_image_set_version_string: Some(COMPONENT_IMAGE_SET_VER_STR.to_string()),
                applicable_components: Some(vec![0, 1]),
                ..Default::default()
            }],
            ..Default::default()
        };

        // Start the PLDM daemon
        self.restart_daemon(pldm_fw_pkg);

        self.wait_cancelled()?;

        if self
            .daemon
            .borrow_mut()
            .update_sm
            .lock()
            .unwrap()
            .context()
            .inner_ctx
            .device_id
            .is_some()
        {
            // If the device ID is set, then it means the update SM received a valid descriptor
            return Ok(());
        }
        Err(())
    }

    fn test_one_valid_descriptor_two_components(&mut self) -> Result<(), ()> {
        // Define a PLDM Firmware Package containing 1 descriptor with a UUID
        // and 2 components with 1 component being a firmware component and the other
        // being a manifest component.
        let pldm_fw_pkg = FirmwareManifest {
            firmware_device_id_records: vec![FirmwareDeviceIdRecord {
                initial_descriptor: manifest::Descriptor {
                    descriptor_type: manifest::DescriptorType::Uuid,
                    descriptor_data: TEST_UUID.to_vec(),
                },
                component_image_set_version_string_type: pldm_fw_pkg::manifest::StringType::Utf8,
                component_image_set_version_string: Some(COMPONENT_IMAGE_SET_VER_STR.to_string()),
                applicable_components: Some(vec![0, 1]),
                ..Default::default()
            }],
            component_image_information: vec![
                manifest::ComponentImageInformation {
                    classification: ComponentClassification::Firmware as u16,
                    identifier: CALIPTRA_FW_COMP_IDENTIFIER,
                    comparison_stamp: Some(CALIPTRA_FW_ACTIVE_COMP_STAMP),
                    ..Default::default()
                },
                manifest::ComponentImageInformation {
                    classification: ComponentClassification::Other as u16,
                    identifier: SOC_MANIFEST_COMP_IDENTIFIER,
                    comparison_stamp: Some(SOC_MANIFEST_ACTIVE_COMP_STAMP),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        // Start the PLDM daemon
        self.restart_daemon(pldm_fw_pkg);

        self.wait_cancelled()?;

        if self
            .daemon
            .borrow_mut()
            .update_sm
            .lock()
            .unwrap()
            .context()
            .inner_ctx
            .components
            .len()
            == 2
        {
            return Ok(());
        }
        Err(())
    }

    fn test_runner(
        &mut self,
        test: fn(&mut Self) -> Result<(), ()>,
        test_name: &str,
    ) -> Result<(), ()> {
        println!("########################################");
        println!("Running test: {}", test_name);
        println!("########################################");
        match test(self) {
            Ok(_) => {
                println!("########################################");
                println!("{} passed", test_name);
                println!("########################################");
                Ok(())
            }
            Err(_) => {
                println!("########################################");
                println!("{} failed", test_name);
                println!("########################################");
                Err(())
            }
        }
    }

    fn run_all(&mut self) -> Result<(), ()> {
        run_test!(self, test_unrecognized_descriptor)?;
        run_test!(self, test_valid_descriptor)?;
        run_test!(self, test_one_valid_descriptor_two_components)?;
        self.daemon.borrow_mut().stop();
        Ok(())
    }

    pub fn run(socket: MctpPldmSocket, running: Arc<AtomicBool>) {
        std::thread::spawn(move || {
            print!("Emulator: Running PldmFwUpdateInventoryTest: ",);
            let mut test = PldmFwUpdateInventoryTest::new(socket, running);
            if test.run_all().is_err() {
                println!("Failed");
                exit(-1);
            } else {
                println!("Passed");
            }
            test.running.store(false, Ordering::Relaxed);
        });
    }
}
