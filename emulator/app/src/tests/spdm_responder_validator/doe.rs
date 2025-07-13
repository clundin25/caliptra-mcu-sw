// Licensed under the Apache-2.0 license

use crate::doe_mbox_fsm::DoeTestState;
use crate::tests::spdm_responder_validator::common::{execute_spdm_validator, SpdmValidatorRunner};
use crate::tests::spdm_responder_validator::transport::{Transport, SOCKET_TRANSPORT_TYPE_PCI_DOE};
use crate::{wait_for_runtime_start, EMULATOR_RUNNING};
use std::net::TcpListener;
use std::process::exit;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;

const TEST_NAME: &str = "DOE-SPDM-RESPONDER-VALIDATOR";

pub struct DoeTransport {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    tx_rx_state: DoeTestState,
}

impl DoeTransport {
    pub fn new(tx: Sender<Vec<u8>>, rx: Receiver<Vec<u8>>) -> Self {
        Self {
            tx,
            rx,
            tx_rx_state: DoeTestState::Start,
        }
    }
    fn send_req_receive_resp(&mut self, _req: &[u8]) -> Option<Vec<u8>> {
        todo!("Implement send_req_receive_resp for DoeTransport");
    }

    fn wait_for_responder(&mut self, _req: &[u8]) -> Option<Vec<u8>> {
        todo!("Implement wait_for_responder for DoeTransport");
    }
}

impl Transport for DoeTransport {
    fn target_send_and_receive(&mut self, req: &[u8], wait_for_responder: bool) -> Option<Vec<u8>> {
        if wait_for_responder {
            self.wait_for_responder(req)
        } else {
            self.send_req_receive_resp(req)
        }
    }

    fn transport_type(&self) -> u32 {
        SOCKET_TRANSPORT_TYPE_PCI_DOE
    }
}

pub fn run_doe_spdm_conformance_test(
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    test_timeout_seconds: Duration,
) {
    // Spawn a thread to handle the timeout for the test
    thread::spawn(move || {
        std::thread::sleep(test_timeout_seconds);
        println!(
            "[{}]: Timeout after {:?} seconds",
            TEST_NAME,
            test_timeout_seconds.as_secs()
        );
        EMULATOR_RUNNING.store(false, Ordering::Relaxed);
    });

    // Spawn a thread to run the tests
    thread::spawn(move || {
        wait_for_runtime_start();
        let transport = DoeTransport::new(tx, rx);

        if !EMULATOR_RUNNING.load(Ordering::Relaxed) {
            exit(-1);
        }

        let listener =
            TcpListener::bind("127.0.0.1:2323").expect("Could not bind to the SPDM listerner port");
        println!("[{}]: Spdm Server Listening on port 2323", TEST_NAME);

        if let Some(spdm_stream) = listener.incoming().next() {
            let mut spdm_client_stream = spdm_stream.expect("Failed to accept connection");

            let mut test = SpdmValidatorRunner::new(Box::new(transport), TEST_NAME);
            test.run_test(&mut spdm_client_stream);
            if !test.is_passed() {
                println!("[{}]: Spdm Responder Conformance Test Failed", TEST_NAME);
                exit(-1);
            } else {
                println!("[{}]: Spdm Responder Conformance Test Passed", TEST_NAME);
                exit(0);
            }
        }
    });

    execute_spdm_validator("PCI_DOE");
}
