// Licensed under the Apache-2.0 license

// This module provides an abstraction over the MCTP (Management Component Transport Protocol) transport layer for PLDM (Platform Level Data Model).
// It implements the `PldmSocket` and `PldmTransport` traits, which define generic transport entities used by PLDM for communication.
// The `MctpPldmSocket` struct represents a socket for sending and receiving PLDM messages over MCTP.
// The `MctpTransport` struct is responsible for creating and managing `MctpPldmSocket` instances.

use crate::tests::mctp_util::common::MctpUtil;
use core::time::Duration;
use emulator_periph::DynamicI3cAddress;

use pldm_common::util::mctp_transport::{MctpCommonHeader, MCTP_PLDM_MSG_TYPE};
use pldm_ua::transport::{
    EndpointId, Payload, PldmSocket, PldmTransport, PldmTransportError, RxPacket,
    MAX_PLDM_PAYLOAD_SIZE,
};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug, PartialEq, Clone)]
enum MctpPldmSocketState {
    Idle,
    WaitingForFirstResponse,
    DuplexReady,
}

pub struct MctpPldmSocket {
    source: EndpointId,
    dest: EndpointId,
    target_addr: u8,
    msg_tag: u8,
    running: Arc<AtomicBool>,
    context: Arc<Mutex<MctpPldmSocketData>>,
    state: Arc<(Mutex<MctpPldmSocketState>, Condvar)>,
}

struct MctpPldmSocketData {
    stream: TcpStream,
    first_response: Option<Vec<u8>>,
    mctp_util: MctpUtil,
}

impl PldmSocket for MctpPldmSocket {
    fn send(&self, payload: &[u8]) -> Result<(), PldmTransportError> {
        let mut mctp_util = {
            let context = &mut *self.context.lock().unwrap();
            context.mctp_util.clone()
        };
        let (state_lock, cvar) = &*self.state;
        let state = &mut *state_lock.lock().unwrap();

        let mut mctp_common_header = MctpCommonHeader(0);
        mctp_common_header.set_ic(0);
        mctp_common_header.set_msg_type(MCTP_PLDM_MSG_TYPE);

        let mut mctp_payload: Vec<u8> = Vec::new();
        mctp_payload.push(mctp_common_header.0);
        mctp_payload.extend_from_slice(payload);

        let mut stream = {
            let context = &mut *self.context.lock().unwrap();
            context
                .stream
                .try_clone()
                .map_err(|_| PldmTransportError::Disconnected)?
        };

        if *state == MctpPldmSocketState::Idle {
            /* If this is the first time we are sending a request,
             * we need to make sure that the responder is ready
             * so we wait for a response for the first message
             */
            mctp_util.new_req(self.msg_tag);
            let response = mctp_util.wait_for_responder(
                self.msg_tag,
                mctp_payload.as_mut_slice(),
                self.running.clone(),
                &mut stream,
                self.target_addr,
            );
            self.context
                .lock()
                .unwrap()
                .first_response
                .replace(response.unwrap());
            *state = MctpPldmSocketState::WaitingForFirstResponse;
            cvar.notify_all();
        } else if payload[0] & 0x80 == 0x80 {
            mctp_util.send_request(
                self.msg_tag,
                mctp_payload.as_mut_slice(),
                self.running.clone(),
                &mut stream,
                self.target_addr,
            );
        } else {
            mctp_util.send_response(
                mctp_payload.as_mut_slice(),
                self.running.clone(),
                &mut stream,
                self.target_addr,
            );
        }

        Ok(())
    }

    fn receive(&self, _timeout: Option<Duration>) -> Result<RxPacket, PldmTransportError> {
        {
            let (state_lock, cvar) = &*self.state;
            let mut state = state_lock.lock().unwrap();
            println!("state: {:?}", *state);
            if *state == MctpPldmSocketState::WaitingForFirstResponse
                || *state == MctpPldmSocketState::Idle
            {
                // Wait for the first response
                state = cvar.wait(state).unwrap();
                let context = &mut *self.context.lock().unwrap();
                if let Some(response) = context.first_response.as_mut() {
                    let mut data = [0u8; MAX_PLDM_PAYLOAD_SIZE];
                    // Skip the first byte containing the MCTP common header
                    // and only return the PLDM payload
                    data[..response.len() - 1].copy_from_slice(&response[1..]);
                    let ret = RxPacket {
                        src: self.dest,
                        payload: Payload {
                            data,
                            len: response.len() - 1,
                        },
                    };
                    context.first_response = None;
                    *state = MctpPldmSocketState::DuplexReady;
                    return Ok(ret);
                } else {
                    return Err(PldmTransportError::Disconnected);
                }
            }
        }

        // We are in duplex mode, so we can receive packets
        // without waiting for the first response
        let mut mctp_util = {
            let context = &mut *self.context.lock().unwrap();
            context.mctp_util.clone()
        };
        let mut stream = {
            let context = &mut *self.context.lock().unwrap();
            context
                .stream
                .try_clone()
                .map_err(|_| PldmTransportError::Disconnected)?
        };
        let raw_pkt: Vec<u8> =
            mctp_util.receive(self.running.clone(), &mut stream, self.target_addr);
        let len = raw_pkt.len() - 1;
        if raw_pkt.is_empty() {
            return Err(PldmTransportError::Underflow);
        }
        let mut data = [0u8; MAX_PLDM_PAYLOAD_SIZE];
        // Skip the first byte containing the MCTP common header
        // and only return the PLDM payload
        data[..len].copy_from_slice(&raw_pkt[1..]);
        Ok(RxPacket {
            src: self.dest,
            payload: Payload { data, len },
        })
    }

    fn connect(&self) -> Result<(), PldmTransportError> {
        // Not supported
        Ok(())
    }

    fn disconnect(&self) {
        // Not supported
    }

    fn clone(&self) -> Self {
        MctpPldmSocket {
            source: self.source,
            dest: self.dest,
            target_addr: self.target_addr,
            msg_tag: self.msg_tag,
            running: self.running.clone(),
            context: self.context.clone(),
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
pub struct MctpTransport {
    port: u16,
    target_addr: DynamicI3cAddress,
}

impl MctpTransport {
    pub fn new(port: u16, target_addr: DynamicI3cAddress) -> Self {
        Self { port, target_addr }
    }
}

impl PldmTransport<MctpPldmSocket> for MctpTransport {
    fn create_socket(
        &self,
        source: EndpointId,
        dest: EndpointId,
    ) -> Result<MctpPldmSocket, PldmTransportError> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let stream = TcpStream::connect(addr).map_err(|_| PldmTransportError::Disconnected)?;
        let running = Arc::new(AtomicBool::new(true));
        let mctp_util = MctpUtil::new();
        let msg_tag = 0u8;
        Ok(MctpPldmSocket {
            source,
            dest,
            target_addr: self.target_addr.into(),
            msg_tag,
            running,
            context: Arc::new(Mutex::new(MctpPldmSocketData {
                stream,
                first_response: None,
                mctp_util,
            })),
            state: Arc::new((Mutex::new(MctpPldmSocketState::Idle), Condvar::new())),
        })
    }
}
