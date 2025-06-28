// Licensed under the Apache-2.0 license

use crate::recovery;
use caliptra_emu_bus::{Device, Event, EventData, RecoveryCommandCode};
use std::sync::mpsc;

pub struct Bmc {
    /// Recovery state machine
    recovery_state_machine: recovery::StateMachine<recovery::Context>,

    // Channel for events going into BMC
    incoming_event_sender: mpsc::Sender<Event>,
    incoming_events: mpsc::Receiver<Event>,

    // Channel for events going out of BMC
    outgoing_event_sender: mpsc::Sender<Event>,
    outgoing_events: Option<mpsc::Receiver<Event>>,
}

impl Bmc {
    pub fn new() -> Bmc {
        
        let (incoming_event_sender, incoming_events) = mpsc::channel::<Event>();
        let (outgoing_event_sender, outgoing_events) = mpsc::channel::<Event>();
        let recovery_context = recovery::Context::new(outgoing_event_sender.clone());
        Bmc {
            recovery_state_machine: recovery::StateMachine::new(recovery_context),
            incoming_event_sender,
            incoming_events,
            outgoing_event_sender,
            outgoing_events:Some(outgoing_events),
          

        }
    }

    pub fn get_event_sender(&self) -> mpsc::Sender<Event> {
        self.incoming_event_sender.clone()
    }

    pub fn get_event_receiver(&mut self) -> Option<mpsc::Receiver<Event>> {
        self.outgoing_events.take()
    }


    pub fn push_recovery_image(&mut self, image: Vec<u8>) {
        self.recovery_state_machine
            .context_mut()
            .recovery_images
            .push(image);
    }

    /// Called once every clock cycle by the emulator so the BMC can do work
    pub fn step(&mut self) {
        let prev_state = *self.recovery_state_machine.state();
        // process any incoming events
        while let Ok(event) = self.incoming_events.try_recv() {
            match event.dest {
                Device::BMC => self.incoming_caliptra_event(event),
                _ => {}
            }
        }

        self.recovery_step();
        if prev_state != *self.recovery_state_machine.state() {
            println!(
                "[emulator bmc recovery] Recovery state transition: {:?} -> {:?}",
                prev_state,
                self.recovery_state_machine.state()
            );
        }
    }

    /// Take any actions for the recovery interface.
    fn recovery_step(&mut self) {
        let state = *self.recovery_state_machine.state();
        if state == recovery::States::Done {
            return;
        }

        if let Some(event) = recovery::state_to_read_request(state) {
            self.outgoing_event_sender.send(event).unwrap();
        }
    }

    pub fn incoming_mcu_event(&mut self, _event: Event) {
        // do nothing for now
    }

    // translate from Caliptra events to state machine events
    pub fn incoming_caliptra_event(&mut self, event: Event) {
        match &event.event {
            EventData::RecoveryBlockReadResponse {
                source_addr: _,
                target_addr: _,
                command_code,
                payload,
            } => match command_code {
                RecoveryCommandCode::ProtCap => {
                    if payload.len() >= 15 {
                        let msg2 = u32::from_le_bytes(payload[8..12].try_into().unwrap());
                        let prot_cap = msg2.into();
                        let _ = self
                            .recovery_state_machine
                            .process_event(recovery::Events::ProtCap(prot_cap));
                    } else {
                        println!("Invalid ProtCap payload (should be at least 15 bytes); ignoring message");
                    }
                }
                RecoveryCommandCode::DeviceStatus => {
                    if payload.len() >= 4 {
                        let status0: u32 = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                        let device_status = status0.into();
                        let _ = self
                            .recovery_state_machine
                            .process_event(recovery::Events::DeviceStatus(device_status));
                    } else {
                        println!("Invalid DeviceStatus payload (should be at least 4 bytes); ignoring message");
                    }
                }
                RecoveryCommandCode::RecoveryStatus => {
                    if payload.len() >= 2 {
                        let status0: u16 = u16::from_le_bytes(payload[0..2].try_into().unwrap());
                        let recovery_status = (status0 as u32).into();
                        let _ = self
                            .recovery_state_machine
                            .process_event(recovery::Events::RecoveryStatus(recovery_status));
                    } else {
                        println!("Invalid RecoveryStatus payload (should be at least 2 bytes); ignoring message");
                    }
                }
                _ => todo!(),
            },
            _ => todo!(),
        }
    }
}
