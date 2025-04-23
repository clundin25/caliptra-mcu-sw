// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, GetImageInfoReq, GetImageInfoResp, ImageHashSource, MailboxReqHeader, Request
};
use core::fmt::Write;
use libsyscall_caliptra::{dma::{DMASource, DMATransaction, DMA as DMASyscall}, mailbox::{Mailbox, MailboxError}};
use libtock_platform::Syscalls;
use romtime::{println, test_exit};
use zerocopy::{FromBytes, IntoBytes};
use caliptra_auth_man_types::ImageMetadataFlags;
const MCU_SRAM_HI_OFFSET: u64 = 0x1000_0000;
const EXTERNAL_SRAM_HI_OFFSET: u64 = 0x2000_0000;

#[allow(unused)]
pub(crate) async fn test_get_image_info<S: Syscalls>() {
    println!("Starting test_get_image_info test");

    let mailbox = Mailbox::<S>::new();

    let mut req = GetImageInfoReq {
        hdr: MailboxReqHeader::default(),
        fw_id: 2u32.to_le_bytes(),
    };
    let req_data = req.as_mut_bytes();
    mailbox
        .populate_checksum(GetImageInfoReq::ID.into(), req_data)
        .unwrap();

    let response_buffer = &mut [0u8; core::mem::size_of::<GetImageInfoResp>()];

    println!("Sending GET_IMAGE_INFO command");

    if let Err(err) = mailbox
        .execute(GetImageInfoReq::ID.0, req_data, response_buffer)
        .await
    {
        println!("Mailbox command failed with err {:?}", err);
        test_exit(1);
    }

    println!("Mailbox command success");

    if response_buffer.iter().all(|&x| x == 0) {
        println!("Mailbox response all 0");
        test_exit(1);
    }

    match GetImageInfoResp::ref_from_bytes(response_buffer) {
        Ok(resp) => {
            println!("Image Info: {:?}", resp);
        }
        Err(err) => {
            println!("Failed to parse response: {:?}", err);
            romtime::test_exit(1);
        }
    }
    println!("Test passed");
}


pub(crate) async fn test_authorize_and_stash<S: Syscalls>() {
    println!("Starting test_authorize_and_stash test");

    let mailbox = Mailbox::<S>::new();



    let dma_syscall = DMASyscall::<S>::new();

    let load_memory_contents = [0x55u8; 64];

    // Address of my_buffer_source
    let source_address = (MCU_SRAM_HI_OFFSET << 32) |  (&load_memory_contents as *const _ as u64);
    let dest_address = (EXTERNAL_SRAM_HI_OFFSET << 32) |  0u64;

    println!("Emulator source address: {:#x}", source_address);
    println!("Emulator destination address: {:#x}", dest_address);

    let transaction = DMATransaction {
        byte_count: load_memory_contents.len(),
        source: DMASource::Address(source_address),
        dest_addr: dest_address,
    };
    println!("Emulator calling DMA transfer");
    dma_syscall.xfer(&transaction).await.unwrap();








    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::LoadAddress as u32);

    let mut req = AuthorizeAndStashReq {
        hdr: MailboxReqHeader::default(),
        fw_id: 10u32.to_le_bytes(),

        flags: flags.0,
        source: ImageHashSource::StagingAddress as u32,
        image_size: load_memory_contents.len() as u32,
        ..Default::default()
    };
    let req_data = req.as_mut_bytes();
    mailbox
        .populate_checksum(AuthorizeAndStashReq::ID.into(), req_data)
        .unwrap();

    let response_buffer = &mut [0u8; core::mem::size_of::<AuthorizeAndStashResp>()];

    println!("Sending AUTHORIZE_AND_STASH command");

    if let Err(err) = mailbox
        .execute(AuthorizeAndStashReq::ID.0, req_data, response_buffer)
        .await
    {
        println!("Mailbox command failed with err {:?}", err);
        test_exit(1);
    }

    println!("Mailbox command success");

    if response_buffer.iter().all(|&x| x == 0) {
        println!("Mailbox response all 0");
        test_exit(1);
    }

    match AuthorizeAndStashResp::ref_from_bytes(response_buffer) {
        Ok(resp) => {
            println!("AuthorizeAndStashResp: {:?}", resp);
        }
        Err(err) => {
            println!("Failed to parse response: {:?}", err);
            romtime::test_exit(1);
        }
    }
    println!("Test passed");
}