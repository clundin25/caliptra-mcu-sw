// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, GetImageInfoReq, GetImageInfoResp, ImageHashSource, MailboxReqHeader, Request
};
use core::fmt::Write;
use libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use libtock_platform::Syscalls;
use romtime::{println, test_exit};
use zerocopy::{FromBytes, IntoBytes};
use caliptra_auth_man_types::ImageMetadataFlags;

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
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::LoadAddress as u32);

    let mut req = AuthorizeAndStashReq {
        hdr: MailboxReqHeader::default(),
        fw_id: 2u32.to_le_bytes(),

        flags: flags.0,
        source: ImageHashSource::StagingAddress as u32,
        image_size: 128,
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