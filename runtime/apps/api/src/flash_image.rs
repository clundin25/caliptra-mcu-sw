#![no_std]

use libtock_platform::ErrorCode;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FlashHeader {
    pub magic: u32,
    pub version: u16,
    pub image_count: u16,
}

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FlashChecksums {
    pub header_crc32: u32,
    pub payload_crc32: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Clone, Copy, Immutable)]
pub struct ImageInfo {
    pub identifier: u32,
    pub offset: u32,
    pub size: u32,
}

pub struct FlashLayout<'a> {
    pub header: &'a FlashHeader,
    pub checksums: &'a FlashChecksums,
    pub image_infos: &'a [ImageInfo],
}

impl<'a> FlashLayout<'a> {
    pub fn parse(mut flash: &'a [u8]) -> Result<Self, ErrorCode> {


        let (header, rest) = FlashHeader::ref_from_prefix(flash).map_err(|_| ErrorCode::Fail)?;
        flash = rest;

        let (checksums, rest) = FlashChecksums::ref_from_prefix(flash).map_err(|_| ErrorCode::Fail)?;
        flash = rest;


        let image_count = header.image_count as usize;
        let image_infos_size = image_count * core::mem::size_of::<ImageInfo>();

        let (image_infos, _) = ImageInfo::slice_from_prefix(flash, image_count)
            .ok_or(ErrorCode::Fail)?;
        flash = &flash[image_infos_size..];

        Ok(Self {
            header: &header,
            checksums: &checksums,
            image_infos
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // Create a static test buffer instead of heap-allocating Vec
    fn make_test_flash() -> &'static [u8] {
        const FLASH: &[u8] = &[
            // Header: magic, version, image_count
            0x48, 0x53, 0x4C, 0x46,  // "FLSH"
            0x01, 0x00,              // version = 0x0001
            0x02, 0x00,              // image_count = 2

            // Checksums
            0x11, 0x11, 0x11, 0x11,  // header_crc32
            0x22, 0x22, 0x22, 0x22,  // payload_crc32

            // ImageInfo[0]
            0x01, 0x00, 0x00, 0x00,  // identifier
            0x30, 0x00, 0x00, 0x00,  // offset
            0x10, 0x00, 0x00, 0x00,  // size

            // ImageInfo[1]
            0x02, 0x00, 0x00, 0x00,  // identifier
            0x40, 0x00, 0x00, 0x00,  // offset
            0x08, 0x00, 0x00, 0x00,  // size

            // Padding to offset 0x30
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,

            // Image[0] @ 0x30
            0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1,
            0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1,

            // Image[1] @ 0x40
            0xD2, 0xD2, 0xD2, 0xD2, 0xD2, 0xD2, 0xD2, 0xD2,
        ];
        FLASH
    }

    #[test]
    fn test_parse_valid_flash() {
        let flash = make_test_flash();
        let layout = FlashLayout::parse(flash).expect("Parse should succeed");

        assert_eq!(layout.header.magic, 0x464C5348);
        assert_eq!(layout.header.image_count, 2);
        assert_eq!(layout.image_infos.len(), 2);
        // Verify image infos
        assert_eq!(layout.image_infos[0].identifier, 1);
        assert_eq!(layout.image_infos[0].offset, 0x30);
        assert_eq!(layout.image_infos[0].size, 16);
        assert_eq!(layout.image_infos[1].identifier, 2);
        assert_eq!(layout.image_infos[1].offset, 0x40);
        assert_eq!(layout.image_infos[1].size, 8);

    }

    #[test]
    fn test_parse_too_small() {
        static BAD_FLASH: &[u8] = &[0x00; 10];
        let layout = FlashLayout::parse(BAD_FLASH);
        assert!(layout.is_err());
    }
}
