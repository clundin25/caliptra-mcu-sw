use crate::flash_image::{FlashHeader, ImageHeader};
use libsyscall_caliptra::dma::AXIAddr;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    NotRunning,
    Initializing,
    Initialized,
    DownloadingHeader,
    HeaderDownloadComplete,
    DownloadingToc,
    TocDownloadComplete,
    ImageDownloadReady,
    DownloadingImage,
    ImageDownloadComplete,
}

#[derive(Debug, Clone, Copy)]
pub struct DownloadCtx {
    pub total_length: usize,
    pub initial_offset: usize,
    pub current_offset: usize,
    pub total_downloaded: usize,
    pub last_requested_length: usize,
    pub download_complete: bool,
    pub header: [u8; core::mem::size_of::<FlashHeader>()],
    pub image_info: [u8; core::mem::size_of::<ImageHeader>()],
    pub load_address: AXIAddr,
}
