// Licensed under the Apache-2.0 license
extern crate alloc;
use core::cell::{Ref, RefCell};
use crate::flash_image::{FlashChecksums, FlashHeader, ImageInfo};
use async_trait::async_trait;
use alloc::boxed::Box;
use embassy_executor::Spawner;
use embassy_sync::signal::Signal;
use pldm_common::message::firmware_update::apply_complete::ApplyResult;
use pldm_common::message::firmware_update::get_status::ProgressPercent;
use pldm_common::message::firmware_update::transfer_complete::TransferResult;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use crate::mailbox::{
    AuthorizeAndStashRequest, GetImageLoadAddressRequest, GetImageLocationOffsetRequest,
    GetImageSizeRequest, Mailbox, MailboxRequest, MailboxRequestType, MailboxResponse,
    AUTHORIZED_IMAGE,
};

use libsyscall_caliptra::dma::{AXIAddr, DMASource, DMATransaction, DMA as DMASyscall};
use libsyscall_caliptra::flash::{driver_num, SpiFlash as FlashSyscall};
use libtock_platform::ErrorCode;
use libtock_platform::Syscalls;
use libtockasync::TockExecutor;

use pldm_common::protocol::firmware_update::{ComponentActivationMethods, ComponentClassification, ComponentParameterEntry, Descriptor, FirmwareDeviceCapability, PldmFirmwareString, PldmFirmwareVersion};
use pldm_lib::daemon::PldmService;

use core::fmt::Write;
use libtock_console::Console;
use romtime::println;
use zerocopy::FromBytes;

pub struct PldmInstance<'a, S: Syscalls> {
    pub pldm_service: Option<PldmService<'a, S>>,
    pub executor: TockExecutor,
}

pub struct ImageLoaderAPI<'a, S: Syscalls> {
    mailbox_api: Mailbox<S>,
    source: ImageSource,
    pldm: Option<PldmInstance<'a, S>>,
}

#[derive(Debug, Clone, Copy)]
pub struct DownloadCtx {
    pub total_length: usize,
    pub initial_offset: usize,
    pub current_offset: usize,
    pub total_downloaded: usize,
    pub download_complete: bool,
    pub header: [u8; core::mem::size_of::<FlashHeader>()],
    pub checksums: [u8; core::mem::size_of::<FlashChecksums>()],
    pub image_info: [u8; core::mem::size_of::<ImageInfo>()],
}

/// This is the size of the buffer used for DMA transfers.
const MAX_TRANSFER_SIZE: usize = 1024;
#[derive(Debug, Clone, Copy)]
pub enum ImageSource {
    // Image is located in Flash
    Flash,
    // Image is retrieved via PLDM
    // PLDM Descriptors should be specified.
    Pldm(&'static [Descriptor]),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    NotRunning,
    Initializing,
    DownloadingHeader,
    HeaderDownloadComplete,
    DownloadingToc,
    TocDownloadComplete,
    ImageDownloadReady,
    DownloadingImage,
    ImageDownloadComplete,
    Done,
}

// declare lazy static StudFdOps
// static mut PLDM_FD_OPS: StubFdOps = StubFdOps::new();
static PLDM_STATE: Mutex<CriticalSectionRawMutex, RefCell<State>> = Mutex::new(RefCell::new(State::Initializing));
static YIELD_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static MAIN_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static DOWNLOAD_CTX : Mutex<CriticalSectionRawMutex, RefCell<DownloadCtx>> = Mutex::new(RefCell::new(DownloadCtx {
    total_length: 0,
    current_offset: 0,
    initial_offset: 0,
    total_downloaded: 0,
    download_complete: false,
    header: [0; core::mem::size_of::<FlashHeader>()],
    checksums: [0; core::mem::size_of::<FlashChecksums>()],
    image_info: [0; core::mem::size_of::<ImageInfo>()],
}));


#[cfg(target_arch = "riscv32")]
#[embassy_executor::task]
pub async fn pldm_service_task(pldm_ops: &'static dyn FdOps, spawner: Spawner) {
    pldm_service::<libtock_runtime::TockSyscalls>(pldm_ops, spawner).await;
}

#[cfg(not(target_arch = "riscv32"))]
#[embassy_executor::task]
async fn pldm_service_task(pldm_ops: &'static dyn FdOps, spawner: Spawner) {
    pldm_service::<libtock_unittest::fake::Syscalls>(pldm_ops, spawner).await;
}

pub async fn pldm_service<S: Syscalls>(pldm_ops: &'static dyn FdOps, spawner: Spawner) {
    let mut pldm_service_init = PldmService::<S>::init(pldm_ops, spawner);
    let mut console_writer = Console::<S>::writer();
    writeln!(console_writer, "IMAGE_LOADING:pldm_service").unwrap();
    pldm_service_init.start().await.unwrap();
}


pub const PLDM_PROTOCOL_CAP_COUNT: usize = 2;
pub const FD_DESCRIPTORS_COUNT: usize = 1;
pub const FD_FW_COMPONENTS_COUNT: usize = 1;
pub const FD_MAX_XFER_SIZE: usize = 512; // Arbitrary limit and change as needed.
pub const DEFAULT_FD_T1_TIMEOUT: PldmFdTime = 120000; // FD_T1 update mode idle timeout, range is [60s, 120s].
pub const DEFAULT_FD_T2_RETRY_TIME: PldmFdTime = 5000; // FD_T2 retry request for firmware data, range is [1s, 5s].
pub const INSTANCE_ID_COUNT: u8 = 32;
pub static FIRMWARE_PARAMS: LazyLock<FirmwareParameters> = LazyLock::new(|| {
    let active_firmware_string = PldmFirmwareString::new("UTF-8", "soc-fw-1.0").unwrap();
    let active_firmware_version =
        PldmFirmwareVersion::new(0x12345678, &active_firmware_string, Some("20250210"));
    let pending_firmware_string = PldmFirmwareString::new("UTF-8", "soc-fw-1.1").unwrap();
    let pending_firmware_version =
        PldmFirmwareVersion::new(0x87654321, &pending_firmware_string, Some("20250213"));
    let comp_activation_methods = ComponentActivationMethods(0x0001);
    let capabilities_during_update = FirmwareDeviceCapability(0x0010);
    let component_parameter_entry = ComponentParameterEntry::new(
        ComponentClassification::Firmware,
        0x0001,
        0,
        &active_firmware_version,
        &pending_firmware_version,
        comp_activation_methods,
        capabilities_during_update,
    );
    FirmwareParameters::new(
        capabilities_during_update,
        FD_FW_COMPONENTS_COUNT as u16,
        &active_firmware_string,
        &pending_firmware_string,
        &[component_parameter_entry],
    )
});

impl<'a, S: Syscalls> ImageLoaderAPI<'a, S> {
    /// Creates a new instance of the ImageLoaderAPI.
    pub async fn new(source: ImageSource, spawner: Spawner) -> Self {
        let mut console_writer = Console::<S>::writer();
        writeln!(
            console_writer,
            "IMAGE_LOADING: Marco Test descriptor source {:?}",
            source
        )
        .unwrap();

        let pldm: Option<PldmInstance<S>> = None;
        if let ImageSource::Pldm(descriptors) = &source {
            if descriptors.is_empty() {
                panic!("PLDM descriptors cannot be empty");
            }
            let mut STUD_FD_OPS: StubFdOps = StubFdOps::new(descriptors);
            
      
            let stud_fd_ops: &'static mut StubFdOps =
            unsafe { core::mem::transmute(&mut STUD_FD_OPS) };

            spawner
                .spawn(pldm_service_task(stud_fd_ops, spawner))
                .unwrap();

            Self::initialize_pldm_download().await;

            writeln!(console_writer, "IMAGE_LOADING: PLDM initialized").unwrap();


           Self::download_header().await;
           

        }

        Self {
            mailbox_api: Mailbox::new(),
            source,
            pldm,
        }
    }

    async fn initialize_pldm_download() {
        let mut console_writer = Console::<S>::writer();
        writeln!(console_writer, "IMAGE_LOADING: Waiting for PLDM to initialize...").unwrap();
     
        loop {
            writeln!(console_writer, "IMAGE_LOADING5: Waiting main").unwrap();
            MAIN_SIGNAL.wait().await; 
            writeln!(console_writer, "IMAGE_LOADING5: Waiting main ok").unwrap();
            let state = PLDM_STATE.lock(|state| *state.borrow());
            if state != State::Initializing {
                writeln!(console_writer, "IMAGE_LOADING: 1 state {:?}",state).unwrap();
                break;
            }
                           
        }
    }

    async fn download_header()  {
        let mut console_writer = Console::<S>::writer();
        DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            ctx.total_length = core::mem::size_of::<FlashHeader>();
            ctx.initial_offset = 0;
            ctx.current_offset = 0;
            ctx.total_downloaded = 0;
        });

        YIELD_SIGNAL.signal(());
        // Wait for DownloadingHeader to be ready
        loop {
            MAIN_SIGNAL.wait().await;
            let state = PLDM_STATE.lock(|state| *state.borrow());
            if state == State::DownloadingToc {
                writeln!(console_writer, "IMAGE_LOADING: 2 state {:?}",state).unwrap();
                break;
            }
            
        }


        DOWNLOAD_CTX.lock(|ctx| {
            let ctx = ctx.borrow();
            let (header, rest) = FlashHeader::ref_from_prefix(&ctx.header).unwrap();
            writeln!(console_writer, "IMAGE_LOADING: header: {:?} ", header).unwrap();
        });
        writeln!(console_writer, "IMAGE_LOADING: download_header exit ").unwrap();

    }

    async fn download_toc(image_id: u32) -> bool
    {
        let mut console_writer = Console::<S>::writer();
        writeln!(console_writer, "IMAGE_LOADING: download_toc enter ").unwrap();

        let num_images = DOWNLOAD_CTX.lock(|ctx| {
            let ctx = ctx.borrow();
            let (header, rest) = FlashHeader::ref_from_prefix(&ctx.header).unwrap();
            header.image_count as usize
        });


        let mut is_image_found = false;
        for index in 0..num_images {
            writeln!(console_writer, "IMAGE_LOADING: download_toc index {} ", index).unwrap();

            
            DOWNLOAD_CTX.lock(|ctx| {
                let mut ctx = ctx.borrow_mut();
                ctx.total_length = core::mem::size_of::<ImageInfo>(); // image info length
                ctx.initial_offset = core::mem::size_of::<FlashHeader>() + core::mem::size_of::<FlashChecksums>() + index * core::mem::size_of::<ImageInfo>();
                ctx.current_offset = ctx.initial_offset;
                ctx.total_downloaded = 0;

                writeln!(console_writer, "IMAGE_LOADING: download_toc offset {} ", ctx.current_offset).unwrap();
            });


            writeln!(console_writer, "IMAGE_LOADING: download_toc yield ").unwrap();
            YIELD_SIGNAL.signal(());
            // Wait for TOC DownloadComplete to be ready
            loop {
                writeln!(console_writer, "IMAGE_LOADING: download_toc main wait ").unwrap();
                MAIN_SIGNAL.wait().await;
                writeln!(console_writer, "IMAGE_LOADING: download_toc main ok ").unwrap();
                let is_dowload_complete  = PLDM_STATE.lock(|state| 
                    {
                        let mut state = state.borrow_mut();
                        if *state == State::TocDownloadComplete {
                            DOWNLOAD_CTX.lock(|ctx| {
                                let ctx = ctx.borrow();
                                let (info, rest) = ImageInfo::ref_from_prefix(&ctx.image_info).unwrap();
                                writeln!(console_writer, "IMAGE_LOADING: image_info: {:?} ", info).unwrap();
                                if (info.identifier == image_id) {
                                    is_image_found = true;
                                    writeln!(console_writer, "IMAGE_LOADING: image found {} ", info.identifier).unwrap();
                                    *state = State::ImageDownloadReady;
                                }
                                else {
                                    *state = State::DownloadingToc;
                                }
                            });
                            
                            return true;
                        }
                        else 
                        {
                            return false;
                        }
                    }    
                );
                if is_dowload_complete {
                    writeln!(console_writer, "IMAGE_LOADING: download_toc TocDownloadComplete").unwrap();
                    break;
                }
            }

            if is_image_found {
                break;
            }

        }


        writeln!(console_writer, "IMAGE_LOADING: download_toc exit ").unwrap();
        is_image_found
    }

    /// Loads the specified image to a storage mapped to the AXI bus memory map.
    ///
    /// # Parameters
    /// image_id: The unsigned integer identifier of the image.
    ///
    /// # Returns
    /// - `Ok()`: Image has been loaded and authorized succesfully.
    /// - `Err(ErrorCode)`: Indication of the failure to load or authorize the image.
    pub async fn load_and_authorize(&self, image_id: u32) -> Result<(), ErrorCode> {

        let mut console_writer = Console::<S>::writer();
        writeln!(
            console_writer,
            "IMAGE_LOADING: load_and_authorize {:?}",
            image_id
        )
        .unwrap();
    

        if Self::download_toc(image_id).await {
            writeln!(console_writer, "IMAGE_LOADING: download_toc image found").unwrap();
        } else {
            writeln!(console_writer, "IMAGE_LOADING: download_toc image not found").unwrap();
            self.finalize().await?;
            return Err(ErrorCode::Fail);
        }


/*
        let offset = self.get_image_offset(image_id).await?;
        let img_size = self.get_image_size(image_id).await?;
        let load_address = self.get_image_load_address(image_id).await?;
        self.load_image(load_address, offset as usize, img_size)
            .await?;
        self.authorize_image(image_id).await?;
 */
        Ok(())
    }

    /// Retrieves the offset of the image in memory.
    async fn get_image_offset(&self, image_id: u32) -> Result<u32, ErrorCode> {
        let mut request = GetImageLocationOffsetRequest {
            fw_id: image_id.to_be_bytes(),
            ..Default::default()
        };
        request.populate_checksum();
        let response = self
            .mailbox_api
            .execute_command(&MailboxRequest::GetImageLocationOffset(request))
            .await?;
        if let MailboxResponse::GetImageLocationOffset(res) = response {
            Ok(res.offset)
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Fetches the load address of the image.
    async fn get_image_load_address(&self, image_id: u32) -> Result<u64, ErrorCode> {
        let mut request = GetImageLoadAddressRequest {
            fw_id: image_id.to_be_bytes(),
            ..Default::default()
        };
        request.populate_checksum();
        let response = self
            .mailbox_api
            .execute_command(&MailboxRequest::GetImageLoadAddress(request))
            .await?;
        if let MailboxResponse::GetImageLoadAddress(res) = response {
            Ok((res.load_address_high as u64) << 32 | res.load_address_low as u64)
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Retrieves the size of the image in bytes.
    async fn get_image_size(&self, image_id: u32) -> Result<usize, ErrorCode> {
        let mut request = GetImageSizeRequest {
            fw_id: image_id.to_be_bytes(),
            ..Default::default()
        };
        request.populate_checksum();
        let response = self
            .mailbox_api
            .execute_command(&MailboxRequest::GetImageSize(request))
            .await?;
        if let MailboxResponse::GetImageSize(res) = response {
            Ok(res.size as usize)
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Authorizes an image based on its ID.
    async fn authorize_image(&self, image_id: u32) -> Result<(), ErrorCode> {
        let mut request = AuthorizeAndStashRequest {
            fw_id: image_id.to_be_bytes(),
            ..Default::default()
        };
        request.populate_checksum();
        let response = self
            .mailbox_api
            .execute_command(&MailboxRequest::AuthorizeAndStash(request))
            .await?;
        if let MailboxResponse::AuthorizeAndStash(res) = response {
            if res.auth_req_result == AUTHORIZED_IMAGE {
                return Ok(());
            }
        }
        Err(ErrorCode::Fail)
    }

    /// Loads an image from flash into the specified address using DMA transfers.
    async fn load_image(
        &self,
        load_address: AXIAddr,
        offset: usize,
        img_size: usize,
    ) -> Result<(), ErrorCode> {
        let dma_syscall = DMASyscall::<S>::new();
        let flash_syscall = FlashSyscall::<S>::new(driver_num::ACTIVE_IMAGE_PARTITION);
        let mut remaining_size = img_size;
        let mut current_offset = offset;
        let mut current_address = load_address;

        while remaining_size > 0 {
            let transfer_size = remaining_size.min(MAX_TRANSFER_SIZE);
            let mut buffer = [0; MAX_TRANSFER_SIZE];
            flash_syscall
                .read(current_offset, transfer_size, &mut buffer)
                .await?;
            let transaction = DMATransaction {
                byte_count: transfer_size,
                source: DMASource::Buffer(&buffer[..transfer_size]),
                dest_addr: current_address,
            };
            dma_syscall.xfer(&transaction).await?;
            remaining_size -= transfer_size;
            current_offset += transfer_size;
            current_address += transfer_size as u64;
        }

        Ok(())
    }


    pub async fn finalize(&self) -> Result<(), ErrorCode> {
        let mut console_writer = Console::<libtock_runtime::TockSyscalls>::writer();
        writeln!(console_writer, "IMAGE_LOADING: finalize").unwrap();
        DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            ctx.download_complete = true;
        });
        writeln!(console_writer, "IMAGE_LOADING: finalize yield").unwrap();
        YIELD_SIGNAL.signal(());
        Ok(())
    }
}

use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::lazy_lock::LazyLock;
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::protocol::firmware_update::{
    ComponentResponseCode, PldmFdTime, PLDM_FWUP_BASELINE_TRANSFER_SIZE,
};
use pldm_common::util::fw_component::FirmwareComponent;
use pldm_lib::firmware_device::fd_ops::{ComponentOperation, FdOps, FdOpsError};

/// Stub implementation of the FdOps trait for testing and development purposes.
pub struct StubFdOps {
    descriptors: &'static [Descriptor],
}

impl StubFdOps {
    /// Creates a new instance of the StubFdOps.
    pub const fn new(descriptors: &'static [Descriptor]) -> Self {
        Self { descriptors }
    }

    fn copy_data_to_buffer(
        &self,
        _offset: usize,
        data: &[u8],
        _component: &FirmwareComponent,
    ) -> Result<(), FdOpsError> {
        let mut console_writer = Console::<libtock_runtime::TockSyscalls>::writer();

        let state = PLDM_STATE.lock(|state| {*state.borrow()});


        DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            ctx.total_downloaded += data.len();
            let start = ctx.current_offset-ctx.initial_offset;


            if state == State::DownloadingHeader {
                let end = (start + data.len()).min(ctx.header.len());
                writeln!(console_writer, "IMAGE_LOADING: start {} end{}", start, end).unwrap();
                ctx.header[start..end].copy_from_slice(&data[..end - start]);
            }  else if state == State::DownloadingToc {
                let end = (start + data.len()).min(ctx.image_info.len());
                ctx.image_info[start..end].copy_from_slice(&data[..end - start]);
                
            }
            else if state == State::DownloadingImage {
                
            }

            writeln!(console_writer, "IMAGE_LOADING: PLDM_STATE unlocked ").unwrap();
        });
        Ok(())
    }
}

#[async_trait(?Send)]
impl FdOps for StubFdOps {
    async fn get_device_identifiers(
        &self,
        device_identifiers: &mut [Descriptor],
    ) -> Result<usize, FdOpsError> {
        let mut console_writer = Console::<libtock_runtime::TockSyscalls>::writer();
        writeln!(console_writer, "IMAGE_LOADING:get_device_identifiers called").unwrap();
        self.descriptors
            .iter()
            .enumerate()
            .for_each(|(i, descriptor)| {
                if i < device_identifiers.len() {
                    device_identifiers[i] = *descriptor;
                }
            });
        Ok(self.descriptors.len())
    }

    async fn get_firmware_parms(
        &self,
        firmware_params: &mut FirmwareParameters,
    ) -> Result<(), FdOpsError> {
        let fw_params = FIRMWARE_PARAMS.get();
        *firmware_params = (*fw_params).clone();
        Ok(())

    }

    async fn get_xfer_size(&self, ua_transfer_size: usize) -> Result<usize, FdOpsError> {
        // Return the minimum of requested and baseline transfer size
        let size = core::cmp::min(ua_transfer_size, PLDM_FWUP_BASELINE_TRANSFER_SIZE);
        Ok(size)
    }

    async fn handle_component(
        &self,
        _component: &FirmwareComponent,
        _fw_params: &FirmwareParameters,
        _op: ComponentOperation,
    ) -> Result<ComponentResponseCode, FdOpsError> {
        // Always return success response code for stub
        Ok(ComponentResponseCode::CompCanBeUpdated)
    }

    async fn now(&self) -> PldmFdTime {
        // Return a dummy timestamp (e.g., 123456 ms)
        PldmFdTime::from_le(123_456)
    }

    
    async fn query_download_offset_and_length(
        &self,
        _component: &FirmwareComponent,
    ) -> Result<(usize, usize), FdOpsError> {
        let mut console_writer = Console::<libtock_runtime::TockSyscalls>::writer();
        writeln!(console_writer, "IMAGE_LOADING:query_download_offset_and_length called").unwrap();


        let should_yield = PLDM_STATE.lock(|state| {
            let mut state = state.borrow_mut();
            writeln!(console_writer, "IMAGE_LOADING: 2 state {:?}",state).unwrap();
            if *state == State::Initializing {
                *state = State::DownloadingHeader;
                return true;
            } else if *state == State::HeaderDownloadComplete {
                *state = State::DownloadingToc;
                return true;
            } else if *state == State::ImageDownloadReady {
                return true;
            }
            return false;
        });
        if should_yield {
            writeln!(console_writer, "IMAGE_LOADING:3 yielding").unwrap();
            MAIN_SIGNAL.signal(());
            writeln!(console_writer, "IMAGE_LOADING:3 waiting").unwrap();
            YIELD_SIGNAL.wait().await;
            writeln!(console_writer, "IMAGE_LOADING:4 proceeding").unwrap();;
        }

        let offset =  DOWNLOAD_CTX.lock(|ctx| ctx.borrow().current_offset);
       
        Ok((offset, PLDM_FWUP_BASELINE_TRANSFER_SIZE))
    }

    async fn download_fw_data(
        &self,
        offset: usize,
        data: &[u8],
        _component: &FirmwareComponent,
    ) -> Result<TransferResult, FdOpsError> {
        let mut console_writer = Console::<libtock_runtime::TockSyscalls>::writer();
        writeln!(console_writer, "IMAGE_LOADING:download_fw_data called offset {} length {}", offset, data.len()).unwrap();

        self.copy_data_to_buffer(offset, data, _component)?;


        // update DOWNLOAD_CTX
        let should_yield = DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            ctx.total_downloaded += data.len();
            writeln!(console_writer, "IMAGE_LOADING: downloadedb {}/{}", ctx.total_downloaded, ctx.total_length).unwrap();

    
            if ctx.total_downloaded >= ctx.total_length {
                writeln!(console_writer, "IMAGE_LOADING: download complete").unwrap();

                PLDM_STATE.lock(|state| {
                    writeln!(console_writer, "IMAGE_LOADING: download complete PLDM_STATE locked").unwrap();
                    let mut state = state.borrow_mut();
                    if *state == State::DownloadingHeader {
                        *state = State::HeaderDownloadComplete;
                        writeln!(console_writer, "IMAGE_LOADING: HeaderDownloadComplete").unwrap();
                        return false;
                        
                    }  else if *state == State::DownloadingToc {
                        *state = State::TocDownloadComplete;
                        writeln!(console_writer, "IMAGE_LOADING: TocDownloadComplete - yield true").unwrap();
                        
                        return true;
                    }
                    else if *state == State::DownloadingImage {
                        *state = State::ImageDownloadComplete;
                        writeln!(console_writer, "IMAGE_LOADING: Downloading Image").unwrap();
                        return true;
                    }
                    return false;
                })
            } else {
                ctx.current_offset += data.len();
                return false;
            }
        });

        if should_yield {
            MAIN_SIGNAL.signal(());
            YIELD_SIGNAL.wait().await;
            writeln!(console_writer, "IMAGE_LOADING: 7 proceeding").unwrap();
        }        


            
        Ok(TransferResult::TransferSuccess)
    }

    async fn is_download_complete(&self, component: &FirmwareComponent) -> bool {
        DOWNLOAD_CTX.lock(|ctx| ctx.borrow().download_complete) 
    }

    async fn verify(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<VerifyResult, FdOpsError> {
        *progress_percent = ProgressPercent::new(100).unwrap();
        Ok(VerifyResult::VerifySuccess)
    }

    async fn apply(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<ApplyResult, FdOpsError> {
        *progress_percent = ProgressPercent::new(100).unwrap();
        Ok(ApplyResult::ApplySuccess)
    }

    async fn activate(
        &self,
        self_contained_activation: u8,
        estimated_time: &mut u16,
    ) -> Result<u8, FdOpsError> {
        *estimated_time = 0;
        Ok(0) // PLDM completion code for success
    }
}
