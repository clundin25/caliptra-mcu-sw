// Licensed under the Apache-2.0 license
extern crate alloc;
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
    pub current_offset: usize,
    pub total_downloaded: usize,
    pub download_complete: bool,
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
    StartingPldmService,
    Initializing,
    DownloadingToc,
    ImageDownloadReady,
    DownloadingImage,
    ImageDownloadComplete,
    Done,
}

// declare lazy static StudFdOps
// static mut PLDM_FD_OPS: StubFdOps = StubFdOps::new();
static mut PLDM_STATE: Mutex<CriticalSectionRawMutex, State> = Mutex::new(State::Initializing);
static YIELD_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static MAIN_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static EXECUTOR: LazyLock<TockExecutor> = LazyLock::new(TockExecutor::new);
static mut DOWNLOAD_CTX : Mutex<CriticalSectionRawMutex, DownloadCtx> = Mutex::new(DownloadCtx {
    total_length: 0,
    current_offset: 0,
    total_downloaded: 0,
    download_complete: false,
});

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
            
      
        let STUD_FD_OPS: &'static mut StubFdOps =
            unsafe { core::mem::transmute(&mut STUD_FD_OPS) };

            spawner
                .spawn(pldm_service_task(STUD_FD_OPS, spawner))
                .unwrap();

            writeln!(console_writer, "IMAGE_LOADING: Waiting for PLDM to initialize...").unwrap();
            loop {

                let state = unsafe { PLDM_STATE.lock(|state| *state) };
                if state != State::Initializing {
                    writeln!(console_writer, "IMAGE_LOADING: 1 state {:?}",state).unwrap();
                    break;
                }
                MAIN_SIGNAL.wait().await;                
            }

            writeln!(console_writer, "IMAGE_LOADING: PLDM initialized").unwrap();

            unsafe {
                let download_ctx = DOWNLOAD_CTX.get_mut();
                download_ctx.total_length = 100;
                download_ctx.current_offset = 0;
                download_ctx.total_downloaded = 0;
            }
    
            YIELD_SIGNAL.signal(());

            // Wait for DownloadToc to be ready
            loop {
                let state = unsafe { PLDM_STATE.lock(|state| *state) };
                if state != State::DownloadingToc {
                    writeln!(console_writer, "IMAGE_LOADING: 2 state {:?}",state).unwrap();
                    break;
                }
                MAIN_SIGNAL.wait().await;
            }

        }

        Self {
            mailbox_api: Mailbox::new(),
            source,
            pldm,
        }
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
    


        unsafe {
            let download_ctx = DOWNLOAD_CTX.get_mut();
            download_ctx.total_length = 100;
            download_ctx.current_offset = 500;
            download_ctx.total_downloaded = 0;
            let state = PLDM_STATE.get_mut();
            *state = State::DownloadingImage;
        }


        YIELD_SIGNAL.signal(());
        MAIN_SIGNAL.wait().await;
        writeln!(console_writer, "IMAGE_LOADING: 6 proceeding").unwrap();


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
        // Finalize the image loading process.
        // This could involve sending a completion signal or performing cleanup tasks.
        unsafe {
            let download_ctx = DOWNLOAD_CTX.get_mut();
            download_ctx.download_complete = true;
        }
        YIELD_SIGNAL.signal(());
        Ok(())
    }
}

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
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
        component: &FirmwareComponent,
    ) -> Result<(usize, usize), FdOpsError> {
        let mut console_writer = Console::<libtock_runtime::TockSyscalls>::writer();
        writeln!(console_writer, "IMAGE_LOADING:query_download_offset_and_length called").unwrap();

        unsafe {
            let state = PLDM_STATE.get_mut();
            writeln!(console_writer, "IMAGE_LOADING: 2 state {:?}",*state).unwrap();
            if *state == State::Initializing {
                *state = State::DownloadingToc;
                writeln!(console_writer, "IMAGE_LOADING:3 state {:?} yielding",*state).unwrap();

                    MAIN_SIGNAL.signal(());
                    writeln!(console_writer, "IMAGE_LOADING:3 waiting").unwrap();;
                    YIELD_SIGNAL.wait().await;
                    writeln!(console_writer, "IMAGE_LOADING:4 proceeding").unwrap();;
                
            } else if *state == State::ImageDownloadReady {
                YIELD_SIGNAL.wait().await;
                writeln!(console_writer, "IMAGE_LOADING:5 proceeding").unwrap();;
            }
        }
        let download_ctx = unsafe { DOWNLOAD_CTX.lock(|ctx| *ctx) };
        let offset = download_ctx.current_offset;
        let length = download_ctx.total_length;
        writeln!(console_writer, "IMAGE_LOADING:5 offset {:?} length {:?}",offset,length).unwrap();
        
        Ok((offset, PLDM_FWUP_BASELINE_TRANSFER_SIZE))
    }

    async fn download_fw_data(
        &self,
        offset: usize,
        data: &[u8],
        component: &FirmwareComponent,
    ) -> Result<TransferResult, FdOpsError> {
        let mut console_writer = Console::<libtock_runtime::TockSyscalls>::writer();
        writeln!(console_writer, "IMAGE_LOADING:download_fw_data called offset {} length {}", offset, data.len()).unwrap();

        // update DOWNLOAD_CTX
        unsafe {
            let mut download_ctx = DOWNLOAD_CTX.get_mut();
            download_ctx.total_downloaded += data.len();
            if download_ctx.total_downloaded >= download_ctx.total_length {
                writeln!(console_writer, "IMAGE_LOADING: download complete").unwrap();
                let mut state = PLDM_STATE.get_mut();
                if *state == State::DownloadingToc {
                    *state = State::ImageDownloadReady;
                    writeln!(console_writer, "IMAGE_LOADING: image_download ready").unwrap();
                    MAIN_SIGNAL.signal(());
                }
                else if *state == State::DownloadingImage {
                    *state = State::ImageDownloadComplete;
                    writeln!(console_writer, "IMAGE_LOADING: image_download complete").unwrap();
                    MAIN_SIGNAL.signal(());
                    YIELD_SIGNAL.wait().await;
                }
            } else {
                writeln!(console_writer, "IMAGE_LOADING: downloaded {}/{}", download_ctx.total_downloaded, download_ctx.total_length).unwrap();
                download_ctx.current_offset += data.len();
            }
            
            
        }
        Ok(TransferResult::TransferSuccess)
    }

    async fn is_download_complete(&self, component: &FirmwareComponent) -> bool {
        let download_ctx = unsafe { DOWNLOAD_CTX.lock(|ctx| *ctx) };
        download_ctx.download_complete
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
