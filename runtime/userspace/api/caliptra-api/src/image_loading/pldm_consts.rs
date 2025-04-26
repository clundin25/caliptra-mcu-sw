use embassy_sync::lazy_lock::LazyLock;
use pldm_common::{
    message::firmware_update::get_fw_params::FirmwareParameters,
    protocol::firmware_update::{
        ComponentActivationMethods, ComponentClassification, ComponentParameterEntry,
        FirmwareDeviceCapability, PldmFirmwareString, PldmFirmwareVersion,
    },
};

pub const FD_FW_COMPONENTS_COUNT: usize = 1;
pub static STREAMING_BOOT_FIRMWARE_PARAMS: LazyLock<FirmwareParameters> = LazyLock::new(|| {
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
        0xffff,
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
