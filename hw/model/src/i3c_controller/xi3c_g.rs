#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uintptr_t = libc::c_ulong;
pub type u8_0 = uint8_t;
pub type u16_0 = uint16_t;
pub type u32_0 = uint32_t;
pub type UINTPTR = uintptr_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct XI3c_Config {
    pub DeviceId: u16_0,
    pub BaseAddress: UINTPTR,
    pub InputClockHz: u32_0,
    pub RwFifoDepth: u8_0,
    pub WrThreshold: u8_0,
    pub DeviceCount: u8_0,
    pub IbiCapable: u8_0,
    pub HjCapable: u8_0,
}
#[no_mangle]
pub static mut XI3c_ConfigTable: XI3c_Config = XI3c_Config {
    DeviceId: 0,
    BaseAddress: 0,
    InputClockHz: 0,
    RwFifoDepth: 0,
    WrThreshold: 0,
    DeviceCount: 0,
    IbiCapable: 0,
    HjCapable: 0,
};
