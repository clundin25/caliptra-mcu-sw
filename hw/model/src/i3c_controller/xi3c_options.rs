#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
extern "C" {
    static mut Xil_AssertStatus: u32_0;
    fn Xil_Assert(File: *const char8, Line: s32);
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int32_t = __int32_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
pub type u8_0 = uint8_t;
pub type u16_0 = uint16_t;
pub type u32_0 = uint32_t;
pub type char8 = libc::c_char;
pub type s32 = int32_t;
pub type u64_0 = uint64_t;
pub type UINTPTR = uintptr_t;
pub type XI3c_IntrHandler = Option<unsafe extern "C" fn(u32_0) -> ()>;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct XI3c_SlaveInfo {
    pub DynaAddr: u8_0,
    pub Id: u64_0,
    pub Bcr: u8_0,
    pub Dcr: u8_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct XI3c {
    pub Config: XI3c_Config,
    pub IsReady: u32_0,
    pub SendBufferPtr: *mut u8_0,
    pub RecvBufferPtr: *mut u8_0,
    pub SendByteCount: u16_0,
    pub RecvByteCount: u16_0,
    pub Error: u8_0,
    pub CurDeviceCount: u8_0,
    pub StatusHandler: XI3c_IntrHandler,
    pub XI3c_SlaveInfoTable: [XI3c_SlaveInfo; 108],
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_SetSClk(
    mut InstancePtr: *mut XI3c,
    mut SclkHz: u32_0,
    mut Mode: u8_0,
) -> s32 {
    let mut THigh: u32_0 = 0;
    let mut TLow: u32_0 = 0;
    let mut THold: u32_0 = 0;
    let mut OdTHigh: u32_0 = 0;
    let mut OdTLow: u32_0 = 0;
    let mut CorePeriodNs: u32_0 = 0;
    let mut TcasMin: u32_0 = 0;
    let mut TsuStart: u32_0 = 0;
    let mut TsuStop: u32_0 = 0;
    let mut ThdStart: u32_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_options.c\0" as *const u8 as *const libc::c_char,
            67 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if SclkHz > 0 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_options.c\0" as *const u8 as *const libc::c_char,
            68 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    THigh = ((*InstancePtr).Config.InputClockHz)
        .wrapping_add(SclkHz)
        .wrapping_sub(1 as libc::c_int as libc::c_uint)
        .wrapping_div(SclkHz)
        >> 1 as libc::c_int;
    TLow = THigh;
    THold = TLow
        .wrapping_mul(4 as libc::c_int as libc::c_uint)
        .wrapping_div(10 as libc::c_int as libc::c_uint);
    CorePeriodNs = (1000000000 as libc::c_int as libc::c_uint)
        .wrapping_add((*InstancePtr).Config.InputClockHz)
        .wrapping_sub(1 as libc::c_int as libc::c_uint)
        .wrapping_div((*InstancePtr).Config.InputClockHz);
    if (Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0 as libc::c_int as u32_0 as libc::c_ulong),
    ) & 0xff00 as libc::c_int as libc::c_uint)
        >> 8 as libc::c_int
        == 0 as libc::c_int as libc::c_uint
    {
        THold = if THold < 5 as libc::c_int as libc::c_uint {
            5 as libc::c_int as libc::c_uint
        } else {
            THold
        };
    } else {
        THold = if THold < 6 as libc::c_int as libc::c_uint {
            6 as libc::c_int as libc::c_uint
        } else {
            THold
        };
    }
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x38 as libc::c_int as u32_0 as libc::c_ulong),
        THigh.wrapping_sub(2 as libc::c_int as libc::c_uint)
            & 0x3ffff as libc::c_int as libc::c_uint,
    );
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x3c as libc::c_int as u32_0 as libc::c_ulong),
        TLow.wrapping_sub(2 as libc::c_int as libc::c_uint)
            & 0x3ffff as libc::c_int as libc::c_uint,
    );
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x40 as libc::c_int as u32_0 as libc::c_ulong),
        THold.wrapping_sub(2 as libc::c_int as libc::c_uint)
            & 0x3ffff as libc::c_int as libc::c_uint,
    );
    if Mode == 0 {
        Xil_Out32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x54 as libc::c_int as u32_0 as libc::c_ulong),
            THigh.wrapping_sub(2 as libc::c_int as libc::c_uint)
                & 0x3ffff as libc::c_int as libc::c_uint,
        );
        Xil_Out32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x58 as libc::c_int as u32_0 as libc::c_ulong),
            TLow.wrapping_sub(2 as libc::c_int as libc::c_uint)
                & 0x3ffff as libc::c_int as libc::c_uint,
        );
        TcasMin = (600000 as libc::c_int as libc::c_uint)
            .wrapping_add(CorePeriodNs)
            .wrapping_sub(1 as libc::c_int as libc::c_uint)
            .wrapping_div(CorePeriodNs);
    } else {
        OdTLow = (500000 as libc::c_int as libc::c_uint)
            .wrapping_add(CorePeriodNs)
            .wrapping_sub(1 as libc::c_int as libc::c_uint)
            .wrapping_div(CorePeriodNs);
        OdTHigh = (41000 as libc::c_int as libc::c_uint)
            .wrapping_add(CorePeriodNs)
            .wrapping_sub(1 as libc::c_int as libc::c_uint)
            .wrapping_div(CorePeriodNs);
        OdTLow = if TLow < OdTLow { OdTLow } else { TLow };
        OdTHigh = if THigh > OdTHigh { OdTHigh } else { THigh };
        Xil_Out32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x54 as libc::c_int as u32_0 as libc::c_ulong),
            OdTHigh.wrapping_sub(2 as libc::c_int as libc::c_uint)
                & 0x3ffff as libc::c_int as libc::c_uint,
        );
        Xil_Out32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x58 as libc::c_int as u32_0 as libc::c_ulong),
            OdTLow.wrapping_sub(2 as libc::c_int as libc::c_uint)
                & 0x3ffff as libc::c_int as libc::c_uint,
        );
        TcasMin = (260000 as libc::c_int as libc::c_uint)
            .wrapping_add(CorePeriodNs)
            .wrapping_sub(1 as libc::c_int as libc::c_uint)
            .wrapping_div(CorePeriodNs);
    }
    ThdStart = if THigh > TcasMin { THigh } else { TcasMin };
    TsuStart = if TLow > TcasMin { TLow } else { TcasMin };
    TsuStop = if TLow > TcasMin { TLow } else { TcasMin };
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x48 as libc::c_int as u32_0 as libc::c_ulong),
        TsuStart.wrapping_sub(2 as libc::c_int as libc::c_uint)
            & 0x3ffff as libc::c_int as libc::c_uint,
    );
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x4c as libc::c_int as u32_0 as libc::c_ulong),
        ThdStart.wrapping_sub(2 as libc::c_int as libc::c_uint)
            & 0x3ffff as libc::c_int as libc::c_uint,
    );
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x50 as libc::c_int as u32_0 as libc::c_ulong),
        TsuStop.wrapping_sub(2 as libc::c_int as libc::c_uint)
            & 0x3ffff as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_long as s32;
}
#[inline]
unsafe extern "C" fn Xil_In32(mut Addr: UINTPTR) -> u32_0 {
    return *(Addr as *mut u32_0);
}
#[inline]
unsafe extern "C" fn Xil_Out32(mut Addr: UINTPTR, mut Value: u32_0) {
    let mut LocalAddr: *mut u32_0 = Addr as *mut u32_0;
    ::core::ptr::write_volatile(LocalAddr, Value);
}
