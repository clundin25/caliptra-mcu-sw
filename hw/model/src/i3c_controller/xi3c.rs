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
    fn usleep(useconds: ULONG);
    fn XI3c_SendTransferCmd(InstancePtr: *mut XI3c, Cmd: *mut XI3c_Cmd, Data: u8_0) -> s32;
    fn XI3c_MasterRecvPolled(
        InstancePtr: *mut XI3c,
        Cmd: *mut XI3c_Cmd,
        MsgPtr: *mut u8_0,
        ByteCount: u16_0,
    ) -> s32;
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
pub type ULONG = libc::c_ulong;
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
pub struct XI3c_Cmd {
    pub CmdType: u8_0,
    pub NoRepeatedStart: u8_0,
    pub Pec: u8_0,
    pub SlaveAddr: u8_0,
    pub Rw: u8_0,
    pub ByteCount: u16_0,
    pub Tid: u8_0,
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
pub static mut XI3C_DynaAddrList: [u8_0; 108] = [
    0x8 as libc::c_int as u8_0,
    0x9 as libc::c_int as u8_0,
    0xa as libc::c_int as u8_0,
    0xb as libc::c_int as u8_0,
    0xc as libc::c_int as u8_0,
    0xd as libc::c_int as u8_0,
    0xe as libc::c_int as u8_0,
    0xf as libc::c_int as u8_0,
    0x10 as libc::c_int as u8_0,
    0x11 as libc::c_int as u8_0,
    0x12 as libc::c_int as u8_0,
    0x13 as libc::c_int as u8_0,
    0x14 as libc::c_int as u8_0,
    0x15 as libc::c_int as u8_0,
    0x16 as libc::c_int as u8_0,
    0x17 as libc::c_int as u8_0,
    0x18 as libc::c_int as u8_0,
    0x19 as libc::c_int as u8_0,
    0x1a as libc::c_int as u8_0,
    0x1b as libc::c_int as u8_0,
    0x1c as libc::c_int as u8_0,
    0x1d as libc::c_int as u8_0,
    0x1e as libc::c_int as u8_0,
    0x1f as libc::c_int as u8_0,
    0x20 as libc::c_int as u8_0,
    0x21 as libc::c_int as u8_0,
    0x22 as libc::c_int as u8_0,
    0x23 as libc::c_int as u8_0,
    0x24 as libc::c_int as u8_0,
    0x25 as libc::c_int as u8_0,
    0x26 as libc::c_int as u8_0,
    0x27 as libc::c_int as u8_0,
    0x28 as libc::c_int as u8_0,
    0x29 as libc::c_int as u8_0,
    0x2a as libc::c_int as u8_0,
    0x2b as libc::c_int as u8_0,
    0x2c as libc::c_int as u8_0,
    0x2d as libc::c_int as u8_0,
    0x2e as libc::c_int as u8_0,
    0x2f as libc::c_int as u8_0,
    0x30 as libc::c_int as u8_0,
    0x31 as libc::c_int as u8_0,
    0x32 as libc::c_int as u8_0,
    0x33 as libc::c_int as u8_0,
    0x34 as libc::c_int as u8_0,
    0x35 as libc::c_int as u8_0,
    0x36 as libc::c_int as u8_0,
    0x37 as libc::c_int as u8_0,
    0x38 as libc::c_int as u8_0,
    0x39 as libc::c_int as u8_0,
    0x3a as libc::c_int as u8_0,
    0x3b as libc::c_int as u8_0,
    0x3c as libc::c_int as u8_0,
    0x3d as libc::c_int as u8_0,
    0x3f as libc::c_int as u8_0,
    0x40 as libc::c_int as u8_0,
    0x41 as libc::c_int as u8_0,
    0x42 as libc::c_int as u8_0,
    0x43 as libc::c_int as u8_0,
    0x44 as libc::c_int as u8_0,
    0x45 as libc::c_int as u8_0,
    0x46 as libc::c_int as u8_0,
    0x47 as libc::c_int as u8_0,
    0x48 as libc::c_int as u8_0,
    0x49 as libc::c_int as u8_0,
    0x4a as libc::c_int as u8_0,
    0x4b as libc::c_int as u8_0,
    0x4c as libc::c_int as u8_0,
    0x4d as libc::c_int as u8_0,
    0x4e as libc::c_int as u8_0,
    0x4f as libc::c_int as u8_0,
    0x50 as libc::c_int as u8_0,
    0x51 as libc::c_int as u8_0,
    0x52 as libc::c_int as u8_0,
    0x53 as libc::c_int as u8_0,
    0x54 as libc::c_int as u8_0,
    0x55 as libc::c_int as u8_0,
    0x56 as libc::c_int as u8_0,
    0x57 as libc::c_int as u8_0,
    0x58 as libc::c_int as u8_0,
    0x59 as libc::c_int as u8_0,
    0x5a as libc::c_int as u8_0,
    0x5b as libc::c_int as u8_0,
    0x5c as libc::c_int as u8_0,
    0x5d as libc::c_int as u8_0,
    0x5f as libc::c_int as u8_0,
    0x60 as libc::c_int as u8_0,
    0x61 as libc::c_int as u8_0,
    0x62 as libc::c_int as u8_0,
    0x63 as libc::c_int as u8_0,
    0x64 as libc::c_int as u8_0,
    0x65 as libc::c_int as u8_0,
    0x66 as libc::c_int as u8_0,
    0x67 as libc::c_int as u8_0,
    0x68 as libc::c_int as u8_0,
    0x69 as libc::c_int as u8_0,
    0x6a as libc::c_int as u8_0,
    0x6b as libc::c_int as u8_0,
    0x6c as libc::c_int as u8_0,
    0x6d as libc::c_int as u8_0,
    0x6f as libc::c_int as u8_0,
    0x70 as libc::c_int as u8_0,
    0x71 as libc::c_int as u8_0,
    0x72 as libc::c_int as u8_0,
    0x73 as libc::c_int as u8_0,
    0x74 as libc::c_int as u8_0,
    0x75 as libc::c_int as u8_0,
    0x77 as libc::c_int as u8_0,
];
#[no_mangle]
pub unsafe extern "C" fn XI3C_BusInit(mut InstancePtr: *mut XI3c) {
    let mut Cmd: XI3c_Cmd = XI3c_Cmd {
        CmdType: 0,
        NoRepeatedStart: 0,
        Pec: 0,
        SlaveAddr: 0,
        Rw: 0,
        ByteCount: 0,
        Tid: 0,
    };
    let mut Status: s32 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.c\0" as *const u8 as *const libc::c_char,
            71 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    Cmd.SlaveAddr = 0x7e as libc::c_int as u8_0;
    Cmd.NoRepeatedStart = 1 as libc::c_int as u8_0;
    Cmd.Tid = 0 as libc::c_int as u8_0;
    Cmd.Pec = 0 as libc::c_int as u8_0;
    Cmd.CmdType = 1 as libc::c_int as u8_0;
    Status = XI3c_SendTransferCmd(InstancePtr, &mut Cmd, 0x1 as libc::c_int as u8_0);
    if Status as libc::c_long != 0 as libc::c_long {
        return;
    }
    Cmd.SlaveAddr = 0x7e as libc::c_int as u8_0;
    Cmd.NoRepeatedStart = 1 as libc::c_int as u8_0;
    Cmd.Tid = 0 as libc::c_int as u8_0;
    Cmd.Pec = 0 as libc::c_int as u8_0;
    Cmd.CmdType = 1 as libc::c_int as u8_0;
    Status = XI3c_SendTransferCmd(InstancePtr, &mut Cmd, 0 as libc::c_int as u8_0);
    if Status as libc::c_long != 0 as libc::c_long {
        return;
    }
    Cmd.SlaveAddr = 0x7e as libc::c_int as u8_0;
    Cmd.NoRepeatedStart = 1 as libc::c_int as u8_0;
    Cmd.Tid = 0 as libc::c_int as u8_0;
    Cmd.Pec = 0 as libc::c_int as u8_0;
    Cmd.CmdType = 1 as libc::c_int as u8_0;
    Status = XI3c_SendTransferCmd(InstancePtr, &mut Cmd, 0x6 as libc::c_int as u8_0);
    if Status as libc::c_long != 0 as libc::c_long {
        return;
    }
}
#[inline]
unsafe extern "C" fn Xil_In32(mut Addr: UINTPTR) -> u32_0 {
    return *(Addr as *mut u32_0);
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_CfgInitialize(
    mut InstancePtr: *mut XI3c,
    mut ConfigPtr: *mut XI3c_Config,
    mut EffectiveAddr: u32_0,
) -> s32 {
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.c\0" as *const u8 as *const libc::c_char,
            141 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if !ConfigPtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.c\0" as *const u8 as *const libc::c_char,
            142 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        return 5 as libc::c_long as s32;
    }
    (*InstancePtr).Config.DeviceId = (*ConfigPtr).DeviceId;
    (*InstancePtr).Config.BaseAddress = EffectiveAddr as UINTPTR;
    (*InstancePtr).Config.InputClockHz = (*ConfigPtr).InputClockHz;
    (*InstancePtr).Config.RwFifoDepth = (*ConfigPtr).RwFifoDepth;
    (*InstancePtr).Config.WrThreshold =
        ((*ConfigPtr).WrThreshold as libc::c_int * 4 as libc::c_int) as u8_0;
    (*InstancePtr).Config.DeviceCount = (*ConfigPtr).DeviceCount;
    (*InstancePtr).Config.IbiCapable = (*ConfigPtr).IbiCapable;
    (*InstancePtr).Config.HjCapable = (*ConfigPtr).HjCapable;
    (*InstancePtr).CurDeviceCount = 0 as libc::c_int as u8_0;
    (*InstancePtr).IsReady = 0x11111111 as libc::c_uint;
    XI3c_Reset(InstancePtr);
    XI3c_ResetFifos(InstancePtr);
    if (*InstancePtr).Config.IbiCapable != 0 {
        XI3c_EnableIbi(InstancePtr);
    }
    if (*InstancePtr).Config.HjCapable != 0 {
        XI3c_EnableHotjoin(InstancePtr);
    }
    XI3c_Enable(InstancePtr, 1 as libc::c_int as u8_0);
    XI3C_BusInit(InstancePtr);
    if (*InstancePtr).Config.IbiCapable as libc::c_int != 0
        && (*InstancePtr).Config.DeviceCount as libc::c_int != 0
    {
        XI3c_DynaAddrAssign(
            InstancePtr,
            XI3C_DynaAddrList.as_mut_ptr(),
            (*InstancePtr).Config.DeviceCount,
        );
        XI3c_ConfigIbi(InstancePtr, (*InstancePtr).Config.DeviceCount);
    }
    if (*InstancePtr).Config.HjCapable != 0 {
        Xil_Out32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
            Xil_In32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
            ) | 0x100 as libc::c_int as libc::c_uint,
        );
    }
    return 0 as libc::c_long as s32;
}
#[inline]
unsafe extern "C" fn Xil_Out32(mut Addr: UINTPTR, mut Value: u32_0) {
    let mut LocalAddr: *mut u32_0 = Addr as *mut u32_0;
    ::core::ptr::write_volatile(LocalAddr, Value);
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_FillCmdFifo(mut InstancePtr: *mut XI3c, mut Cmd: *mut XI3c_Cmd) {
    let mut TransferCmd: u32_0 = 0 as libc::c_int as u32_0;
    let mut DevAddr: u8_0 = 0 as libc::c_int as u8_0;
    DevAddr = (((*Cmd).SlaveAddr as libc::c_int & 0x7f as libc::c_int) << 1 as libc::c_int
        | (*Cmd).Rw as libc::c_int & 0x1 as libc::c_int) as u8_0;
    TransferCmd = ((*Cmd).CmdType as libc::c_int & 0xf as libc::c_int) as u32_0;
    TransferCmd |=
        (((*Cmd).NoRepeatedStart as libc::c_int & 0x1 as libc::c_int) as u32_0) << 4 as libc::c_int;
    TransferCmd |= (((*Cmd).Pec as libc::c_int & 0x1 as libc::c_int) as u32_0) << 5 as libc::c_int;
    TransferCmd |= (DevAddr as u32_0) << 8 as libc::c_int;
    TransferCmd |=
        (((*Cmd).ByteCount as libc::c_int & 0xfff as libc::c_int) as u32_0) << 16 as libc::c_int;
    TransferCmd |= (((*Cmd).Tid as libc::c_int & 0xf as libc::c_int) as u32_0) << 28 as libc::c_int;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x20 as libc::c_int as u32_0 as libc::c_ulong),
        TransferCmd,
    );
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_WriteTxFifo(mut InstancePtr: *mut XI3c) {
    let mut Data: u32_0 = 0 as libc::c_int as u32_0;
    let mut Index: u16_0 = 0;
    if (*InstancePtr).SendByteCount as libc::c_int > 3 as libc::c_int {
        Data = ((*((*InstancePtr).SendBufferPtr).offset(0 as libc::c_int as isize) as libc::c_int)
            << 24 as libc::c_int
            | (*((*InstancePtr).SendBufferPtr).offset(1 as libc::c_int as isize) as libc::c_int)
                << 16 as libc::c_int
            | (*((*InstancePtr).SendBufferPtr).offset(2 as libc::c_int as isize) as libc::c_int)
                << 8 as libc::c_int
            | (*((*InstancePtr).SendBufferPtr).offset(3 as libc::c_int as isize) as libc::c_int)
                << 0 as libc::c_int) as u32_0;
        (*InstancePtr).SendByteCount =
            ((*InstancePtr).SendByteCount as libc::c_int - 4 as libc::c_int) as u16_0;
        (*InstancePtr).SendBufferPtr =
            ((*InstancePtr).SendBufferPtr).offset(4 as libc::c_int as isize);
    } else {
        Index = 0 as libc::c_int as u16_0;
        while (Index as libc::c_int) < (*InstancePtr).SendByteCount as libc::c_int {
            Data |= ((*((*InstancePtr).SendBufferPtr).offset(Index as libc::c_int as isize)
                as libc::c_int)
                << 24 as libc::c_int - 8 as libc::c_int * Index as libc::c_int)
                as u32_0;
            Index = Index.wrapping_add(1);
            Index;
        }
        (*InstancePtr).SendByteCount = 0 as libc::c_int as u16_0;
    }
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x24 as libc::c_int as u32_0 as libc::c_ulong),
        Data,
    );
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_ReadRxFifo(mut InstancePtr: *mut XI3c) {
    let mut Data: u32_0 = 0 as libc::c_int as u32_0;
    let mut Index: u16_0 = 0;
    Data = Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x28 as libc::c_int as u32_0 as libc::c_ulong),
    );
    if (*InstancePtr).RecvByteCount as libc::c_int > 3 as libc::c_int {
        *((*InstancePtr).RecvBufferPtr).offset(0 as libc::c_int as isize) =
            (Data >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u8_0;
        *((*InstancePtr).RecvBufferPtr).offset(1 as libc::c_int as isize) =
            (Data >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u8_0;
        *((*InstancePtr).RecvBufferPtr).offset(2 as libc::c_int as isize) =
            (Data >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u8_0;
        *((*InstancePtr).RecvBufferPtr).offset(3 as libc::c_int as isize) =
            (Data >> 0 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u8_0;
        (*InstancePtr).RecvByteCount =
            ((*InstancePtr).RecvByteCount as libc::c_int - 4 as libc::c_int) as u16_0;
        (*InstancePtr).RecvBufferPtr =
            ((*InstancePtr).RecvBufferPtr).offset(4 as libc::c_int as isize);
    } else {
        Index = 0 as libc::c_int as u16_0;
        while (Index as libc::c_int) < (*InstancePtr).RecvByteCount as libc::c_int {
            *((*InstancePtr).RecvBufferPtr).offset(Index as libc::c_int as isize) =
                (Data >> 24 as libc::c_int - 8 as libc::c_int * Index as libc::c_int
                    & 0xff as libc::c_int as libc::c_uint) as u8_0;
            Index = Index.wrapping_add(1);
            Index;
        }
        (*InstancePtr).RecvByteCount = 0 as libc::c_int as u16_0;
    };
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_DynaAddrAssign(
    mut InstancePtr: *mut XI3c,
    mut DynaAddr: *mut u8_0,
    mut DevCount: u8_0,
) -> s32 {
    let mut RecvBuffer: [u8_0; 8] = [0; 8];
    let mut Cmd: XI3c_Cmd = XI3c_Cmd {
        CmdType: 0,
        NoRepeatedStart: 0,
        Pec: 0,
        SlaveAddr: 0,
        Rw: 0,
        ByteCount: 0,
        Tid: 0,
    };
    let mut Index: u16_0 = 0;
    let mut Addr: u8_0 = 0;
    let mut Status: s32 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.c\0" as *const u8 as *const libc::c_char,
            335 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.c\0" as *const u8 as *const libc::c_char,
            336 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    Cmd.NoRepeatedStart = 0 as libc::c_int as u8_0;
    Cmd.SlaveAddr = 0x7e as libc::c_int as u8_0;
    Cmd.Tid = 0 as libc::c_int as u8_0;
    Cmd.Pec = 0 as libc::c_int as u8_0;
    Cmd.CmdType = 1 as libc::c_int as u8_0;
    Status = XI3c_SendTransferCmd(InstancePtr, &mut Cmd, 0x7 as libc::c_int as u8_0);
    if Status as libc::c_long != 0 as libc::c_long {
        return Status;
    }
    Index = 0 as libc::c_int as u16_0;
    while (Index as libc::c_int) < DevCount as libc::c_int
        && (Index as libc::c_int) < 108 as libc::c_int
    {
        Addr = ((*DynaAddr.offset(Index as isize) as libc::c_int) << 1 as libc::c_int
            | XI3c_GetOddParity(*DynaAddr.offset(Index as isize)) as libc::c_int)
            as u8_0;
        (*InstancePtr).SendBufferPtr = &mut Addr;
        (*InstancePtr).SendByteCount = 1 as libc::c_int as u16_0;
        XI3c_WriteTxFifo(InstancePtr);
        if Index as libc::c_int + 1 as libc::c_int == DevCount as libc::c_int {
            Cmd.NoRepeatedStart = 1 as libc::c_int as u8_0;
        } else {
            Cmd.NoRepeatedStart = 0 as libc::c_int as u8_0;
        }
        Cmd.SlaveAddr = 0x7e as libc::c_int as u8_0;
        Cmd.Tid = 0 as libc::c_int as u8_0;
        Cmd.Pec = 0 as libc::c_int as u8_0;
        Cmd.CmdType = 1 as libc::c_int as u8_0;
        Status = XI3c_MasterRecvPolled(
            InstancePtr,
            &mut Cmd,
            RecvBuffer.as_mut_ptr(),
            9 as libc::c_int as u16_0,
        );
        if Status as libc::c_long != 0 as libc::c_long {
            return Status;
        }
        (*InstancePtr).XI3c_SlaveInfoTable[(*InstancePtr).CurDeviceCount as usize].Id =
            (RecvBuffer[0 as libc::c_int as usize] as u64_0) << 40 as libc::c_int
                | (RecvBuffer[1 as libc::c_int as usize] as u64_0) << 32 as libc::c_int
                | (RecvBuffer[2 as libc::c_int as usize] as u64_0) << 24 as libc::c_int
                | (RecvBuffer[3 as libc::c_int as usize] as u64_0) << 16 as libc::c_int
                | (RecvBuffer[4 as libc::c_int as usize] as u64_0) << 8 as libc::c_int
                | RecvBuffer[5 as libc::c_int as usize] as u64_0;
        (*InstancePtr).XI3c_SlaveInfoTable[(*InstancePtr).CurDeviceCount as usize].Bcr =
            RecvBuffer[6 as libc::c_int as usize];
        (*InstancePtr).XI3c_SlaveInfoTable[(*InstancePtr).CurDeviceCount as usize].Dcr =
            RecvBuffer[7 as libc::c_int as usize];
        (*InstancePtr).XI3c_SlaveInfoTable[(*InstancePtr).CurDeviceCount as usize].DynaAddr =
            *DynaAddr.offset(Index as isize);
        (*InstancePtr).CurDeviceCount = ((*InstancePtr).CurDeviceCount).wrapping_add(1);
        (*InstancePtr).CurDeviceCount;
        Index = Index.wrapping_add(1);
        Index;
    }
    return 0 as libc::c_long as s32;
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_ConfigIbi(mut InstancePtr: *mut XI3c, mut DevCount: u8_0) {
    let mut Index: u16_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.c\0" as *const u8 as *const libc::c_char,
            411 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.c\0" as *const u8 as *const libc::c_char,
            412 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    Index = 0 as libc::c_int as u16_0;
    while (Index as libc::c_int) < DevCount as libc::c_int
        && (Index as libc::c_int) < 108 as libc::c_int
    {
        XI3c_UpdateAddrBcr(InstancePtr, Index);
        Index = Index.wrapping_add(1);
        Index;
    }
}
#[inline]
unsafe extern "C" fn XI3c_Enable(mut InstancePtr: *mut XI3c, mut Enable: u8_0) {
    let mut Data: u32_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            666 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            667 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    Data = Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x8 as libc::c_int as u32_0 as libc::c_ulong),
    );
    Data &= !(0x1 as libc::c_int) as libc::c_uint;
    Data |= Enable as libc::c_uint;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x8 as libc::c_int as u32_0 as libc::c_ulong),
        Data,
    );
}
#[inline]
unsafe extern "C" fn XI3c_EnableIbi(mut InstancePtr: *mut XI3c) {
    let mut Data: u32_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            747 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            748 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    Data = Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x8 as libc::c_int as u32_0 as libc::c_ulong),
    );
    Data |= 0x8 as libc::c_int as libc::c_uint;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x8 as libc::c_int as u32_0 as libc::c_ulong),
        Data,
    );
}
#[inline]
unsafe extern "C" fn XI3c_EnableHotjoin(mut InstancePtr: *mut XI3c) {
    let mut Data: u32_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            772 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            773 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    Data = Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x8 as libc::c_int as u32_0 as libc::c_ulong),
    );
    Data |= 0x10 as libc::c_int as libc::c_uint;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x8 as libc::c_int as u32_0 as libc::c_ulong),
        Data,
    );
}
#[inline]
unsafe extern "C" fn XI3c_UpdateAddrBcr(mut InstancePtr: *mut XI3c, mut DevIndex: u16_0) {
    let mut AddrBcr: u32_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            799 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            800 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    AddrBcr = ((*InstancePtr).XI3c_SlaveInfoTable[DevIndex as usize].DynaAddr as libc::c_int
        & 0x7f as libc::c_int) as u32_0;
    AddrBcr |= (((*InstancePtr).XI3c_SlaveInfoTable[DevIndex as usize].Bcr as libc::c_int
        & 0xff as libc::c_int) as u32_0)
        << 8 as libc::c_int;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x60 as libc::c_int as u32_0 as libc::c_ulong),
        AddrBcr,
    );
}
#[inline]
unsafe extern "C" fn XI3c_Reset(mut InstancePtr: *mut XI3c) {
    let mut Data: u32_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            831 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            832 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    Data = Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x4 as libc::c_int as u32_0 as libc::c_ulong),
    );
    Data |= 0x1 as libc::c_int as libc::c_uint;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x4 as libc::c_int as u32_0 as libc::c_ulong),
        Data,
    );
    usleep(50 as libc::c_int as ULONG);
    Data &= !(0x1 as libc::c_int) as libc::c_uint;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x4 as libc::c_int as u32_0 as libc::c_ulong),
        Data,
    );
    usleep(10 as libc::c_int as ULONG);
}
#[inline]
unsafe extern "C" fn XI3c_ResetFifos(mut InstancePtr: *mut XI3c) {
    let mut Data: u32_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            861 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c.h\0" as *const u8 as *const libc::c_char,
            862 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    Data = Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x4 as libc::c_int as u32_0 as libc::c_ulong),
    );
    Data |= 0x1e as libc::c_int as libc::c_uint;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x4 as libc::c_int as u32_0 as libc::c_ulong),
        Data,
    );
    usleep(50 as libc::c_int as ULONG);
    Data &= !(0x1e as libc::c_int) as libc::c_uint;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x4 as libc::c_int as u32_0 as libc::c_ulong),
        Data,
    );
    usleep(10 as libc::c_int as ULONG);
}
#[inline]
unsafe extern "C" fn XI3c_GetOddParity(mut Addr: u8_0) -> u8_0 {
    Addr = (Addr as libc::c_int & 0xf as libc::c_int
        ^ Addr as libc::c_int >> 4 as libc::c_int & 0xf as libc::c_int) as u8_0;
    Addr = (Addr as libc::c_int & 0x3 as libc::c_int
        ^ Addr as libc::c_int >> 2 as libc::c_int & 0x3 as libc::c_int) as u8_0;
    Addr = (Addr as libc::c_int & 0x1 as libc::c_int
        ^ Addr as libc::c_int >> 1 as libc::c_int & 0x1 as libc::c_int) as u8_0;
    return (Addr as libc::c_int & 1 as libc::c_int == 0) as libc::c_int as u8_0;
}
