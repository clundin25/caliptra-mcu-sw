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
    fn Xil_WaitForEvent(RegAddr: UINTPTR, EventMask: u32_0, Event: u32_0, Timeout: u32_0) -> u32_0;
    static mut XI3C_DynaAddrList: [u8_0; 0];
    fn XI3c_FillCmdFifo(InstancePtr: *mut XI3c, Cmd: *mut XI3c_Cmd);
    fn XI3c_WriteTxFifo(InstancePtr: *mut XI3c);
    fn XI3c_ReadRxFifo(InstancePtr: *mut XI3c);
    fn XI3c_DynaAddrAssign(InstancePtr: *mut XI3c, DynaAddr: *mut u8_0, DevCount: u8_0) -> s32;
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
unsafe extern "C" fn XI3c_GetResponse(mut InstancePtr: *mut XI3c) -> s32 {
    let mut Status: s32 = 0;
    let mut ResponseData: u32_0 = 0;
    Status = Xil_WaitForEvent(
        ((*InstancePtr).Config.BaseAddress).wrapping_add(0x10 as libc::c_int as libc::c_ulong),
        0x10 as libc::c_int as u32_0,
        0x10 as libc::c_int as u32_0,
        2000000 as libc::c_uint,
    ) as libc::c_int;
    if Status as libc::c_long != 0 as libc::c_long {
        return 31 as libc::c_long as s32;
    }
    ResponseData = Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x2c as libc::c_int as u32_0 as libc::c_ulong),
    );
    return ((ResponseData & 0x1e0 as libc::c_int as libc::c_uint) >> 5 as libc::c_int) as s32;
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_SendTransferCmd(
    mut InstancePtr: *mut XI3c,
    mut Cmd: *mut XI3c_Cmd,
    mut Data: u8_0,
) -> s32 {
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            90 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if !Cmd.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            91 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            92 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    (*InstancePtr).SendBufferPtr = &mut Data;
    (*InstancePtr).SendByteCount = 1 as libc::c_int as u16_0;
    XI3c_WriteTxFifo(InstancePtr);
    (*Cmd).SlaveAddr = 0x7e as libc::c_int as u8_0;
    (*Cmd).Rw = 0 as libc::c_int as u8_0;
    (*Cmd).ByteCount = 1 as libc::c_int as u16_0;
    XI3c_FillCmdFifo(InstancePtr, Cmd);
    if XI3c_GetResponse(InstancePtr) != 0 {
        return 28 as libc::c_long as s32;
    }
    return 0 as libc::c_long as s32;
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_MasterSend(
    mut InstancePtr: *mut XI3c,
    mut Cmd: *mut XI3c_Cmd,
    mut MsgPtr: *mut u8_0,
    mut ByteCount: u16_0,
) -> s32 {
    let mut WrFifoSpace: u16_0 = 0;
    let mut SpaceIndex: u16_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            139 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if !Cmd.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            140 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if MsgPtr.is_null() {
        return 13 as libc::c_long as s32;
    }
    if ByteCount as libc::c_int > 4095 as libc::c_int {
        return 28 as libc::c_long as s32;
    }
    (*InstancePtr).SendBufferPtr = MsgPtr;
    (*InstancePtr).SendByteCount = ByteCount;
    (*Cmd).ByteCount = ByteCount;
    (*Cmd).Rw = 0 as libc::c_int as u8_0;
    WrFifoSpace = (Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x30 as libc::c_int as u32_0 as libc::c_ulong),
    ) & 0xffff as libc::c_int as libc::c_uint) as u16_0;
    SpaceIndex = 0 as libc::c_int as u16_0;
    while (SpaceIndex as libc::c_int) < WrFifoSpace as libc::c_int
        && (*InstancePtr).SendByteCount as libc::c_int > 0 as libc::c_int
    {
        XI3c_WriteTxFifo(InstancePtr);
        SpaceIndex = SpaceIndex.wrapping_add(1);
        SpaceIndex;
    }
    if ((*InstancePtr).Config.WrThreshold as libc::c_int) < ByteCount as libc::c_int {
        Xil_Out32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x1c as libc::c_int as u32_0 as libc::c_ulong),
            Xil_In32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x1c as libc::c_int as u32_0 as libc::c_ulong),
            ) | 0x20 as libc::c_int as libc::c_uint,
        );
    }
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
        Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
        ) | 0x10 as libc::c_int as libc::c_uint,
    );
    XI3c_FillCmdFifo(InstancePtr, Cmd);
    return 0 as libc::c_long as s32;
}
#[inline]
unsafe extern "C" fn Xil_In32(mut Addr: UINTPTR) -> u32_0 {
    return *(Addr as *mut u32_0);
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_MasterRecv(
    mut InstancePtr: *mut XI3c,
    mut Cmd: *mut XI3c_Cmd,
    mut MsgPtr: *mut u8_0,
    mut ByteCount: u16_0,
) -> s32 {
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            204 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if !Cmd.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            205 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if MsgPtr.is_null() {
        return 13 as libc::c_long as s32;
    }
    if ByteCount as libc::c_int > 4095 as libc::c_int {
        return 27 as libc::c_long as s32;
    }
    (*InstancePtr).RecvBufferPtr = MsgPtr;
    (*InstancePtr).RecvByteCount = ByteCount;
    (*Cmd).ByteCount = ByteCount;
    (*Cmd).Rw = 1 as libc::c_int as u8_0;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
        Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
        ) | (0x40 as libc::c_int | 0x10 as libc::c_int) as libc::c_uint,
    );
    XI3c_FillCmdFifo(InstancePtr, Cmd);
    return 0 as libc::c_long as s32;
}
#[inline]
unsafe extern "C" fn Xil_Out32(mut Addr: UINTPTR, mut Value: u32_0) {
    let mut LocalAddr: *mut u32_0 = Addr as *mut u32_0;
    ::core::ptr::write_volatile(LocalAddr, Value);
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_MasterSendPolled(
    mut InstancePtr: *mut XI3c,
    mut Cmd: *mut XI3c_Cmd,
    mut MsgPtr: *mut u8_0,
    mut ByteCount: u16_0,
) -> s32 {
    let mut WrFifoSpace: u16_0 = 0;
    let mut SpaceIndex: u16_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            262 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if !Cmd.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            263 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if MsgPtr.is_null() {
        return 13 as libc::c_long as s32;
    }
    if ByteCount as libc::c_int > 4095 as libc::c_int {
        return 28 as libc::c_long as s32;
    }
    (*InstancePtr).SendBufferPtr = MsgPtr;
    (*InstancePtr).SendByteCount = ByteCount;
    (*Cmd).ByteCount = ByteCount;
    (*Cmd).Rw = 0 as libc::c_int as u8_0;
    XI3c_FillCmdFifo(InstancePtr, Cmd);
    while (*InstancePtr).SendByteCount as libc::c_int > 0 as libc::c_int {
        WrFifoSpace = (Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x30 as libc::c_int as u32_0 as libc::c_ulong),
        ) & 0xffff as libc::c_int as libc::c_uint) as u16_0;
        SpaceIndex = 0 as libc::c_int as u16_0;
        while (SpaceIndex as libc::c_int) < WrFifoSpace as libc::c_int
            && (*InstancePtr).SendByteCount as libc::c_int > 0 as libc::c_int
        {
            XI3c_WriteTxFifo(InstancePtr);
            SpaceIndex = SpaceIndex.wrapping_add(1);
            SpaceIndex;
        }
    }
    if XI3c_GetResponse(InstancePtr) != 0 {
        return 28 as libc::c_long as s32;
    } else {
        return 0 as libc::c_long as s32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_MasterRecvPolled(
    mut InstancePtr: *mut XI3c,
    mut Cmd: *mut XI3c_Cmd,
    mut MsgPtr: *mut u8_0,
    mut ByteCount: u16_0,
) -> s32 {
    let mut DataIndex: u16_0 = 0;
    let mut RxDataAvailable: u16_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            327 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if !Cmd.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            328 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if MsgPtr.is_null() {
        return 13 as libc::c_long as s32;
    }
    if ByteCount as libc::c_int > 4095 as libc::c_int {
        return 27 as libc::c_long as s32;
    }
    (*InstancePtr).RecvBufferPtr = MsgPtr;
    if (*Cmd).SlaveAddr as libc::c_int == 0x7e as libc::c_int {
        (*InstancePtr).RecvByteCount = (ByteCount as libc::c_int - 1 as libc::c_int) as u16_0;
    } else {
        (*InstancePtr).RecvByteCount = ByteCount;
    }
    (*Cmd).ByteCount = ByteCount;
    (*Cmd).Rw = 1 as libc::c_int as u8_0;
    XI3c_FillCmdFifo(InstancePtr, Cmd);
    while (*InstancePtr).RecvByteCount as libc::c_int > 0 as libc::c_int {
        RxDataAvailable = (Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x34 as libc::c_int as u32_0 as libc::c_ulong),
        ) & 0xffff as libc::c_int as libc::c_uint) as u16_0;
        DataIndex = 0 as libc::c_int as u16_0;
        while (DataIndex as libc::c_int) < RxDataAvailable as libc::c_int
            && (*InstancePtr).RecvByteCount as libc::c_int > 0 as libc::c_int
        {
            XI3c_ReadRxFifo(InstancePtr);
            DataIndex = DataIndex.wrapping_add(1);
            DataIndex;
        }
    }
    if XI3c_GetResponse(InstancePtr) != 0 {
        return 27 as libc::c_long as s32;
    } else {
        return 0 as libc::c_long as s32;
    };
}
unsafe extern "C" fn XI3c_IbiReadRxFifo(mut InstancePtr: *mut XI3c) {
    let mut DataIndex: u16_0 = 0;
    let mut RxDataAvailable: u16_0 = 0;
    RxDataAvailable = (Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x34 as libc::c_int as u32_0 as libc::c_ulong),
    ) & 0xffff as libc::c_int as libc::c_uint) as u16_0;
    DataIndex = 0 as libc::c_int as u16_0;
    while (DataIndex as libc::c_int) < RxDataAvailable as libc::c_int {
        (*InstancePtr).RecvByteCount = 4 as libc::c_int as u16_0;
        XI3c_ReadRxFifo(InstancePtr);
        DataIndex = DataIndex.wrapping_add(1);
        DataIndex;
    }
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_SetStatusHandler(
    mut InstancePtr: *mut XI3c,
    mut FunctionPtr: XI3c_IntrHandler,
) {
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            415 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    if FunctionPtr.is_some() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            416 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    if (*InstancePtr).IsReady == 0x11111111 as libc::c_uint {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            417 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    (*InstancePtr).StatusHandler = FunctionPtr;
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_MasterInterruptHandler(mut InstancePtr: *mut XI3c) {
    let mut IntrStatusReg: u32_0 = 0;
    let mut WrFifoSpace: u16_0 = 0;
    let mut SpaceIndex: u16_0 = 0;
    let mut DataIndex: u16_0 = 0;
    let mut RxDataAvailable: u16_0 = 0;
    let mut ResponseData: u32_0 = 0;
    let mut DynaAddr: [u8_0; 1] = [0; 1];
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            453 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return;
    }
    IntrStatusReg = Xil_In32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x14 as libc::c_int as u32_0 as libc::c_ulong),
    );
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x14 as libc::c_int as u32_0 as libc::c_ulong),
        IntrStatusReg,
    );
    if IntrStatusReg & 0x100 as libc::c_int as libc::c_uint != 0 {
        if (*InstancePtr).CurDeviceCount as libc::c_int <= 108 as libc::c_int {
            DynaAddr[0 as libc::c_int as usize] = *XI3C_DynaAddrList
                .as_mut_ptr()
                .offset((*InstancePtr).CurDeviceCount as isize);
            XI3c_DynaAddrAssign(InstancePtr, DynaAddr.as_mut_ptr(), 1 as libc::c_int as u8_0);
            XI3c_UpdateAddrBcr(
                InstancePtr,
                ((*InstancePtr).CurDeviceCount as libc::c_int - 1 as libc::c_int) as u16_0,
            );
        }
        XI3c_ResetFifos(InstancePtr);
    }
    if IntrStatusReg & 0x80 as libc::c_int as libc::c_uint != 0 {
        while Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x10 as libc::c_int as u32_0 as libc::c_ulong),
        ) & 0x8000 as libc::c_int as libc::c_uint
            != 0
            || Xil_In32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x10 as libc::c_int as u32_0 as libc::c_ulong),
            ) & 0x10 as libc::c_int as libc::c_uint
                == 0
        {
            XI3c_IbiReadRxFifo(InstancePtr);
        }
        Xil_Out32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
            Xil_In32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
            ) & !(0x80 as libc::c_int) as libc::c_uint,
        );
    }
    if IntrStatusReg & 0x20 as libc::c_int as libc::c_uint != 0 {
        WrFifoSpace = (Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x30 as libc::c_int as u32_0 as libc::c_ulong),
        ) & 0xffff as libc::c_int as libc::c_uint) as u16_0;
        SpaceIndex = 0 as libc::c_int as u16_0;
        while (SpaceIndex as libc::c_int) < WrFifoSpace as libc::c_int
            && (*InstancePtr).SendByteCount as libc::c_int > 0 as libc::c_int
        {
            XI3c_WriteTxFifo(InstancePtr);
            SpaceIndex = SpaceIndex.wrapping_add(1);
            SpaceIndex;
        }
        if (*InstancePtr).SendByteCount as libc::c_int <= 0 as libc::c_int {
            Xil_Out32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x1c as libc::c_int as u32_0 as libc::c_ulong),
                Xil_In32(
                    ((*InstancePtr).Config.BaseAddress)
                        .wrapping_add(0x1c as libc::c_int as u32_0 as libc::c_ulong),
                ) & !(0x20 as libc::c_int) as libc::c_uint,
            );
        }
    }
    if IntrStatusReg & 0x40 as libc::c_int as libc::c_uint != 0 {
        RxDataAvailable = (Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x34 as libc::c_int as u32_0 as libc::c_ulong),
        ) & 0xffff as libc::c_int as libc::c_uint) as u16_0;
        DataIndex = 0 as libc::c_int as u16_0;
        while (DataIndex as libc::c_int) < RxDataAvailable as libc::c_int
            && (*InstancePtr).RecvByteCount as libc::c_int > 0 as libc::c_int
        {
            XI3c_ReadRxFifo(InstancePtr);
            DataIndex = DataIndex.wrapping_add(1);
            DataIndex;
        }
        if (*InstancePtr).RecvByteCount as libc::c_int <= 0 as libc::c_int {
            Xil_Out32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
                Xil_In32(
                    ((*InstancePtr).Config.BaseAddress)
                        .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
                ) & !(0x40 as libc::c_int) as libc::c_uint,
            );
        }
    }
    if IntrStatusReg & 0x10 as libc::c_int as libc::c_uint != 0 {
        if (*InstancePtr).RecvByteCount as libc::c_int > 0 as libc::c_int {
            RxDataAvailable = (Xil_In32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x34 as libc::c_int as u32_0 as libc::c_ulong),
            ) & 0xffff as libc::c_int as libc::c_uint) as u16_0;
            DataIndex = 0 as libc::c_int as u16_0;
            while (DataIndex as libc::c_int) < RxDataAvailable as libc::c_int
                && (*InstancePtr).RecvByteCount as libc::c_int > 0 as libc::c_int
            {
                XI3c_ReadRxFifo(InstancePtr);
                DataIndex = DataIndex.wrapping_add(1);
                DataIndex;
            }
        }
        if (*InstancePtr).Config.IbiCapable != 0 {
            XI3c_IbiReadRxFifo(InstancePtr);
        }
        ResponseData = Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x2c as libc::c_int as u32_0 as libc::c_ulong),
        );
        (*InstancePtr).Error =
            ((ResponseData & 0x1e0 as libc::c_int as libc::c_uint) >> 5 as libc::c_int) as u8_0;
        Xil_Out32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
            Xil_In32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
            ) & !(0x10 as libc::c_int | 0x40 as libc::c_int) as libc::c_uint,
        );
        Xil_Out32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x1c as libc::c_int as u32_0 as libc::c_ulong),
            Xil_In32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x1c as libc::c_int as u32_0 as libc::c_ulong),
            ) & !(0x20 as libc::c_int) as libc::c_uint,
        );
        ((*InstancePtr).StatusHandler).expect("non-null function pointer")(
            (*InstancePtr).Error as u32_0,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_IbiRecv(mut InstancePtr: *mut XI3c, mut MsgPtr: *mut u8_0) -> s32 {
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            570 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if !MsgPtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            571 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if MsgPtr.is_null() {
        return 13 as libc::c_long as s32;
    }
    (*InstancePtr).RecvBufferPtr = MsgPtr;
    Xil_Out32(
        ((*InstancePtr).Config.BaseAddress)
            .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
        Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x18 as libc::c_int as u32_0 as libc::c_ulong),
        ) | (0x80 as libc::c_int | 0x10 as libc::c_int) as libc::c_uint,
    );
    return 0 as libc::c_long as s32;
}
#[no_mangle]
pub unsafe extern "C" fn XI3c_IbiRecvPolled(
    mut InstancePtr: *mut XI3c,
    mut MsgPtr: *mut u8_0,
) -> s32 {
    let mut Status: s32 = 0;
    let mut DataIndex: u16_0 = 0;
    let mut RxDataAvailable: u16_0 = 0;
    if !InstancePtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            616 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if !MsgPtr.is_null() {
        Xil_AssertStatus = 0 as libc::c_uint;
    } else {
        Xil_Assert(
            b"xi3c_master.c\0" as *const u8 as *const libc::c_char,
            617 as libc::c_int,
        );
        Xil_AssertStatus = 1 as libc::c_uint;
        return 0 as libc::c_int;
    }
    if MsgPtr.is_null() {
        return 13 as libc::c_long as s32;
    }
    (*InstancePtr).RecvBufferPtr = MsgPtr;
    Status = Xil_WaitForEvent(
        ((*InstancePtr).Config.BaseAddress).wrapping_add(0x10 as libc::c_int as libc::c_ulong),
        0x8000 as libc::c_int as u32_0,
        0x8000 as libc::c_int as u32_0,
        (2000000 as libc::c_uint).wrapping_mul(10 as libc::c_int as libc::c_uint),
    ) as libc::c_int;
    if !(Status as libc::c_long != 0 as libc::c_long) {
        while Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x10 as libc::c_int as u32_0 as libc::c_ulong),
        ) & 0x8000 as libc::c_int as libc::c_uint
            != 0
            || Xil_In32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x10 as libc::c_int as u32_0 as libc::c_ulong),
            ) & 0x10 as libc::c_int as libc::c_uint
                == 0
        {
            RxDataAvailable = (Xil_In32(
                ((*InstancePtr).Config.BaseAddress)
                    .wrapping_add(0x34 as libc::c_int as u32_0 as libc::c_ulong),
            ) & 0xffff as libc::c_int as libc::c_uint) as u16_0;
            DataIndex = 0 as libc::c_int as u16_0;
            while (DataIndex as libc::c_int) < RxDataAvailable as libc::c_int {
                (*InstancePtr).RecvByteCount = 4 as libc::c_int as u16_0;
                XI3c_ReadRxFifo(InstancePtr);
                DataIndex = DataIndex.wrapping_add(1);
                DataIndex;
            }
        }
        RxDataAvailable = (Xil_In32(
            ((*InstancePtr).Config.BaseAddress)
                .wrapping_add(0x34 as libc::c_int as u32_0 as libc::c_ulong),
        ) & 0xffff as libc::c_int as libc::c_uint) as u16_0;
        DataIndex = 0 as libc::c_int as u16_0;
        while (DataIndex as libc::c_int) < RxDataAvailable as libc::c_int {
            (*InstancePtr).RecvByteCount = 4 as libc::c_int as u16_0;
            XI3c_ReadRxFifo(InstancePtr);
            DataIndex = DataIndex.wrapping_add(1);
            DataIndex;
        }
    }
    if XI3c_GetResponse(InstancePtr) != 0 {
        return 27 as libc::c_long as s32;
    } else {
        return 0 as libc::c_long as s32;
    };
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
