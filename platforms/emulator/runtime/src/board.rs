// Licensed under the Apache-2.0 license

use crate::components as runtime_components;
use crate::interrupts::EmulatorPeripherals;
use crate::MCU_MEMORY_MAP;
use arrayvec::ArrayVec;
use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_core::virtualizers::virtual_flash;
use capsules_runtime::doe::driver::DoeDriver;
use capsules_runtime::mctp::base_protocol::MessageType;
use core::ptr::{addr_of, addr_of_mut};
use doe_mbox_driver::EmulatedDoeTransport;
use kernel::capabilities;
use kernel::component::Component;
use kernel::errorcode;
use kernel::hil;
use kernel::hil::time::Alarm;
use kernel::platform::scheduler_timer::VirtualSchedulerTimer;
use kernel::platform::SyscallFilter;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::process;
use kernel::scheduler::cooperative::CooperativeSched;
use kernel::syscall;
use kernel::utilities::registers::interfaces::ReadWriteable;
use kernel::{create_capability, debug, static_init};
use mcu_components::mctp_mux_component_static;
use mcu_components::{
    doe_component_static, mailbox_component_static, mctp_driver_component_static,
};
use mcu_platforms_common::pmp_config::{PlatformPMPConfig, PlatformRegion};
use mcu_tock_veer::chip::{VeeRDefaultPeripherals, TIMERS};
use mcu_tock_veer::pic::Pic;
use mcu_tock_veer::pmp::VeeRProtectionMMLEPMP;
use mcu_tock_veer::timers::InternalTimers;
use registers_generated::mci;
use romtime::CaliptraSoC;
use romtime::StaticRef;
use rv32i::csr;

use crate::instantiate_flash_partitions;
use mcu_config_emulator::{flash_partition_list_primary, flash_partition_list_secondary};

// These symbols are defined in the linker script.
extern "C" {
    /// Beginning of the ROM region containing app images.
    static _sapps: u8;
    /// End of the ROM region containing app images.
    static _eapps: u8;
    /// Beginning of the RAM region for app memory.
    static mut _sappmem: u8;
    /// End of the RAM region for app memory.
    static _eappmem: u8;
    /// The start of the kernel text (Included only for kernel PMP)
    static _stext: u8;
    /// The end of the kernel text (Included only for kernel PMP)
    static _etext: u8;
    /// The start of the kernel / app / storage flash (Included only for kernel PMP)
    static _srom: u8;
    /// The end of the kernel / app / storage flash (Included only for kernel PMP)
    static _eprog: u8;
    /// The start of the kernel / app RAM (Included only for kernel PMP)
    static _ssram: u8;
    /// The end of the kernel / app RAM (Included only for kernel PMP)
    static _esram: u8;

    static _sstorage: u8;
    static _estorage: u8;

    pub(crate) static _pic_vector_table: u8;
}

pub const NUM_PROCS: usize = 4;

// Actual memory for holding the active process structures. Need an empty list
// at least.
pub static mut PROCESSES: [Option<&'static dyn kernel::process::Process>; NUM_PROCS] =
    [None; NUM_PROCS];

pub type VeeRChip = mcu_tock_veer::chip::VeeR<'static, VeeRDefaultPeripherals<'static>>;

// Reference to the chip and peripherals for panic dumps and tests.
pub static mut CHIP: Option<&'static VeeRChip> = None;
pub static mut EMULATOR_PERIPHERALS: Option<&'static EmulatorPeripherals> = None;
// Static reference to process printer for panic dumps.
pub static mut PROCESS_PRINTER: Option<
    &'static capsules_system::process_printer::ProcessPrinterText,
> = None;

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase"
))]
static mut BOARD: Option<&'static kernel::Kernel> = None;

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase"
))]
static mut PLATFORM: Option<&'static VeeR> = None;

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase"
))]
static mut MAIN_CAP: Option<&dyn kernel::capabilities::MainLoopCapability> = None;

// How should the kernel respond when a process faults.
const FAULT_RESPONSE: capsules_system::process_policies::PanicFaultPolicy =
    capsules_system::process_policies::PanicFaultPolicy {};

/// Dummy buffer that causes the linker to reserve enough space for the stack.
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x2000] = [0; 0x2000];

#[no_mangle]
pub static mut PIC: Pic = Pic::new(MCU_MEMORY_MAP.pic_offset);

// XS: Allocate 128K for logging test
#[no_mangle]
pub static mut LOG_STORAGE: Option<&'static [u8]> = None;

/// A structure representing this platform that holds references to all
/// capsules for this platform.
struct VeeR {
    alarm: &'static capsules_core::alarm::AlarmDriver<
        'static,
        VirtualMuxAlarm<'static, InternalTimers<'static>>,
    >,
    console: &'static capsules_core::console::Console<'static>,
    lldb: &'static capsules_core::low_level_debug::LowLevelDebug<
        'static,
        capsules_core::virtualizers::virtual_uart::UartDevice<'static>,
    >,
    scheduler: &'static CooperativeSched<'static>,
    scheduler_timer:
        &'static VirtualSchedulerTimer<VirtualMuxAlarm<'static, InternalTimers<'static>>>,
    mctp_spdm: &'static capsules_runtime::mctp::driver::MCTPDriver<'static>,
    mctp_secure_spdm: &'static capsules_runtime::mctp::driver::MCTPDriver<'static>,
    mctp_pldm: &'static capsules_runtime::mctp::driver::MCTPDriver<'static>,
    mctp_caliptra: &'static capsules_runtime::mctp::driver::MCTPDriver<'static>,
    doe_spdm: &'static capsules_runtime::doe::driver::DoeDriver<
        'static,
        EmulatedDoeTransport<'static, InternalTimers<'static>>,
    >,
    flash_partitions: [Option<&'static capsules_runtime::flash_partition::FlashPartition<'static>>;
        mcu_config_emulator::flash::FLASH_PARTITIONS_COUNT],
    mailbox: &'static capsules_runtime::mailbox::Mailbox<
        'static,
        VirtualMuxAlarm<'static, InternalTimers<'static>>,
    >,
    dma: &'static capsules_emulator::dma::Dma<'static>,
}

/// Mapping of integer syscalls to objects that implement syscalls.
impl SyscallDriverLookup for VeeR {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::syscall::SyscallDriver>) -> R,
    {
        match driver_num {
            capsules_core::alarm::DRIVER_NUM => f(Some(self.alarm)),
            capsules_core::console::DRIVER_NUM => f(Some(self.console)),
            capsules_core::low_level_debug::DRIVER_NUM => f(Some(self.lldb)),
            capsules_runtime::mctp::driver::MCTP_SPDM_DRIVER_NUM => f(Some(self.mctp_spdm)),
            capsules_runtime::mctp::driver::MCTP_SECURE_SPDM_DRIVER_NUM => {
                f(Some(self.mctp_secure_spdm))
            }
            capsules_runtime::mctp::driver::MCTP_PLDM_DRIVER_NUM => f(Some(self.mctp_pldm)),
            capsules_runtime::mctp::driver::MCTP_CALIPTRA_DRIVER_NUM => f(Some(self.mctp_caliptra)),
            capsules_runtime::doe::driver::DOE_SPDM_DRIVER_NUM => f(Some(self.doe_spdm)),
            capsules_runtime::mailbox::DRIVER_NUM => f(Some(self.mailbox)),
            capsules_emulator::dma::DMA_CTRL_DRIVER_NUM => f(Some(self.dma)),
            mcu_config_emulator::flash::DRIVER_NUM_START
                ..=mcu_config_emulator::flash::DRIVER_NUM_END => {
                for index in 0..mcu_config_emulator::flash::FLASH_PARTITIONS_COUNT {
                    if let Some(partition) = self.flash_partitions[index] {
                        if partition.get_driver_num() == driver_num {
                            return f(Some(partition));
                        }
                    }
                }
                return f(None);
            }

            _ => f(None),
        }
    }
}

struct Filter {}

impl SyscallFilter for Filter {
    fn filter_syscall(
        &self,
        _process: &dyn process::Process,
        _syscall: &syscall::Syscall,
    ) -> Result<(), errorcode::ErrorCode> {
        // Uncomment this to enable syscall logging
        //romtime::println!("Syscall: {:?}", syscall);
        Ok(())
    }
}

impl KernelResources<VeeRChip> for VeeR {
    type SyscallDriverLookup = Self;
    type SyscallFilter = Filter;
    type ProcessFault = ();
    type Scheduler = CooperativeSched<'static>;
    type SchedulerTimer = VirtualSchedulerTimer<VirtualMuxAlarm<'static, InternalTimers<'static>>>;
    type WatchDog = ();
    type ContextSwitchCallback = ();

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup {
        self
    }
    fn syscall_filter(&self) -> &Self::SyscallFilter {
        &Filter {}
    }
    fn process_fault(&self) -> &Self::ProcessFault {
        &()
    }
    fn scheduler(&self) -> &Self::Scheduler {
        self.scheduler
    }
    fn scheduler_timer(&self) -> &Self::SchedulerTimer {
        self.scheduler_timer
    }
    fn watchdog(&self) -> &Self::WatchDog {
        &()
    }
    fn context_switch_callback(&self) -> &Self::ContextSwitchCallback {
        &()
    }
}

// TODO: remove this dependence on the emulator when the emulator-specific
// pieces are moved to platform/emulator/runtime
pub(crate) struct EmulatorWriter {}
pub(crate) static mut EMULATOR_WRITER: EmulatorWriter = EmulatorWriter {};

impl core::fmt::Write for EmulatorWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print_to_console(s);
        Ok(())
    }
}

pub(crate) fn print_to_console(buf: &str) {
    for b in buf.bytes() {
        // Print to this address for emulator output
        unsafe {
            core::ptr::write_volatile(0x1000_1041 as *mut u8, b);
        }
    }
}

pub(crate) struct EmulatorExiter {}
pub(crate) static mut EMULATOR_EXITER: EmulatorExiter = EmulatorExiter {};
impl romtime::Exit for EmulatorExiter {
    fn exit(&mut self, code: u32) {
        crate::io::exit_emulator(code);
    }
}

/// Main function called after RAM initialized.
///
/// # Safety
/// Accesses memory, memory-mapped registers and CSRs.
pub unsafe fn main() {
    // only machine mode
    rv32i::configure_trap_handler();

    // TODO: remove this when the emulator-specific pieces are moved to
    // platform/emulator/runtime
    #[allow(static_mut_refs)]
    romtime::set_printer(&mut EMULATOR_WRITER);
    #[allow(static_mut_refs)]
    romtime::set_exiter(&mut EMULATOR_EXITER);

    // Set up memory protection immediately after setting the trap handler, to
    // ensure that much of the board initialization routine runs with ePMP
    // protection.

    // Define platform-specific memory regions
    let mut platform_regions = ArrayVec::<PlatformRegion, 9>::new();

    // Kernel text region (read + execute)
    platform_regions.push(PlatformRegion {
        start_addr: addr_of!(_stext),
        size: addr_of!(_etext) as usize - addr_of!(_stext) as usize,
        is_mmio: false,
        user_accessible: false,
        read: true,
        write: false,
        execute: true,
    });

    // Read-only region (ROM)
    platform_regions.push(PlatformRegion {
        start_addr: addr_of!(_srom),
        size: addr_of!(_eprog) as usize - addr_of!(_srom) as usize,
        is_mmio: false,
        user_accessible: false,
        read: true,
        write: false,
        execute: false,
    });

    // Data region (SRAM)
    platform_regions.push(PlatformRegion {
        start_addr: addr_of!(_ssram),
        size: (addr_of!(_esram) as usize + 0x80) - addr_of!(_ssram) as usize,
        is_mmio: false,
        user_accessible: false,
        read: true,
        write: true,
        execute: false,
    });

    // Add DCCM region if not being used for stack
    // Check if DCCM is available and not used for stack
    if !(MCU_MEMORY_MAP.dccm_offset..MCU_MEMORY_MAP.dccm_offset + MCU_MEMORY_MAP.dccm_size)
        .contains(&(addr_of!(STACK_MEMORY) as u32))
    {
        platform_regions.push(PlatformRegion {
            start_addr: MCU_MEMORY_MAP.dccm_offset as *const u8,
            size: MCU_MEMORY_MAP.dccm_size as usize,
            is_mmio: false,
            user_accessible: false,
            read: true,
            write: true,
            execute: false,
        });
    }

    // User-accessible MMIO (emulator control and UART)
    platform_regions.push(PlatformRegion {
        start_addr: 0x1000_0000 as *const u8,
        size: 0x1000_0000,
        is_mmio: true,
        user_accessible: true,
        read: true,
        write: true,
        execute: false,
    });

    // TODO: Why is this not in the McuMemoryMap? What is this?
    platform_regions.push(PlatformRegion {
        start_addr: 0x2000_8000 as *const u8,
        size: 0x1000,
        is_mmio: true,
        user_accessible: false,
        read: true,
        write: true,
        execute: false,
    });

    // Dummy DOE mailbox peripheral region
    platform_regions.push(PlatformRegion {
        start_addr: 0x2f00_0000 as *const u8,
        size: 0x10_1000,
        is_mmio: true,
        user_accessible: false,
        read: true,
        write: true,
        execute: false,
    });

    // TODO: Why is this not in the McuMemoryMap? What is this?
    platform_regions.push(PlatformRegion {
        start_addr: 0x3000_0000 as *const u8,
        size: 0x20000,
        is_mmio: true,
        user_accessible: false,
        read: true,
        write: true,
        execute: false,
    });

    // XS: Add direct read flash region
    platform_regions.push(PlatformRegion {
        start_addr: addr_of!(_sstorage) as *const u8,
        size: (addr_of!(_estorage) as usize - addr_of!(_sstorage) as usize),
        is_mmio: true,
        user_accessible: true,
        read: true,
        write: false,
        execute: false,
    });

    // Create PMP configuration
    let config = PlatformPMPConfig {
        regions: &platform_regions,
        memory_map: &MCU_MEMORY_MAP,
    };

    // Generate PMP region list using the shared infrastructure
    let pmp_regions = mcu_platforms_common::pmp_config::create_pmp_regions(config)
        .expect("Failed to create PMP regions");

    romtime::println!("PMP Regions:");
    romtime::println!("{}", pmp_regions);
    let epmp = VeeRProtectionMMLEPMP::new(pmp_regions).unwrap();
    romtime::println!("Finished setting up PMP");

    // initialize capabilities
    let process_mgmt_cap = create_capability!(capabilities::ProcessManagementCapability);
    let memory_allocation_cap = create_capability!(capabilities::MemoryAllocationCapability);

    let main_loop_cap = create_capability!(capabilities::MainLoopCapability);
    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(&*addr_of!(PROCESSES)));

    // Configure kernel debug gpios as early as possible
    kernel::debug::assign_gpios(None, None, None);

    let timers = &*addr_of!(TIMERS);

    // Create a shared virtualization mux layer on top of a single hardware
    // alarm.
    let mux_alarm = static_init!(MuxAlarm<'static, InternalTimers>, MuxAlarm::new(timers));
    hil::time::Alarm::set_alarm_client(timers, mux_alarm);

    // Alarm
    let virtual_alarm_user = static_init!(
        VirtualMuxAlarm<'static, InternalTimers>,
        VirtualMuxAlarm::new(mux_alarm)
    );
    virtual_alarm_user.setup();

    let systick_virtual_alarm = static_init!(
        VirtualMuxAlarm<'static, InternalTimers>,
        VirtualMuxAlarm::new(mux_alarm)
    );
    systick_virtual_alarm.setup();

    let alarm = static_init!(
        capsules_core::alarm::AlarmDriver<'static, VirtualMuxAlarm<'static, InternalTimers>>,
        capsules_core::alarm::AlarmDriver::new(
            virtual_alarm_user,
            board_kernel.create_grant(capsules_core::alarm::DRIVER_NUM, &memory_allocation_cap)
        )
    );
    hil::time::Alarm::set_alarm_client(virtual_alarm_user, alarm);

    let mailbox = mcu_components::mailbox::MailboxComponent::new(
        board_kernel,
        capsules_runtime::mailbox::DRIVER_NUM,
        mux_alarm,
    )
    .finalize(mailbox_component_static!(
        InternalTimers<'static>,
        Some(MCU_MEMORY_MAP.soc_offset),
        Some(MCU_MEMORY_MAP.soc_offset),
        Some(MCU_MEMORY_MAP.mbox_offset)
    ));
    mailbox.alarm.set_alarm_client(mailbox);

    let emulator_peripherals =
        static_init!(EmulatorPeripherals, EmulatorPeripherals::new(mux_alarm),);
    emulator_peripherals.init();
    EMULATOR_PERIPHERALS = Some(emulator_peripherals);

    let peripherals = static_init!(
        VeeRDefaultPeripherals,
        VeeRDefaultPeripherals::new(emulator_peripherals, mux_alarm, &MCU_MEMORY_MAP)
    );

    let chip = static_init!(VeeRChip, mcu_tock_veer::chip::VeeR::new(peripherals, epmp));
    chip.init(addr_of!(_pic_vector_table) as u32);
    CHIP = Some(chip);

    // Create a shared UART channel for the console and for kernel debug.
    let uart_mux = components::console::UartMuxComponent::new(&emulator_peripherals.uart, 115200)
        .finalize(components::uart_mux_component_static!());

    // Create the debugger object that handles calls to `debug!()`.
    components::debug_writer::DebugWriterComponent::new(uart_mux)
        .finalize(components::debug_writer_component_static!());

    let lldb = components::lldb::LowLevelDebugComponent::new(
        board_kernel,
        capsules_core::low_level_debug::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::low_level_debug_component_static!());

    // Setup the console.
    let console = components::console::ConsoleComponent::new(
        board_kernel,
        capsules_core::console::DRIVER_NUM,
        uart_mux,
    )
    .finalize(components::console_component_static!());

    // Create a process printer for panic.
    let process_printer = components::process_printer::ProcessPrinterTextComponent::new()
        .finalize(components::process_printer_text_component_static!());
    PROCESS_PRINTER = Some(process_printer);

    let process_console = components::process_console::ProcessConsoleComponent::new(
        board_kernel,
        uart_mux,
        mux_alarm,
        process_printer,
        None,
    )
    .finalize(components::process_console_component_static!(
        InternalTimers
    ));
    let _ = process_console.start();

    let mux_mctp = mcu_components::mux_mctp::MCTPMuxComponent::new(&peripherals.i3c, mux_alarm)
        .finalize(mctp_mux_component_static!(InternalTimers, MCTPI3CBinding));

    let mctp_spdm = mcu_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_SPDM_DRIVER_NUM,
        mux_mctp,
        MessageType::Spdm,
    )
    .finalize(mctp_driver_component_static!(InternalTimers));

    let mctp_secure_spdm = mcu_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_SECURE_SPDM_DRIVER_NUM,
        mux_mctp,
        MessageType::SecureSpdm,
    )
    .finalize(mctp_driver_component_static!(InternalTimers));

    let mctp_pldm = mcu_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_PLDM_DRIVER_NUM,
        mux_mctp,
        MessageType::Pldm,
    )
    .finalize(mctp_driver_component_static!(InternalTimers));

    let mctp_caliptra = mcu_components::mctp_driver::MCTPDriverComponent::new(
        board_kernel,
        capsules_runtime::mctp::driver::MCTP_CALIPTRA_DRIVER_NUM,
        mux_mctp,
        MessageType::Caliptra,
    )
    .finalize(mctp_driver_component_static!(InternalTimers));

    // Set up a SPDM over DOE capsule.
    let doe_spdm = mcu_components::doe::DoeComponent::new(
        board_kernel,
        capsules_runtime::doe::driver::DOE_SPDM_DRIVER_NUM,
        &emulator_peripherals.doe_transport,
    )
    .finalize(doe_component_static!(
        doe_mbox_driver::EmulatedDoeTransport<'static, InternalTimers<'static>>
    ));

    peripherals.init();

    // Create a mux for the physical flash controller
    let mux_primary_flash =
        components::flash::FlashMuxComponent::new(&emulator_peripherals.primary_flash_ctrl)
            .finalize(components::flash_mux_component_static!(
                flash_driver::flash_ctrl::EmulatedFlashCtrl
            ));

    let mut flash_partitions: [Option<
        &'static capsules_runtime::flash_partition::FlashPartition<'static>,
    >; mcu_config_emulator::flash::FLASH_PARTITIONS_COUNT] =
        [None; mcu_config_emulator::flash::FLASH_PARTITIONS_COUNT];

    instantiate_flash_partitions!(
        flash_partition_list_primary,
        flash_partitions,
        board_kernel,
        mux_primary_flash
    );

    // Create a mux for the recovery flash controller
    let mux_secondary_flash =
        components::flash::FlashMuxComponent::new(&emulator_peripherals.secondary_flash_ctrl)
            .finalize(components::flash_mux_component_static!(
                flash_driver::flash_ctrl::EmulatedFlashCtrl
            ));

    instantiate_flash_partitions!(
        flash_partition_list_secondary,
        flash_partitions,
        board_kernel,
        mux_secondary_flash
    );

    let dma = runtime_components::dma::DmaComponent::new(
        &emulator_peripherals.dma,
        board_kernel,
        capsules_emulator::dma::DMA_CTRL_DRIVER_NUM,
    )
    .finalize(kernel::static_buf!(capsules_emulator::dma::Dma<'static>));

    // Need to enable all interrupts for Tock Kernel
    chip.enable_pic_interrupts();
    chip.enable_timer_interrupts();

    // enable interrupts globally
    csr::CSR
        .mie
        .modify(csr::mie::mie::mext::SET + csr::mie::mie::msoft::SET + csr::mie::mie::BIT29::SET);
    csr::CSR.mstatus.modify(csr::mstatus::mstatus::mie::SET);

    romtime::println!("[xs debug]sstorage: {:#010x}", addr_of!(_sstorage) as usize);
    romtime::println!("[xs debug]estorage: {:#010x}", addr_of!(_estorage) as usize);

    LOG_STORAGE = Some(unsafe {
        core::slice::from_raw_parts(
            addr_of!(_sstorage),
            addr_of!(_estorage) as usize - addr_of!(_sstorage) as usize,
        )
    });

    if let Some(log_storage) = LOG_STORAGE {
        check_log_storage_erased(log_storage);
    }

    debug!("MCU initialization complete.");
    debug!("Entering main loop.");

    let scheduler =
        components::sched::cooperative::CooperativeComponent::new(&*addr_of!(PROCESSES))
            .finalize(components::cooperative_component_static!(NUM_PROCS));

    let scheduler_timer = static_init!(
        VirtualSchedulerTimer<VirtualMuxAlarm<'static, InternalTimers<'static>>>,
        VirtualSchedulerTimer::new(systick_virtual_alarm)
    );

    let veer = static_init!(
        VeeR,
        VeeR {
            alarm,
            console,
            lldb,
            scheduler,
            scheduler_timer,
            mctp_spdm,
            mctp_secure_spdm,
            mctp_pldm,
            mctp_caliptra,
            doe_spdm,
            flash_partitions,
            mailbox,
            dma,
        }
    );

    kernel::process::load_processes(
        board_kernel,
        chip,
        core::slice::from_raw_parts(
            addr_of!(_sapps),
            addr_of!(_eapps) as usize - addr_of!(_sapps) as usize,
        ),
        core::slice::from_raw_parts_mut(
            addr_of_mut!(_sappmem),
            addr_of!(_eappmem) as usize - addr_of!(_sappmem) as usize,
        ),
        &mut *addr_of_mut!(PROCESSES),
        &FAULT_RESPONSE,
        &process_mgmt_cap,
    )
    .unwrap_or_else(|err| {
        debug!("Error loading processes!");
        debug!("{:?}", err);
    });

    #[cfg(any(
        feature = "test-flash-ctrl-read-write-page",
        feature = "test-flash-ctrl-erase-page",
        feature = "test-flash-storage-read-write",
        feature = "test-flash-storage-erase"
    ))]
    {
        PLATFORM = Some(veer);
        MAIN_CAP = Some(&create_capability!(capabilities::MainLoopCapability));
        BOARD = Some(board_kernel);
    }

    // Run any requested test
    let exit = if cfg!(feature = "test-exit-immediately") {
        debug!("Executing test-exit-immediately");
        Some(0)
    } else if cfg!(feature = "test-i3c-simple") {
        debug!("Executing test-i3c-simple");
        crate::tests::i3c_target_test::test_i3c_simple()
    } else if cfg!(feature = "test-i3c-constant-writes") {
        debug!("Executing test-i3c-constant-writes");
        crate::tests::i3c_target_test::test_i3c_constant_writes()
    } else if cfg!(feature = "test-flash-ctrl-init") {
        debug!("Executing test-flash-ctrl-init");
        crate::tests::flash_ctrl_test::test_flash_ctrl_init()
    } else if cfg!(feature = "test-flash-ctrl-read-write-page") {
        debug!("Executing test-flash-ctrl-read-write-page");
        crate::tests::flash_ctrl_test::test_flash_ctrl_read_write_page()
    } else if cfg!(feature = "test-flash-ctrl-erase-page") {
        debug!("Executing test-flash-ctrl-erase-page");
        crate::tests::flash_ctrl_test::test_flash_ctrl_erase_page()
    } else if cfg!(feature = "test-flash-storage-read-write") {
        debug!("Executing test-flash-storage-read-write");
        crate::tests::flash_storage_test::test_flash_storage_read_write()
    } else if cfg!(feature = "test-flash-storage-erase") {
        debug!("Executing test-flash-storage-erase");
        crate::tests::flash_storage_test::test_flash_storage_erase()
    } else if cfg!(feature = "test-mcu-rom-flash-access") {
        debug!("Executing test-mcu-rom-flash-access");
        Some(0)
    } else if cfg!(feature = "test-doe-transport-loopback") {
        debug!("Executing test-doe-transport-loopback");
        crate::tests::doe_transport_test::test_doe_transport_loopback()
    } else {
        None
    };

    #[cfg(feature = "test-mctp-capsule-loopback")]
    {
        debug!("Executing test-mctp-capsule-loopback");
        crate::tests::mctp_test::test_mctp_capsule_loopback(mux_mctp);
    }

    if let Some(exit) = exit {
        crate::io::exit_emulator(exit);
    }

    // Disable WDT1 before running the loop
    let mci: StaticRef<mci::regs::Mci> =
        unsafe { StaticRef::new(MCU_MEMORY_MAP.mci_offset as *const mci::regs::Mci) };
    let mci_wdt = romtime::Mci::new(mci);
    mci_wdt.disable_wdt();

    board_kernel.kernel_loop(veer, chip, None::<&kernel::ipc::IPC<0>>, &main_loop_cap);
}

#[cfg(any(
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page",
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase"
))]
pub fn run_kernel_op(loops: usize) {
    unsafe {
        for _i in 0..loops {
            BOARD.unwrap().kernel_loop_operation(
                PLATFORM.unwrap(),
                CHIP.unwrap(),
                None::<&kernel::ipc::IPC<0>>,
                true,
                MAIN_CAP.unwrap(),
            );
        }
    }
}

// Sanity check the storage region is 0xFF
fn check_log_storage_erased(log_storage: &[u8]) {
    for (i, &byte) in log_storage.iter().enumerate() {
        assert!(
            byte == 0xFF,
            "[xs debug] LOG_STORAGE not erased at offset {:#x}: {:#04x}",
            i,
            byte
        );
    }
    debug!(
        "[xs debug] LOG_STORAGE erased check passed, size: {} bytes",
        log_storage.len()
    );
}
