// Licensed under the Apache-2.0 license

use clap::{Parser, Subcommand};
use clap_num::maybe_hex;
use core::panic;
use mcu_builder::ImageCfg;
use std::path::PathBuf;

mod cargo_lock;
mod clippy;
mod deps;
mod docs;
mod format;
mod fpga;
mod header;
mod pldm_fw_pkg;
mod precheckin;
mod registers;
mod rom;
mod runtime;
mod test;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Xtask {
    #[command(subcommand)]
    xtask: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build and Run Runtime image
    Runtime {
        /// Run with tracing options
        #[arg(short, long, default_value_t = false)]
        trace: bool,

        /// TCP port to listen on for communication I3C socket
        #[arg(long)]
        i3c_port: Option<u16>,

        /// Features to build runtime with
        #[arg(long)]
        features: Vec<String>,

        #[arg(long, default_value_t = false)]
        no_stdin: bool,

        #[arg(long)]
        caliptra_rom: Option<PathBuf>,

        #[arg(long)]
        caliptra_firmware: Option<PathBuf>,

        #[clap(long, default_value_t = false)]
        manufacturing_mode: bool,

        #[arg(long)]
        soc_manifest: Option<PathBuf>,

        #[arg(long)]
        vendor_pk_hash: Option<String>,

        /// Path to the PLDM Firmware package to be used in streaming boot
        #[arg(long)]
        streaming_boot: Option<PathBuf>,

        /// List of SoC images with format: <path>,<load_addr>,<image_id>
        /// Example: --soc_image image1.bin,0x80000000,2
        #[arg(long = "soc_image", value_name = "SOC_IMAGE", num_args = 1.., required = false)]
        soc_images: Option<Vec<ImageCfg>>,

        /// Path to the Flash image to be used in streaming boot
        #[arg(long)]
        flash_image: Option<PathBuf>,

        #[arg(long, default_value_t = false)]
        use_dccm_for_stack: bool,

        #[arg(long, value_parser=maybe_hex::<u32>)]
        dccm_offset: Option<u32>,

        #[arg(long, value_parser=maybe_hex::<u32>)]
        dccm_size: Option<u32>,
    },
    /// Build Runtime image
    RuntimeBuild {
        /// Features to build runtime with
        #[arg(long)]
        features: Vec<String>,

        #[arg(long)]
        output: Option<String>,

        /// Platform to build for. Default: emulator
        #[arg(long)]
        platform: Option<String>,

        #[arg(long, default_value_t = false)]
        use_dccm_for_stack: bool,

        #[arg(long, value_parser=maybe_hex::<u32>)]
        dccm_offset: Option<u32>,

        #[arg(long, value_parser=maybe_hex::<u32>)]
        dccm_size: Option<u32>,
    },
    /// Build ROM
    RomBuild {
        /// Platform to build for. Default: emulator
        #[arg(long)]
        platform: Option<String>,
        /// Features to build ROM with.
        #[arg(long)]
        features: Option<String>,
    },
    /// Build and Run ROM image
    Rom {
        /// Run with tracing options
        #[arg(short, long, default_value_t = false)]
        trace: bool,
    },
    /// Commands related to flash images
    FlashImage {
        #[command(subcommand)]
        subcommand: FlashImageCommands,
    },
    /// Run clippy on all targets
    Clippy,
    /// Build docs
    Docs,
    /// Check that all files are formatted
    Format,
    /// Run pre-check-in checks
    Precheckin,
    /// Check cargo lock
    CargoLock,
    /// Check files for Apache license header
    HeaderCheck,
    /// Add Apache license header to files where it is missing
    HeaderFix,
    /// Run tests
    Test,
    /// Autogenerate register files and emulator bus from RDL
    RegistersAutogen {
        /// Check output only
        #[arg(short, long, default_value_t = false)]
        check: bool,

        /// Extra RDL files to parse
        #[arg(short, long)]
        files: Vec<PathBuf>,

        /// Extra addrmap entries to add
        /// Must be in the format of "type@addr"
        #[arg(short, long)]
        addrmap: Vec<String>,
    },
    /// Check dependencies
    Deps,
    /// Build and install the FPGA kernel modules for uio and the ROM backdoors
    FpgaInstallKernelModules,
    /// Utility to create and parse PLDM firmware packages
    PldmFirmware {
        #[command(subcommand)]
        subcommand: PldmFirmwareCommands,
    },
}

#[derive(Subcommand)]
enum FlashImageCommands {
    /// Create a new flash image
    Create {
        /// Path to the Caliptra firmware file
        #[arg(long, value_name = "CALIPTRA_FW", required = true)]
        caliptra_fw: Option<String>,

        /// Path to the SoC manifest file
        #[arg(long, value_name = "SOC_MANIFEST", required = true)]
        soc_manifest: Option<String>,

        /// Path to the MCU runtime file
        #[arg(long, value_name = "MCU_RUNTIME", required = true)]
        mcu_runtime: Option<String>,

        /// List of SoC images with format: <path>,<load_addr>,<image_id>
        /// Example: --soc_image /tmp/a.bin,0x80000000,2
        #[arg(long, value_name = "SOC_IMAGE", num_args=1.., required = false)]
        soc_images: Option<Vec<String>>,

        /// Paths to the output image file
        #[arg(long, value_name = "OUTPUT", required = true)]
        output: String,
    },
    /// Verify an existing flash image
    Verify {
        /// Path to the flash image file
        #[arg(value_name = "FILE")]
        file: String,

        /// Offset of the flash image in the file
        #[arg(long, value_name = "OFFSET", default_value_t = 0)]
        offset: u32,
    },
}

#[derive(Subcommand)]
enum PldmFirmwareCommands {
    /// Encode a manifest TOML file to a firmware package
    Create {
        /// Path to the manifest TOML file
        #[arg(short, long, value_name = "MANIFEST", required = true)]
        manifest: String,

        /// Output file for the firmware package
        #[arg(short, long, value_name = "FILE", required = true)]
        file: String,
    },
    /// Decode a firmware package to a manifest and components
    Decode {
        /// Path to the firmware package file
        #[arg(short, long, value_name = "PACKAGE", required = true)]
        package: String,

        /// Output directory for manifest and components
        #[arg(short, long, value_name = "DIRECTORY", required = true)]
        dir: String,
    },
}

fn main() {
    let cli = Xtask::parse();
    let result = match &cli.xtask {
        Commands::Runtime { .. } => runtime::runtime_run(cli.xtask),
        Commands::RuntimeBuild {
            features,
            output,
            platform,
            use_dccm_for_stack,
            dccm_offset,
            dccm_size,
        } => {
            let features: Vec<&str> = features.iter().map(|x| x.as_str()).collect();
            mcu_builder::runtime_build_with_apps_cached(
                &features,
                output.as_deref(),
                false,
                platform.as_deref(),
                match platform.as_deref() {
                    None | Some("emulator") => Some(&mcu_config_emulator::EMULATOR_MEMORY_MAP),
                    Some("fpga") => Some(&mcu_config_fpga::FPGA_MEMORY_MAP),
                    _ => panic!("Unsupported platform"),
                },
                *use_dccm_for_stack,
                *dccm_offset,
                *dccm_size,
            )
            .map(|_| ())
        }
        Commands::Rom { trace } => rom::rom_run(*trace),
        Commands::RomBuild { platform, features } => {
            mcu_builder::rom_build(platform.as_deref(), features.as_deref().unwrap_or(""))
                .map(|_| ())
        }
        Commands::FlashImage { subcommand } => match subcommand {
            FlashImageCommands::Create {
                caliptra_fw,
                soc_manifest,
                mcu_runtime,
                soc_images,
                output,
            } => mcu_builder::flash_image::flash_image_create(
                caliptra_fw,
                soc_manifest,
                mcu_runtime,
                soc_images,
                0,
                output,
            ),
            FlashImageCommands::Verify { file, offset } => {
                mcu_builder::flash_image::flash_image_verify(file, *offset)
            }
        },
        Commands::Clippy => clippy::clippy(),
        Commands::Docs => docs::docs(),
        Commands::Precheckin => precheckin::precheckin(),
        Commands::Format => format::format(),
        Commands::CargoLock => cargo_lock::cargo_lock(),
        Commands::HeaderFix => header::fix(),
        Commands::HeaderCheck => header::check(),
        Commands::Test => test::test(),
        Commands::RegistersAutogen {
            check,
            files,
            addrmap,
        } => registers::autogen(*check, files, addrmap),
        Commands::Deps => deps::check(),
        Commands::FpgaInstallKernelModules => fpga::fpga_install_kernel_modules(),
        Commands::PldmFirmware { subcommand } => match subcommand {
            PldmFirmwareCommands::Create { manifest, file } => pldm_fw_pkg::create(manifest, file),
            PldmFirmwareCommands::Decode { package, dir } => pldm_fw_pkg::decode(package, dir),
        },
    };
    result.unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });
}
