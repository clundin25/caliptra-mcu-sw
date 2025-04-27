// Licensed under the Apache-2.0 license

use clap::{Parser, Subcommand};
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

        #[arg(long, default_value_t = false)]
        active_mode: bool,

        #[arg(long)]
        soc_manifest: Option<PathBuf>,

        #[arg(long)]
        vendor_pk_hash: Option<String>,

        /// Path to the PLDM Firmware package to be used in streaming boot
        #[arg(long)]
        streaming_boot: Option<PathBuf>,

        /// Paths to the optional SoC images to be used in streaming boot
        soc_images: Option<Vec<PathBuf>>,

        /// Path to the Flash image to be used in streaming boot
        #[arg(long)]
        flash_image: Option<PathBuf>,
    },
    /// Build Runtime image
    RuntimeBuild {
        /// Features to build runtime with
        #[arg(long)]
        features: Vec<String>,

        #[arg(long)]
        output: Option<String>,
    },
    /// Build ROM
    RomBuild,
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

        /// Paths to optional SoC images
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
        Commands::RuntimeBuild { features, output } => {
            let features: Vec<&str> = features.iter().map(|x| x.as_str()).collect();
            mcu_builder::runtime_build_with_apps(&features, output.as_deref(), false)
        }
        Commands::Rom { trace } => rom::rom_run(*trace),
        Commands::RomBuild => mcu_builder::rom_build(),
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
                output,
            ),
            FlashImageCommands::Verify { file } => {
                mcu_builder::flash_image::flash_image_verify(file)
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
