// Licensed under the Apache-2.0 license

mod apps;
mod caliptra;
pub mod flash_image;
mod rom;
mod runtime;
mod tbf;

pub use caliptra::CaliptraBuilder;
pub use rom::rom_build;
pub use runtime::{runtime_build_no_apps, runtime_build_with_apps};

use anyhow::{anyhow, Result};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::LazyLock,
};

pub const TARGET: &str = "riscv32imc-unknown-none-elf";

pub static PROJECT_ROOT: LazyLock<PathBuf> = LazyLock::new(|| {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
});

pub(crate) static SYSROOT: LazyLock<String> = LazyLock::new(|| {
    // cache this in the target directory as it seems to be very slow to call rustc
    let sysroot_file = PROJECT_ROOT.join("target").join("sysroot.txt");
    if sysroot_file.exists() {
        let root = std::fs::read_to_string(&sysroot_file).unwrap();
        if PathBuf::from(&root).exists() {
            return root;
        }
    }
    // slow path
    let tock_dir = &PROJECT_ROOT
        .join("platforms")
        .join("emulator")
        .join("runtime");
    let root = String::from_utf8(
        Command::new("cargo")
            .args(["rustc", "--", "--print", "sysroot"])
            .current_dir(tock_dir)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    if root.is_empty() {
        panic!("Failed to get sysroot");
    }
    // write to target directory as a cache
    std::fs::write(sysroot_file, root.as_bytes()).unwrap();
    root
});

// Set additional flags to produce binaries from .elf files.
// - `--strip-sections`: Remove all section and data not in segments.
// - `--strip-all`: Remove non-allocated sections outside segments.
//   `.gnu.warning*` and `.ARM.attribute` sections are not removed.
pub const OBJCOPY_FLAGS: &str = "--strip-sections --strip-all";

pub(crate) fn find_file(dir: &str, name: &str) -> Option<PathBuf> {
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.unwrap();
        if entry.file_name() == name {
            return Some(entry.path().to_path_buf());
        }
    }
    None
}

pub fn objcopy() -> Result<String> {
    std::env::var("OBJCOPY").map(Ok).unwrap_or_else(|_| {
        // We need to get the full path to llvm-objcopy, if it is installed.
        if let Some(llvm_size) = find_file(&SYSROOT, "llvm-objcopy") {
            Ok(llvm_size.to_str().unwrap().to_string())
        } else {
            Err(anyhow!("Could not find llvm-objcopy; perhaps you need to run `rustup component add llvm-tools` or set the OBJCOPY environment variable to where to find objcopy"))
        }
    })
}

pub(crate) fn target_binary(name: &str) -> PathBuf {
    PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join(name)
}
