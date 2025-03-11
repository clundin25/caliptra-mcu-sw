// Licensed under the Apache-2.0 license

#[cfg(test)]
mod smoke_test;

use caliptra_api::soc_mgr::SocManager;
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    FwId, ImageOptions,
};
use caliptra_image_types::ImageManifest;
use mcu_hw_model::{BootParams, DefaultHwModel, InitParams, McuHwModel};
use openssl::sha::sha384;
use zerocopy::IntoBytes;

pub const DEFAULT_FMC_VERSION: u16 = 0xaaaa;
pub const DEFAULT_APP_VERSION: u32 = 0xbbbbbbbb;

pub fn swap_word_bytes(words: &[u32]) -> Vec<u32> {
    words.iter().map(|word| word.swap_bytes()).collect()
}
pub fn swap_word_bytes_inplace(words: &mut [u32]) {
    for word in words.iter_mut() {
        *word = word.swap_bytes()
    }
}

pub fn bytes_to_be_words_48(buf: &[u8; 48]) -> [u32; 12] {
    let mut result: [u32; 12] = zerocopy::transmute!(*buf);
    swap_word_bytes_inplace(&mut result);
    result
}

// Returns the vendor public key descriptor and owner public key hashes from the image.
pub fn image_pk_desc_hash(manifest: &ImageManifest) -> ([u32; 12], [u32; 12]) {
    let vendor_pk_desc_hash =
        bytes_to_be_words_48(&sha384(manifest.preamble.vendor_pub_key_info.as_bytes()));

    let owner_pk_hash = bytes_to_be_words_48(&sha384(manifest.preamble.owner_pub_keys.as_bytes()));

    (vendor_pk_desc_hash, owner_pk_hash)
}

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
pub fn run_test(
    test_fwid: Option<&'static FwId>,
    test_image_options: Option<ImageOptions>,
    init_params: Option<InitParams>,
    boot_params: Option<BootParams>,
) -> DefaultHwModel {
    let runtime_fwid = test_fwid.unwrap_or(&APP_WITH_UART);

    let image_options = test_image_options.unwrap_or_else(|| {
        let mut opts = ImageOptions::default();
        opts.vendor_config.pl0_pauser = Some(0x1);
        opts.fmc_version = DEFAULT_FMC_VERSION;
        opts.app_version = DEFAULT_APP_VERSION;
        opts
    });

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let init_params = match init_params {
        Some(init_params) => init_params,
        None => InitParams {
            caliptra_rom: &rom,
            ..Default::default()
        },
    };

    let image = caliptra_builder::build_and_sign_image(&FMC_WITH_UART, runtime_fwid, image_options)
        .unwrap();
    let image_bytes = image.to_bytes().unwrap();

    let boot_params = boot_params.unwrap_or_default();

    // Use image in boot_params if provided
    // Otherwise, add our newly built image
    let boot_params = match boot_params.fw_image {
        Some(_) => boot_params,
        None => BootParams {
            fw_image: Some(&image_bytes),
            ..boot_params
        },
    };

    let mut model = mcu_hw_model::new(init_params, boot_params).unwrap();

    model.step_until(|m| {
        m.soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_mb_processing()
    });

    model
}

#[cfg(test)]
mod test {
    use mcu_builder::{CaliptraBuilder, TARGET};
    use std::process::ExitStatus;
    use std::sync::atomic::AtomicU32;
    use std::sync::Mutex;
    use std::{
        path::{Path, PathBuf},
        process::Command,
        sync::LazyLock,
    };

    static PROJECT_ROOT: LazyLock<PathBuf> = LazyLock::new(|| {
        Path::new(&env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    });

    fn target_binary(name: &str) -> PathBuf {
        PROJECT_ROOT
            .join("target")
            .join(TARGET)
            .join("release")
            .join(name)
    }

    // only build the ROM once
    static ROM: LazyLock<PathBuf> = LazyLock::new(compile_rom);

    static TEST_LOCK: LazyLock<Mutex<AtomicU32>> = LazyLock::new(|| Mutex::new(AtomicU32::new(0)));

    fn compile_rom() -> PathBuf {
        mcu_builder::rom_build().expect("ROM build failed");
        let output = target_binary("rom.bin");
        assert!(output.exists());
        output
    }

    fn compile_runtime(feature: &str) -> PathBuf {
        let output = target_binary(&format!("runtime-{}.bin", feature));
        let output_name = format!("{}", output.display());
        mcu_builder::runtime_build_with_apps(&[feature], Some(&output_name))
            .expect("Runtime build failed");
        assert!(output.exists());
        output
    }

    fn run_runtime(
        feature: &str,
        rom_path: PathBuf,
        runtime_path: PathBuf,
        i3c_port: String,
        soc_manifest: Option<PathBuf>,
        caliptra_rom: Option<PathBuf>,
        caliptra_fw: Option<PathBuf>,
        vendor_pk_hash: Option<&str>,
        active_mode: bool,
    ) -> ExitStatus {
        let mut cargo_run_args = vec![
            "run",
            "-p",
            "emulator",
            "--release",
            "--features",
            feature,
            "--",
            "--rom",
            rom_path.to_str().unwrap(),
            "--firmware",
            runtime_path.to_str().unwrap(),
            "--i3c-port",
            i3c_port.as_str(),
        ];
        if active_mode {
            cargo_run_args.push("--active-mode");
        }
        if let Some(soc_manifest) = soc_manifest.as_ref() {
            cargo_run_args.push("--soc-manifest");
            cargo_run_args.push(soc_manifest.to_str().unwrap());
        }
        if let Some(caliptra_rom) = caliptra_rom.as_ref() {
            cargo_run_args.push("--caliptra");
            cargo_run_args.push("--caliptra-rom");
            cargo_run_args.push(caliptra_rom.to_str().unwrap());
        }
        if let Some(caliptra_fw) = caliptra_fw.as_ref() {
            cargo_run_args.push("--caliptra-firmware");
            cargo_run_args.push(caliptra_fw.to_str().unwrap());
        }
        if let Some(vendor_pk_hash) = vendor_pk_hash.as_ref() {
            cargo_run_args.push("--vendor-pk-hash");
            cargo_run_args.push(vendor_pk_hash);
        }
        println!("Running test firmware {}", feature.replace("_", "-"));
        let mut cmd = Command::new("cargo");
        let cmd = cmd.args(&cargo_run_args).current_dir(&*PROJECT_ROOT);
        cmd.status().unwrap()
    }

    #[macro_export]
    macro_rules! run_test {
        ($test:ident) => {
            #[test]
            fn $test() {
                let lock = TEST_LOCK.lock().unwrap();
                lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                println!("Compiling test firmware {}", stringify!($test));
                let feature = stringify!($test).replace("_", "-");
                let test_runtime = compile_runtime(&feature);
                let i3c_port = "65534".to_string();
                let test = run_runtime(
                    &feature,
                    ROM.to_path_buf(),
                    test_runtime,
                    i3c_port,
                    None,
                    None,
                    None,
                    None,
                    false,
                );
                assert_eq!(0, test.code().unwrap_or_default());

                // force the compiler to keep the lock
                lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        };
    }

    // To add a test:
    // * add the test name here
    // * add the feature to the emulator and use it to implement any behavior needed
    // * add the feature to the runtime and use it in board.rs at the end of the main function to call your test
    // These use underscores but will be converted to dashes in the feature flags
    run_test!(test_i3c_simple);
    run_test!(test_i3c_constant_writes);
    run_test!(test_flash_ctrl_init);
    run_test!(test_flash_ctrl_read_write_page);
    run_test!(test_flash_ctrl_erase_page);
    run_test!(test_flash_storage_read_write);
    run_test!(test_flash_storage_erase);
    run_test!(test_flash_usermode);
    run_test!(test_mctp_ctrl_cmds);
    run_test!(test_mctp_capsule_loopback);
    run_test!(test_mctp_user_loopback);
    run_test!(test_pldm_request_response);
    run_test!(test_spdm_validator);
    run_test!(test_pldm_discovery);
    run_test!(test_pldm_fw_update);

    /// This tests a full active mode boot run through with Caliptra, including
    /// loading MCU's firmware from Caliptra over the recovery interface.
    #[test]
    fn test_active_mode_recovery_with_caliptra() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = "test-exit-immediately".to_string();
        println!("Compiling test firmware {}", &feature);
        let test_runtime = compile_runtime(&feature);
        let i3c_port = "65534".to_string();

        let mut caliptra_builder =
            CaliptraBuilder::new(true, None, None, None, None, Some(test_runtime.clone()));

        let caliptra_rom = caliptra_builder
            .get_caliptra_rom()
            .expect("Failed to build Caliptra ROM");
        let caliptra_fw = caliptra_builder
            .get_caliptra_fw()
            .expect("Failed to build Caliptra firmware");
        let soc_manifest = caliptra_builder
            .get_soc_manifest()
            .expect("Failed to build SoC manifest");
        let vendor_pk_hash = caliptra_builder
            .get_vendor_pk_hash()
            .expect("Failed to get vendor PK hash");
        let test = run_runtime(
            &feature,
            ROM.to_path_buf(),
            test_runtime,
            i3c_port,
            Some(soc_manifest),
            Some(caliptra_rom),
            Some(caliptra_fw),
            Some(vendor_pk_hash),
            true,
        );
        assert_eq!(0, test.code().unwrap_or_default());

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
