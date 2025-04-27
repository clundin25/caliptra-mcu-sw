// Licensed under the Apache-2.0 license

use libapi_caliptra::crypto::cert_mgr::{
    CertStoreContext, IDEV_ECC_CSR_MAX_SIZE, MAX_ECC_CERT_SIZE,
};
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};

use libtock_platform::Syscalls;
use romtime::{println, test_exit};

const EXPECTED_HASHES_384: [[u8; 48]; 1] = [[
    // data 1
    0x95, 0x07, 0x7f, 0x78, 0x7b, 0x9a, 0xe1, 0x93, 0x72, 0x24, 0x54, 0xbe, 0x37, 0xf5, 0x01, 0x2a,
    0x0e, 0xbf, 0x81, 0xd0, 0xe3, 0x99, 0xdc, 0x3f, 0x14, 0x7d, 0x41, 0x31, 0xc3, 0x76, 0x42, 0x7b,
    0xa4, 0x8d, 0xd1, 0xc4, 0xae, 0x71, 0xde, 0x9a, 0x88, 0x54, 0x71, 0x30, 0xf2, 0xc5, 0x04, 0x28,
]];

const EXPECTED_HASHES_512: [[u8; 64]; 1] = [[
    // data 1
    0xd7, 0x71, 0xd8, 0x3e, 0x23, 0xfa, 0xfc, 0x4b, 0x92, 0x67, 0xe1, 0xd5, 0xd8, 0x62, 0x10, 0x6d,
    0x3e, 0xc1, 0x23, 0x26, 0x51, 0x96, 0x45, 0xc8, 0xab, 0x7a, 0xba, 0x26, 0xa5, 0xdf, 0x2e, 0xfd,
    0xcf, 0xda, 0x46, 0x2b, 0x92, 0xc5, 0x3f, 0xab, 0x06, 0x6a, 0x88, 0xf5, 0x06, 0xec, 0x95, 0xd5,
    0x11, 0xd8, 0x0d, 0x6b, 0x05, 0x67, 0x77, 0xd8, 0x36, 0x13, 0x2f, 0x46, 0x9f, 0x6c, 0x68, 0xd3,
]];

pub async fn test_caliptra_sha<S: Syscalls>() {
    println!("Starting Caliptra mailbox SHA test");

    let data1 = b"Hello from Caliptra! This is a test of the SHA algorithm.";
    let expected_sha_384 = EXPECTED_HASHES_384[0];
    let expected_sha_512 = EXPECTED_HASHES_512[0];

    test_sha::<S>(data1, HashAlgoType::SHA384, &expected_sha_384).await;
    test_sha::<S>(data1, HashAlgoType::SHA512, &expected_sha_512).await;

    println!("SHA test completed successfully");
}

async fn test_sha<S: Syscalls>(data: &[u8], algo: HashAlgoType, expected_hash: &[u8]) {
    println!("Testing SHA algorithm: {:?}", algo);

    let hash_size = algo.hash_size();
    let mut hash_context = HashContext::<S>::new();

    let mut hash = [0u8; 64];

    if let Err(e) = hash_context.init(algo, None).await {
        println!("Failed to initialize hash context with error: {:?}", e);
        test_exit(1);
    }

    if let Err(e) = hash_context.update(&data).await {
        println!("Failed to update hash context with error: {:?}", e);
        test_exit(1);
    }

    if let Err(e) = hash_context.finalize(&mut hash).await {
        println!("Failed to finalize hash context with error: {:?}", e);
        test_exit(1);
    }

    if hash[..hash_size] != expected_hash[..] {
        println!(
            "Hash mismatch: expected {:x?}, got {:x?}",
            expected_hash, hash
        );
        test_exit(1);
    }

    println!("SHA test for {:?} passed", algo);
}

// test get idev_csr
pub async fn test_get_idev_csr<S: Syscalls>() {
    println!("Starting Caliptra mailbox get idev csr test");

    let mut cert_mgr = CertStoreContext::<S>::new();
    let mut csr_der = [0u8; IDEV_ECC_CSR_MAX_SIZE];
    let result = cert_mgr.get_idev_csr(&mut csr_der).await;
    match result {
        Ok(size) => {
            println!("Retrieved CSR of size: {}", size);
            if size > IDEV_ECC_CSR_MAX_SIZE {
                println!("CSR retrieval failed: size exceeds maximum");
                test_exit(1);
            }
            if size == 0 {
                println!("CSR retrieval failed: size is zero");
                test_exit(1);
            }

            println!("CSR data: {:?}", &csr_der[..size]);
        }
        Err(e) => {
            println!("Failed to get CSR with error: {:?}", e);
            test_exit(1);
        }
    }
    println!("Get idev csr test completed successfully");
}

pub async fn test_get_ldev_cert<S: Syscalls>() {
    println!("Starting Caliptra mailbox get ldev cert test");

    let mut cert_mgr = CertStoreContext::<S>::new();
    let mut cert = [0u8; MAX_ECC_CERT_SIZE];
    let result = cert_mgr.get_ldev_cert(&mut cert).await;
    match result {
        Ok(size) => {
            println!("Retrieved LDEV certificate of size: {}", size);

            if size == 0 {
                println!("LDEV certificate retrieval failed: size is zero");
                test_exit(1);
            }

            println!("LDEV certificate data: {:?}", &cert[..size]);
        }
        Err(e) => {
            println!("Failed to get LDEV certificate with error: {:?}", e);
            test_exit(1);
        }
    }
    println!("Get ldev cert test completed successfully");
}

pub async fn test_get_fmc_alias_cert<S: Syscalls>() {
    println!("Starting Caliptra mailbox get FMC alias cert test");

    let mut cert_mgr = CertStoreContext::<S>::new();
    let mut cert = [0u8; MAX_ECC_CERT_SIZE];
    let result = cert_mgr.get_fmc_alias_cert(&mut cert).await;
    match result {
        Ok(size) => {
            println!("Retrieved FMC alias certificate of size: {}", size);

            if size == 0 {
                println!("FMC alias certificate retrieval failed: size is zero");
                test_exit(1);
            }

            println!("FMC alias certificate data: {:?}", &cert[..size]);
        }
        Err(e) => {
            println!("Failed to get FMC alias certificate with error: {:?}", e);
            test_exit(1);
        }
    }
    println!("Get FMC alias cert test completed successfully");
}

pub async fn test_get_rt_alias_cert<S: Syscalls>() {
    println!("Starting Caliptra mailbox get FMC cert test");

    let mut cert_mgr = CertStoreContext::<S>::new();
    let mut cert = [0u8; MAX_ECC_CERT_SIZE];
    let result = cert_mgr.get_rt_alias_cert(&mut cert).await;
    match result {
        Ok(size) => {
            println!("Retrieved RT alias certificate of size: {}", size);

            if size == 0 {
                println!("RT alias certificate retrieval failed: size is zero");
                test_exit(1);
            }

            println!("RT alias certificate data: {:?}", &cert[..size]);
        }
        Err(e) => {
            println!("Failed to get RT alias certificate with error: {:?}", e);
            test_exit(1);
        }
    }
    println!("Get RT alias cert test completed successfully");
}

pub async fn test_get_cert_chain<S: Syscalls>() {
    println!("Starting Caliptra mailbox get cert chain test");

    let mut cert_chain = [0u8; 4098];
    const CERT_CHUNK_SIZE: usize = 1024;

    let mut cert_mgr = CertStoreContext::<S>::new();
    let mut cert_chunk = [0u8; CERT_CHUNK_SIZE];
    let mut offset = 0;

    let mut cert_chain_complete = false;

    loop {
        if cert_chain_complete {
            break;
        }

        cert_chunk.fill(0);
        println!("Getting certificate chain chunk at offset: {}", offset);

        // Get the next chunk of the certificate chain
        let result = cert_mgr.cert_chain_chunk(offset, &mut cert_chunk).await;
        match result {
            Ok(size) => {
                println!("Retrieved certificate chain of size: {}", size);

                if size < CERT_CHUNK_SIZE {
                    println!("Certificate chain retrieval completed");
                    cert_chain_complete = true;
                }

                // println!("Certificate chain data: {:?}", &cert_chain[..size]);
                if size > 0 {
                    cert_chain[offset..offset + size].copy_from_slice(&cert_chunk[..size]);
                    offset += size;
                }
            }
            Err(e) => {
                println!("Failed to get certificate chain with error: {:x?}", e);
                test_exit(1);
            }
        }
    }
    println!(
        "Get cert chain test completed successfully. Cert chain size: {}",
        offset
    );
    println!("Cert chain data: {:?}", &cert_chain[..offset]);
}

pub async fn test_certify_attestation_key<S: Syscalls>() {
    println!("Starting Caliptra mailbox certify attestation key test");

    let mut cert_mgr = CertStoreContext::<S>::new();
    let mut cert = [0u8; MAX_ECC_CERT_SIZE];
    let mut pubkey_x = [0u8; 48];
    let mut pubkey_y = [0u8; 48];
    let result = cert_mgr
        .certify_attestation_key(&mut cert, Some(&mut pubkey_x), Some(&mut pubkey_y))
        .await;
    match result {
        Ok(size) => {
            println!("Retrieved attestation key certificate of size: {}", size);

            if size == 0 {
                println!("Attestation key certificate retrieval failed: size is zero");
                test_exit(1);
            }

            println!("Attestation key certificate data: {:?}", &cert[..size]);
            println!("Attestation key public key X: {:?}", &pubkey_x[..]);
            println!("Attestation key public key Y: {:?}", &pubkey_y[..]);
        }
        Err(e) => {
            println!(
                "Failed to get attestation key certificate with error: {:?}",
                e
            );
            test_exit(1);
        }
    }

    println!("Certify attestation key test completed successfully");
}

pub async fn test_sign_with_attestation_key<S: Syscalls>() {
    println!("Starting Caliptra mailbox sign with attestation key test");

    let mut cert_mgr = CertStoreContext::<S>::new();
    let test_digest: [u8; 48] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f, 0x30,
    ];
    let mut signature = [0u8; 128];
    let result = cert_mgr
        .sign_with_attestation_key(&test_digest, &mut signature)
        .await;
    match result {
        Ok(size) => {
            println!("Retrieved attestation key signature of size: {}", size);

            if size == 0 {
                println!("Attestation key signature retrieval failed: size is zero");
                test_exit(1);
            }

            println!("Attestation key signature data: {:?}", &signature[..size]);
        }
        Err(e) => {
            println!(
                "Failed to get attestation key signature with error: {:?}",
                e
            );
            test_exit(1);
        }
    }
    println!("Sign with attestation key test completed successfully");
}
