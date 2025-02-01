use frost_ed25519::Identifier;
use crate::types::SessionId;
use std::fs::File;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::io::{Read, Write as IoWrite};

pub enum StorageType {
    Round1SecretPackage,
    Round2SecretPackage,
    Round1IdentifierPackage,
    Round2IdentifierPackage,
    Key,
    PubKey,
}


fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut hex_string = String::new();
    for byte in result {
        write!(&mut hex_string, "{:02x}", byte).expect("Failed to write to string");
    }
    hex_string
}

fn format_filename(session_id: SessionId, storage_type: &StorageType, identifier: Option<&Identifier>) -> String {
     let base_name = format!("session-{}", session_id);

    match storage_type {
        StorageType::Round1SecretPackage => format!("{}-round1-secret", base_name),
        StorageType::Round2SecretPackage => format!("{}-round2-secret", base_name),

        StorageType::Round1IdentifierPackage => {
            if let Some(id) = identifier {
                format!("{}-round1-id-{}", base_name, sha256_hex(&id.serialize()))
            } else {
                format!("{}-round1-id", base_name) // or handle this case differently
            }
        }
        StorageType::Round2IdentifierPackage => {
            if let Some(id) = identifier {
                format!("{}-round2-id-{}", base_name, sha256_hex(&id.serialize()))
            } else {
               format!("{}-round2-id", base_name) // or handle this case differently
            }
        }
        StorageType::Key => format!("{}-key", base_name),
        StorageType::PubKey => format!("{}-pubkey", base_name),
    }
}


pub fn store_data(session_id: SessionId, storage_type: StorageType, data: &[u8], identifier: Option<&Identifier>) -> std::io::Result<()> {
    let filename = format_filename(session_id, &storage_type, identifier);
    store_file(filename, data)
}

pub fn store_file(filename: String, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(bytes)?;
    Ok(())
}


pub fn read_data(session_id: SessionId, storage_type: StorageType, identifier: Option<&Identifier>) -> std::io::Result<Vec<u8>> {
    let filename = format_filename(session_id, &storage_type, identifier);
    read_file(filename)
}


pub fn read_file(filename: String) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}