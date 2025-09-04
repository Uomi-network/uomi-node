use crate::types::SessionId;

use frost_ed25519::keys::PublicKeyPackage;
use frost_ed25519::round1::{SigningCommitments, SigningNonces};
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{Identifier, SigningPackage};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::fs::{self as fs, File};
use std::io::{self, ErrorKind, Read, Write as IoWrite};

use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub enum StorageType {
    /// FROST
    DKGRound1SecretPackage,
    DKGRound2SecretPackage,
    DKGRound1IdentifierPackage,
    DKGRound2IdentifierPackage,
    Key,
    PubKey,
    SigningCommitments,
    SigningNonces,
    SignatureShare,
    SigningPackage,

    // ECDSA
    EcdsaKeys,
    EcdsaOfflineOutput,
    EcdsaOnlineOutput,
}

impl TryFrom<StorageType> for u8 {
    type Error = std::io::Error;

    fn try_from(value: StorageType) -> Result<Self, Self::Error> {
        Ok(match value {
            StorageType::DKGRound1SecretPackage => 0,
            StorageType::DKGRound2SecretPackage => 1,
            StorageType::DKGRound1IdentifierPackage => 2,
            StorageType::DKGRound2IdentifierPackage => 3,
            StorageType::Key => 4,
            StorageType::PubKey => 5,
            StorageType::SigningCommitments => 6,
            StorageType::SigningNonces => 7,
            StorageType::SignatureShare => 8,
            StorageType::SigningPackage => 9,
            StorageType::EcdsaKeys => 10,
            StorageType::EcdsaOfflineOutput => 11,
            StorageType::EcdsaOnlineOutput => 12,
        })
    }
}

impl TryFrom<u8> for StorageType {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(StorageType::DKGRound1SecretPackage),
            1 => Ok(StorageType::DKGRound2SecretPackage),
            2 => Ok(StorageType::DKGRound1IdentifierPackage),
            3 => Ok(StorageType::DKGRound2IdentifierPackage),
            4 => Ok(StorageType::Key),
            5 => Ok(StorageType::PubKey),
            6 => Ok(StorageType::SigningCommitments),
            7 => Ok(StorageType::SigningNonces),
            8 => Ok(StorageType::SignatureShare),
            9 => Ok(StorageType::SigningPackage),
            10 => Ok(StorageType::EcdsaKeys),
            11 => Ok(StorageType::EcdsaOfflineOutput),
            12 => Ok(StorageType::EcdsaOnlineOutput),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid storage type")),
        }
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut hex_string = String::new();
    for byte in result {
        write!(&mut hex_string, "{:02x}", byte).expect("Failed to write to string");
    }
    hex_string
}

fn format_filename(
    session_id: SessionId,
    storage_type: &StorageType,
    identifier: Option<&[u8]>,
) -> String {
    let base_name = format!("sessions/{}", session_id);

    match storage_type {
        StorageType::DKGRound1SecretPackage => format!("{}/dkg/round1/secret", base_name),
        StorageType::DKGRound2SecretPackage => format!("{}/dkg/round2/secret", base_name),
        StorageType::DKGRound1IdentifierPackage => {
            if let Some(id) = identifier {
                format!("{}/round1/{}", base_name, sha256_hex(&id))
            } else {
                format!("{}/round1", base_name)
            }
        }
        StorageType::DKGRound2IdentifierPackage => {
            if let Some(id) = identifier {
                format!("{}/round2/{}", base_name, sha256_hex(&id))
            } else {
                format!("{}/round2", base_name)
            }
        }
        StorageType::Key => format!("{}/frost/keys/{}", base_name, sha256_hex(&identifier.unwrap())),
        StorageType::PubKey => format!("{}/frost/pubkeys/{}", base_name, sha256_hex(&identifier.unwrap())),
        StorageType::SigningCommitments => format!("{}/signing/commitments", base_name),
        StorageType::SigningNonces => format!("{}/signing/nonces", base_name),
        StorageType::SignatureShare => format!("{}/signing/share", base_name),
        StorageType::SigningPackage => format!("{}/signing/package", base_name),

        StorageType::EcdsaKeys => format!("{}/ecdsa/keys/{}", base_name, sha256_hex(&identifier.unwrap())),
        StorageType::EcdsaOfflineOutput => format!("{}/ecdsa/offline/{}", base_name, sha256_hex(&identifier.unwrap())),
        StorageType::EcdsaOnlineOutput => format!("{}/ecdsa/online/{}", base_name, sha256_hex(&identifier.unwrap())),
    }
}

pub trait Storage {
    fn store_data(
        &mut self,
        session_id: SessionId,
        storage_type: StorageType,
        data: &[u8],
        identifier: Option<&[u8]>,
    ) -> io::Result<()>;

    fn read_data(
        &self,
        session_id: SessionId,
        storage_type: StorageType,
        identifier: Option<&[u8]>,
    ) -> io::Result<Vec<u8>>;
    
    // Helper for testing - checks if any data exists for this session
    fn has_session(&self, session_id: &SessionId) -> bool {
        self.read_data(*session_id, StorageType::Key, None).is_ok()
    }

    fn read_secret_package_round1(
        &self,
        session_id: SessionId,
    ) -> Result<frost_ed25519::keys::dkg::round1::SecretPackage, frost_ed25519::Error> {
        let data = self
            .read_data(session_id, StorageType::DKGRound1SecretPackage, None)
            .map_err(|_| frost_ed25519::Error::DeserializationError);
        if let Ok(data) = data {
            frost_ed25519::keys::dkg::round1::SecretPackage::deserialize(&data)
                .map_err(|_| frost_ed25519::Error::DeserializationError)
        } else {
            Err(frost_ed25519::Error::DeserializationError)
        }
    }

    fn read_secret_package_round2(
        &self,
        session_id: SessionId,
    ) -> Result<frost_ed25519::keys::dkg::round2::SecretPackage, frost_ed25519::Error> {
        let data = self
            .read_data(session_id, StorageType::DKGRound2SecretPackage, None)
            .map_err(|_| frost_ed25519::Error::DeserializationError);

        if let Ok(data) = data {
            frost_ed25519::keys::dkg::round2::SecretPackage::deserialize(&data)
                .map_err(|_| frost_ed25519::Error::DeserializationError)
        } else {
            Err(frost_ed25519::Error::DeserializationError)
        }
    }

    fn read_nonces(&self, session_id: SessionId) -> Result<SigningNonces, frost_ed25519::Error> {
        let data = self
            .read_data(session_id, StorageType::SigningNonces, None)
            .map_err(|_| frost_ed25519::Error::DeserializationError);
        if let Ok(data) = data {
            SigningNonces::deserialize(&data)
                .map_err(|_| frost_ed25519::Error::DeserializationError)
        } else {
            Err(frost_ed25519::Error::DeserializationError)
        }
    }

    fn read_signing_package(
        &self,
        session_id: SessionId,
    ) -> Result<SigningPackage, frost_ed25519::Error> {
        let data = self
            .read_data(session_id, StorageType::SigningPackage, None)
            .map_err(|_| frost_ed25519::Error::DeserializationError);
        if let Ok(data) = data {
            SigningPackage::deserialize(&data)
                .map_err(|_| frost_ed25519::Error::DeserializationError)
        } else {
            Err(frost_ed25519::Error::DeserializationError)
        }
    }

    fn get_key_package(
        &self,
        session_id: SessionId,
        identifier: &Identifier
    ) -> Result<frost_ed25519::keys::KeyPackage, frost_ed25519::Error> {
        let data = self
            .read_data(session_id, StorageType::Key, Some(&identifier.serialize()[..]))
            .map_err(|err| {
                log::error!("Errrr {:?}", err);
                frost_ed25519::Error::DeserializationError
            })
            .unwrap();
        frost_ed25519::keys::KeyPackage::deserialize(&data)
            .map_err(|_| frost_ed25519::Error::DeserializationError)
    }

    fn get_signing_nonces(
        &self,
        session_id: SessionId,
    ) -> Result<frost_ed25519::round1::SigningNonces, frost_ed25519::Error> {
        let data = self
            .read_data(session_id, StorageType::SigningNonces, None)
            .map_err(|_| frost_ed25519::Error::DeserializationError)
            .unwrap();
        frost_ed25519::round1::SigningNonces::deserialize(&data)
            .map_err(|_| frost_ed25519::Error::DeserializationError)
    }

    fn get_pubkey(&self, session_id: SessionId, identifier: &Identifier) -> Result<PublicKeyPackage, frost_ed25519::Error> {
        let data = self
            .read_data(session_id, StorageType::PubKey, Some(&identifier.serialize()[..]))
            .map_err(|_| frost_ed25519::Error::DeserializationError)
            .unwrap();
        PublicKeyPackage::deserialize(&data).map_err(|_| frost_ed25519::Error::DeserializationError)
    }

    fn fetch_round1_packages(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, frost_ed25519::keys::dkg::round1::Package>>;
    fn fetch_round2_packages(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, frost_ed25519::keys::dkg::round2::Package>>;
    fn fetch_commitments(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, SigningCommitments>>;
    fn fetch_signature_shares(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, SignatureShare>>;

    fn store_round1_packages(&mut self, session_id: SessionId, identifier: Identifier, data: &[u8]);
    fn store_round2_packages(&mut self, session_id: SessionId, identifier: Identifier, data: &[u8]);
    fn store_commitment(&mut self, session_id: SessionId, identifier: Identifier, data: &[u8]);
    fn store_signature_share(&mut self, session_id: SessionId, identifier: Identifier, data: &[u8]);
    
    // Read signature
    fn read_signature(&self, session_id: SessionId) -> io::Result<Vec<u8>> {
        self.read_data(session_id, StorageType::SignatureShare, None)
    }
    
    // Store signature
    fn store_signature(&mut self, session_id: SessionId, signature: &[u8]) -> io::Result<()> {
        self.store_data(session_id, StorageType::SignatureShare, signature, None)
    }
    
    // Remove signature (for testing)
    fn remove_signature(&mut self, _session_id: SessionId) -> io::Result<()> {
        // Default implementation - can be overridden by implementors
        Ok(())
    }
}

/// In-memory storage implementation. Useful for testing or non-persistent scenarios.
pub struct MemoryStorage {
    data: BTreeMap<(SessionId, StorageType), Vec<u8>>,
    round1: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
    round2: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,

    commitments: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
    signature_shares: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
}

/// File system storage implementation. Persists data to files.
pub struct FileStorage;

impl FileStorage {
    pub fn new() -> Self {
        Self {}
    }
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::<(SessionId, StorageType), Vec<u8>>::new(),
            round1: BTreeMap::<String, BTreeMap<Vec<u8>, Vec<u8>>>::new(),
            round2: BTreeMap::<String, BTreeMap<Vec<u8>, Vec<u8>>>::new(),
            commitments: BTreeMap::<String, BTreeMap<Vec<u8>, Vec<u8>>>::new(),
            signature_shares: BTreeMap::<String, BTreeMap<Vec<u8>, Vec<u8>>>::new(),
        }
    }

    fn dump_to_file(&self) {
        use std::fs::{self, File};
        use std::io::{self, Write};
        use std::path::Path;
    
        // Create a directory for the data if it doesn't exist
        let data_dir = get_base_directory().join("memory_storage");
        if !data_dir.exists() {
            fs::create_dir_all(data_dir.clone()).expect("Failed to create storage directory");
        }
    
        // Helper function to write a Vec<u8> with its length prefix
        fn write_bytes(file: &mut File, bytes: &[u8]) -> io::Result<()> {
            // Write length as u32
            let len = bytes.len() as u32;
            file.write_all(&len.to_le_bytes())?;
            // Write actual bytes
            file.write_all(bytes)
        }
    
        // Helper function to write a String with its length prefix
        fn write_string(file: &mut File, s: &str) -> io::Result<()> {
            write_bytes(file, s.as_bytes())
        }
    
        // Dump main data (BTreeMap<(SessionId, StorageType), Vec<u8>>)
        {
            let data_path = data_dir.join("data.bin");
            let mut file = File::create(data_path).expect("Failed to create data file");
            
            // Write number of entries
            let count = self.data.len() as u32;
            file.write_all(&count.to_le_bytes()).expect("Failed to write count");
            
            // Write each entry
            for ((session_id, storage_type), value) in &self.data {
                // Write session_id (u64)
                file.write_all(&session_id.to_le_bytes()).expect("Failed to write session_id");
                
                // Write storage_type (assuming it's an enum that can be converted to u8)
                let storage_type_val: u8 = (*storage_type).try_into().unwrap();
                file.write_all(&[storage_type_val]).expect("Failed to write storage_type");
                
                // Write value
                write_bytes(&mut file, value).expect("Failed to write value");
            }
        }
    
        // Helper function to serialize a BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>
        fn serialize_nested_map(path: &Path, map: &BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>) -> io::Result<()> {
            let mut file = File::create(path)?;
            
            // Write number of outer entries
            let count = map.len() as u32;
            file.write_all(&count.to_le_bytes())?;
            
            // Write each outer entry
            for (key, inner_map) in map {
                // Write key string
                write_string(&mut file, key)?;
                
                // Write number of inner entries
                let inner_count = inner_map.len() as u32;
                file.write_all(&inner_count.to_le_bytes())?;
                
                // Write each inner entry
                for (inner_key, inner_value) in inner_map {
                    // Write inner key
                    write_bytes(&mut file, inner_key)?;
                    
                    // Write inner value
                    write_bytes(&mut file, inner_value)?;
                }
            }
            
            Ok(())
        }
    
        // Dump other data structures using the helper
        serialize_nested_map(&data_dir.join("round1.bin"), &self.round1)
            .expect("Failed to serialize round1 data");
        
        serialize_nested_map(&data_dir.join("round2.bin"), &self.round2)
            .expect("Failed to serialize round2 data");
        
        serialize_nested_map(&data_dir.join("commitments.bin"), &self.commitments)
            .expect("Failed to serialize commitments data");
        
        serialize_nested_map(&data_dir.join("signature_shares.bin"), &self.signature_shares)
            .expect("Failed to serialize signature_shares data");
    }
    
    pub fn load_from_file(&mut self) {
        use std::fs::File;
        use std::io::{self, Read};
        use std::path::Path;
    
        // Helper function to read a Vec<u8> with its length prefix
        fn read_bytes(file: &mut File) -> io::Result<Vec<u8>> {
            // Read length (u32)
            let mut len_bytes = [0u8; 4];
            file.read_exact(&mut len_bytes)?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            
            // Read bytes
            let mut bytes = vec![0u8; len];
            file.read_exact(&mut bytes)?;
            Ok(bytes)
        }
    
        // Helper function to read a String with its length prefix
        fn read_string(file: &mut File) -> io::Result<String> {
            let bytes = read_bytes(file)?;
            String::from_utf8(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))
        }
    
        let data_dir = get_base_directory().join("memory_storage");
        if !data_dir.exists() {
            // No data to load
            return;
        }
    
        // Load main data (BTreeMap<(SessionId, StorageType), Vec<u8>>)
        let data_path = data_dir.join("data.bin");
        if data_path.exists() {
            let mut file = File::open(data_path).expect("Failed to open data file");
            
            // Read number of entries
            let mut count_bytes = [0u8; 4];
            file.read_exact(&mut count_bytes).expect("Failed to read count");
            let count = u32::from_le_bytes(count_bytes) as usize;
            
            // Clear existing data
            self.data.clear();
            
            // Read each entry
            for _ in 0..count {
                // Read session_id (u64)
                let mut session_id_bytes = [0u8; 8];
                file.read_exact(&mut session_id_bytes).expect("Failed to read session_id");
                let session_id = u64::from_le_bytes(session_id_bytes);
                
                // Read storage_type (assuming it's an enum that can be converted from u8)
                let mut storage_type_byte = [0u8; 1];
                file.read_exact(&mut storage_type_byte).expect("Failed to read storage_type");
                let storage_type: StorageType = storage_type_byte[0].try_into().expect("Failed to convert byte to StorageType");
                
                // Read value
                let value = read_bytes(&mut file).expect("Failed to read value");
                
                // Insert into map
                self.data.insert((session_id, storage_type), value);
            }
        }
    
        // Helper function to deserialize a BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>
        fn deserialize_nested_map(path: &Path) -> io::Result<BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>> {
            let mut result = BTreeMap::new();
            
            if !path.exists() {
                return Ok(result);
            }
            
            let mut file = File::open(path)?;
            
            // Read number of outer entries
            let mut count_bytes = [0u8; 4];
            file.read_exact(&mut count_bytes)?;
            let count = u32::from_le_bytes(count_bytes) as usize;
            
            // Read each outer entry
            for _ in 0..count {
                // Read key string
                let key = read_string(&mut file)?;
                
                // Read number of inner entries
                let mut inner_count_bytes = [0u8; 4];
                file.read_exact(&mut inner_count_bytes)?;
                let inner_count = u32::from_le_bytes(inner_count_bytes) as usize;
                
                // Create inner map
                let mut inner_map = BTreeMap::new();
                
                // Read each inner entry
                for _ in 0..inner_count {
                    // Read inner key
                    let inner_key = read_bytes(&mut file)?;
                    
                    // Read inner value
                    let inner_value = read_bytes(&mut file)?;
                    
                    // Insert into inner map
                    inner_map.insert(inner_key, inner_value);
                }
                
                // Insert into result
                result.insert(key, inner_map);
            }
            
            Ok(result)
        }
    
        // Load other data structures using the helper
        if let Ok(round1_data) = deserialize_nested_map(&data_dir.join("round1.bin")) {
            self.round1 = round1_data;
        }
        
        if let Ok(round2_data) = deserialize_nested_map(&data_dir.join("round2.bin")) {
            self.round2 = round2_data;
        }
        
        if let Ok(commitments_data) = deserialize_nested_map(&data_dir.join("commitments.bin")) {
            self.commitments = commitments_data;
        }
        
        if let Ok(signature_shares_data) = deserialize_nested_map(&data_dir.join("signature_shares.bin")) {
            self.signature_shares = signature_shares_data;
        }
    }

    fn fetch_data_for_round1(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, frost_ed25519::keys::dkg::round1::Package>> {
        let id = format_filename(session_id, &StorageType::DKGRound1IdentifierPackage, None);
        let mut result_map = BTreeMap::new();

        if let Some(inner_map) = self.round1.get(&id) {
            for (key, bytes) in inner_map {
                // Safely deserialize identifier and package; skip invalid entries instead of panicking
                match (Identifier::deserialize(key), frost_ed25519::keys::dkg::round1::Package::deserialize(bytes)) {
                    (Ok(identifier), Ok(pkg)) => {
                        result_map.insert(identifier, pkg);
                    }
                    (id_res, pkg_res) => {
                        log::error!(
                            "[TSS] Invalid stored round1 entry: id_ok={}, pkg_ok={} (session {})",
                            id_res.is_ok(),
                            pkg_res.is_ok(),
                            session_id
                        );
                    }
                }
            }
        }

        Ok(result_map)
    }

    fn fetch_data_for_round2(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, frost_ed25519::keys::dkg::round2::Package>> {
        let id = format_filename(session_id, &StorageType::DKGRound2IdentifierPackage, None);
        let mut result_map = BTreeMap::new();

        if let Some(inner_map) = self.round2.get(&id) {
            for (key, bytes) in inner_map {
                match (Identifier::deserialize(key), frost_ed25519::keys::dkg::round2::Package::deserialize(bytes)) {
                    (Ok(identifier), Ok(pkg)) => {
                        result_map.insert(identifier, pkg);
                    }
                    (id_res, pkg_res) => {
                        log::error!(
                            "[TSS] Invalid stored round2 entry: id_ok={}, pkg_ok={} (session {})",
                            id_res.is_ok(),
                            pkg_res.is_ok(),
                            session_id
                        );
                    }
                }
            }
        }

        Ok(result_map)
    }

    fn store_data_for_round1(
        &mut self,
        session_id: SessionId,
        data: &[u8],
        identifier: &Identifier,
    ) -> io::Result<()> {
        let id = format_filename(session_id, &StorageType::DKGRound1IdentifierPackage, None);

        self.round1
            .entry(id)
            .or_insert_with(BTreeMap::new)
            .insert(identifier.serialize(), data.to_vec());
        self.dump_to_file();
        Ok(())
    }

    fn store_data_for_round2(
        &mut self,
        session_id: SessionId,
        data: &[u8],
        identifier: &Identifier,
    ) -> io::Result<()> {
        let id = format_filename(session_id, &StorageType::DKGRound2IdentifierPackage, None);

        self.round2
            .entry(id)
            .or_insert_with(BTreeMap::new)
            .insert(identifier.serialize(), data.to_vec());
        self.dump_to_file();

        Ok(())
    }

    fn fetch_data_for_commitment(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, SigningCommitments>> {
        let id = format_filename(session_id, &StorageType::SigningCommitments, None);
        let mut result_map = BTreeMap::new();

        if let Some(inner_map) = self.commitments.get(&id) {
            for (key, bytes) in inner_map {
                match (Identifier::deserialize(key), SigningCommitments::deserialize(bytes)) {
                    (Ok(identifier), Ok(pkg)) => {
                        result_map.insert(identifier, pkg);
                    }
                    (id_res, pkg_res) => {
                        log::error!(
                            "[TSS] Invalid stored commitment entry: id_ok={}, pkg_ok={} (session {})",
                            id_res.is_ok(),
                            pkg_res.is_ok(),
                            session_id
                        );
                    }
                }
            }
        }

        Ok(result_map)
    }

    fn fetch_data_for_signature_shares(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, SignatureShare>> {
        let id = format_filename(session_id, &StorageType::SignatureShare, None);
        let mut result_map = BTreeMap::new();

        if let Some(inner_map) = self.signature_shares.get(&id) {
            for (key, bytes) in inner_map {
                match (Identifier::deserialize(key), SignatureShare::deserialize(bytes)) {
                    (Ok(identifier), Ok(pkg)) => {
                        result_map.insert(identifier, pkg);
                    }
                    (id_res, pkg_res) => {
                        log::error!(
                            "[TSS] Invalid stored signature share entry: id_ok={}, pkg_ok={} (session {})",
                            id_res.is_ok(),
                            pkg_res.is_ok(),
                            session_id
                        );
                    }
                }
            }
        }

        Ok(result_map)
    }

    fn store_data_for_commitment(
        &mut self,
        session_id: SessionId,
        data: &[u8],
        identifier: &Identifier,
    ) -> io::Result<()> {
        let id = format_filename(session_id, &StorageType::SigningCommitments, None);

        self.commitments
            .entry(id)
            .or_insert_with(BTreeMap::new)
            .insert(identifier.serialize(), data.to_vec());
        self.dump_to_file();

        Ok(())
    }

    fn store_data_for_signature_share(
        &mut self,
        session_id: SessionId,
        data: &[u8],
        identifier: &Identifier,
    ) -> io::Result<()> {
        let id = format_filename(session_id, &StorageType::SignatureShare, None);

        self.signature_shares
            .entry(id)
            .or_insert_with(BTreeMap::new)
            .insert(identifier.serialize(), data.to_vec());
        self.dump_to_file();

        Ok(())
    }
}

impl Storage for MemoryStorage {
    fn read_data(
        &self,
        session_id: SessionId,
        storage_type: StorageType,
        _identifier: Option<&[u8]>,
    ) -> io::Result<Vec<u8>> {
        self.data
            .get(&(session_id, storage_type))
            .map(|v| v.clone())
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::NotFound,
                    format!(
                        "Data not found for session {} type {:?}",
                        session_id, storage_type
                    ),
                )
            })
    }

    fn store_data(
        &mut self,
        session_id: SessionId,
        storage_type: StorageType,
        data: &[u8],
        _identifier: Option<&[u8]>,
    ) -> io::Result<()> {
        self.data.insert((session_id, storage_type), data.to_vec()); // Store a copy of data
        self.dump_to_file();
        Ok(())
    }

    fn fetch_round1_packages(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, frost_ed25519::keys::dkg::round1::Package>> {
        self.fetch_data_for_round1(session_id)
    }

    fn fetch_round2_packages(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, frost_ed25519::keys::dkg::round2::Package>> {
        self.fetch_data_for_round2(session_id)
    }

    fn fetch_commitments(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, SigningCommitments>> {
        self.fetch_data_for_commitment(session_id)
    }

    fn fetch_signature_shares(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, SignatureShare>> {
        self.fetch_data_for_signature_shares(session_id)
    }

    fn store_round1_packages(
        &mut self,
        session_id: SessionId,
        identifier: Identifier,
        data: &[u8],
    ) {
        if let Err(e) = self.store_data_for_round1(session_id, data, &identifier) {
            log::error!("Error storing data for round 1 {:?}", e)
        }
    }

    fn store_round2_packages(
        &mut self,
        session_id: SessionId,
        identifier: Identifier,
        data: &[u8],
    ) {
        if let Err(e) = self.store_data_for_round2(session_id, data, &identifier) {
            log::error!("Error storing data for round 2 {:?}", e)
        }
    }

    fn store_commitment(&mut self, session_id: SessionId, identifier: Identifier, data: &[u8]) {
        if let Err(e) = self.store_data_for_commitment(session_id, data, &identifier) {
            log::error!("Error storing data for round 2 {:?}", e)
        }
    }
    fn store_signature_share(
        &mut self,
        session_id: SessionId,
        identifier: Identifier,
        data: &[u8],
    ) {
        if let Err(e) = self.store_data_for_signature_share(session_id, data, &identifier) {
            log::error!("Error storing data for round 2 {:?}", e)
        }
    }
    
    fn remove_signature(&mut self, session_id: SessionId) -> io::Result<()> {
        // Remove the signature from data storage
        self.data.remove(&(session_id, StorageType::SignatureShare));
        
        // Also remove from signature_shares storage
        let id = format_filename(session_id, &StorageType::SignatureShare, None);
        self.signature_shares.remove(&id);
        self.dump_to_file();
        Ok(())
    }
}

impl Storage for FileStorage {
    fn store_data(
        &mut self,
        session_id: SessionId,
        storage_type: StorageType,
        data: &[u8],
        identifier: Option<&[u8]>,
    ) -> io::Result<()> {
        println!("Storing data for session {} type {:?}, identifier {:?}", session_id, storage_type, identifier);
        let filename = format_filename(session_id, &storage_type, identifier);
        store_file(filename, data)
    }

    fn read_data(
        &self,
        session_id: SessionId,
        storage_type: StorageType,
        identifier: Option<&[u8]>,
    ) -> io::Result<Vec<u8>> {
        let filename = format_filename(session_id, &storage_type, identifier);
        read_file(filename)
    }

    fn fetch_round1_packages(
        &self,
        _session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, frost_ed25519::keys::dkg::round1::Package>> {
        Ok(BTreeMap::new())
    }
    fn fetch_round2_packages(
        &self,
        _session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, frost_ed25519::keys::dkg::round2::Package>> {
        Ok(BTreeMap::new())
    }

    fn store_round1_packages(
        &mut self,
        _session_id: SessionId,
        _identifier: Identifier,
        _data: &[u8],
    ) {
    }

    fn store_round2_packages(
        &mut self,
        _session_id: SessionId,
        _identifier: Identifier,
        _data: &[u8],
    ) {
    }

    fn store_commitment(&mut self, _session_id: SessionId, _identifier: Identifier, _data: &[u8]) {}

    fn store_signature_share(
        &mut self,
        _session_id: SessionId,
        _identifier: Identifier,
        _data: &[u8],
    ) {
    }

    fn fetch_commitments(
        &self,
        _session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, SigningCommitments>> {
        Ok(BTreeMap::new())
    }
    fn fetch_signature_shares(
        &self,
        _session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, SignatureShare>> {
        Ok(BTreeMap::new())
    }
}

/// Gets the base directory from the environment variable or defaults to "data".
fn get_base_directory() -> PathBuf {
    env::var("TSS_STORAGE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/uomi/chains/uomi/tss"))
}

pub fn store_file(filename: String, bytes: &[u8]) -> io::Result<()> {
    let mut path = get_base_directory();
    path.push(PathBuf::from(&filename));
    
    // Create all parent directories if they don't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    Ok(())
}
/// Reads bytes from a file within the base directory.
pub fn read_file(filename: String) -> io::Result<Vec<u8>> {
    let mut path = get_base_directory();
    path.push(filename);
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}
