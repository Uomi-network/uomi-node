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

    fn fetch_data_for_round1(
        &self,
        session_id: SessionId,
    ) -> io::Result<BTreeMap<Identifier, frost_ed25519::keys::dkg::round1::Package>> {
        let id = format_filename(session_id, &StorageType::DKGRound1IdentifierPackage, None);
        let mut result_map = BTreeMap::new();

        if let Some(inner_map) = self.round1.get(&id) {
            for (key, bytes) in inner_map {
                // result_map.insert(Identifier., value)
                result_map.insert(
                    Identifier::deserialize(key).unwrap(),
                    frost_ed25519::keys::dkg::round1::Package::deserialize(bytes).unwrap(),
                );
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
                // result_map.insert(Identifier., value)
                result_map.insert(
                    Identifier::deserialize(key).unwrap(),
                    frost_ed25519::keys::dkg::round2::Package::deserialize(bytes).unwrap(),
                );
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
                // result_map.insert(Identifier., value)
                result_map.insert(
                    Identifier::deserialize(key).unwrap(),
                    SigningCommitments::deserialize(bytes).unwrap(),
                );
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
                // result_map.insert(Identifier., value)
                result_map.insert(
                    Identifier::deserialize(key).unwrap(),
                    SignatureShare::deserialize(bytes).unwrap(),
                );
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
        .unwrap_or_else(|_| PathBuf::from("key-material"))
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
