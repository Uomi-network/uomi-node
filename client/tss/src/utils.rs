use std::collections::HashMap;
use sc_service::KeystoreContainer;
use sc_network::{
    config::{self, NonDefaultSetConfig, SetConfig}, 
    NotificationService, ProtocolName
};
use sp_core::{sr25519, ByteArray};
use uomi_runtime::pallet_uomi_engine::crypto::CRYPTO_KEY_TYPE as UOMI;

const TSS_PROTOCOL: &[u8] = b"/tss/1";

pub fn get_active_validators() {}

pub fn get_validator_key_from_keystore(keystore: &KeystoreContainer) -> Option<sp_core::sr25519::Public>{
    keystore
        .keystore()
        .sr25519_public_keys(UOMI)
        .first()
        .cloned()
}

pub fn sign_announcment(
    keystore_container: &KeystoreContainer,
    validator_key: &[u8],
    peer_id: &[u8],
    nonce: u16,
    challenge_answer: u32,
) -> Option<Vec<u8>> {
    // Sign (validator_key || peer_id || nonce_le || challenge_answer_le?) to bind anti-replay + challenge
    let mut payload = Vec::with_capacity(validator_key.len() + peer_id.len() + 2 + if challenge_answer != 0 {4} else {0});
    payload.extend_from_slice(validator_key);
    payload.extend_from_slice(peer_id);
    payload.extend_from_slice(&nonce.to_le_bytes());
    if challenge_answer != 0 {
        payload.extend_from_slice(&challenge_answer.to_le_bytes());
    }
    let result = keystore_container.keystore().sign_with(
        UOMI,
        sr25519::CRYPTO_ID,
        validator_key,
        &payload,
    );
    match result {
        Ok(signature) => match signature {
            Some(signature) => Some(signature),
            None => {
                log::error!("[TSS] There was an error signing: None");
                None
            }
        },
        Err(err) => {
            log::error!("[TSS] There was an error signing {:?}", err);
            None
        }
    }
}

pub fn get_config() -> (
    NonDefaultSetConfig,
    Box<dyn NotificationService>,
    ProtocolName,
) {
    let protocol: ProtocolName = std::str::from_utf8(TSS_PROTOCOL).unwrap().into();
    let (config, notification_service) = config::NonDefaultSetConfig::new(
        protocol.clone(),
        Vec::new(),
        1024 * 1024,
        None,
        SetConfig {
            in_peers: 5000,
            out_peers: 5000,
            ..Default::default()
        },
    );

    (config, notification_service, protocol)
}

// Helper function to avoid creating a new empty HashMap every time.
pub fn empty_hash_map<K, V>() -> HashMap<K, V> {
    HashMap::new()
}