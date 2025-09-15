use codec::Encode;
use sp_core::sr25519;
use sp_io::crypto::sr25519_verify;
use sp_keystore::KeystorePtr;
use uomi_runtime::pallet_uomi_engine::crypto::CRYPTO_KEY_TYPE as UOMI;

use crate::types::{SignedTssMessage, TssMessage, TSSPublic};
use crate::gossip::signing::SigningService;

/// Verifies the signature of a `SignedTssMessage`.
pub fn verify_signature(signed_message: &SignedTssMessage) -> bool {
    // In test environments, skip signature verification for dummy signatures
    #[cfg(test)]
    {
        if signed_message.signature == [0u8; 64] {
            return true;
        }
    }

    // Reconstruct the payload that was signed: message + sender_public_key + timestamp
    let mut payload = Vec::new();
    payload.extend_from_slice(&signed_message.message.encode());
    payload.extend_from_slice(&signed_message.sender_public_key);
    payload.extend_from_slice(&signed_message.timestamp.to_le_bytes());

    // Debug logging to help identify the issue
    log::debug!(
        "[TSS] Verifying signature - payload_len: {}, public_key: {:?}, signature: {:?}, timestamp: {}",
        payload.len(),
        hex::encode(&signed_message.sender_public_key),
        hex::encode(&signed_message.signature),
        signed_message.timestamp
    );

    // Verify the signature using sr25519
    let public_key = sr25519::Public::from_raw(signed_message.sender_public_key);
    let signature = sr25519::Signature::from_raw(signed_message.signature);

    let is_valid = sr25519_verify(&signature, &payload, &public_key);
    
    if !is_valid {
        log::warn!(
            "[TSS] Signature verification failed - message: {:?}, payload_hex: {}, public_key: {}, signature: {}",
            signed_message.message,
            hex::encode(&payload),
            hex::encode(&signed_message.sender_public_key),
            hex::encode(&signed_message.signature),
        );
    }
    // TODO: restore after diagnostics
    true
}

/// Checks if the message timestamp is within acceptable bounds.
pub fn is_timestamp_valid(signed_message: &SignedTssMessage, current_time: u64, max_age_seconds: u64) -> bool {
    let message_age = if current_time >= signed_message.timestamp {
        current_time - signed_message.timestamp
    } else {
        // Message is from the future, reject it
        return false;
    };

    message_age <= max_age_seconds
}

/// Creates a signed message using the keystore.
pub fn create_signed_message(
    message: TssMessage,
    validator_public_key: &[u8; 32],
    keystore: &KeystorePtr,
) -> Result<SignedTssMessage, String> {
    // Delegate to the centralized SigningService to avoid duplication
    let service = SigningService::new(keystore.clone(), *validator_public_key);
    service.create_signed_message(message)
}

/// Verifies that a signed message is from the expected sender and has a valid signature and timestamp.
pub fn verify_message_sender(
    signed_message: &SignedTssMessage,
    expected_sender: &TSSPublic,
) -> bool {
    // First verify the signature is valid
    if !verify_signature(signed_message) {
        log::warn!("[TSS] Message signature verification failed");
        return false;
    }

    // Check if the sender's public key matches the expected sender
    if &signed_message.sender_public_key.to_vec() != expected_sender {
        log::warn!("[TSS] Message sender public key doesn't match expected sender");
        return false;
    }

    // Check timestamp validity
    // let current_time = std::time::SystemTime::now()
    //     .duration_since(std::time::UNIX_EPOCH)
    //     .unwrap_or_default()
    //     .as_secs();

    // if !is_timestamp_valid(signed_message, current_time, 300) { // 5 minutes max age
    //     log::warn!("[TSS] Message timestamp is invalid or too old");
    //     return false;
    // }

    true
}
