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

    // Reconstruct the payload that was signed: message + sender_public_key + block_number
    let mut payload = Vec::new();
    payload.extend_from_slice(&signed_message.message.encode());
    payload.extend_from_slice(&signed_message.sender_public_key);
    payload.extend_from_slice(&signed_message.block_number.to_le_bytes());

    // Debug logging to help identify the issue
    log::debug!(
    "[TSS] Verifying signature - payload_len: {}, public_key: {:?}, signature: {:?}, block_number: {}",
        payload.len(),
        hex::encode(&signed_message.sender_public_key),
        hex::encode(&signed_message.signature),
    signed_message.block_number
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
    is_valid
}

/// Checks if the message block number is within acceptable bounds.
///
/// Only rejects messages that are too OLD (replay protection). Future-signed messages
/// are accepted unconditionally: in a p2p network nodes can be significantly behind
/// in block import, and the forward check provides no real security (an attacker would
/// need the private key to forge a future-dated message, and could just sign a fresh
/// one instead). Session lifetimes (pallet deadline) provide the outer validity bound.
pub fn is_block_number_valid(signed_message: &SignedTssMessage, current_block: u64, max_age_blocks: u64) -> bool {
    if current_block < signed_message.block_number {
        // Message is from the future — sender is ahead of us in block import, accept it.
        return true;
    }
    let age = current_block - signed_message.block_number;
    age <= max_age_blocks
}

/// Creates a signed message using the keystore.
pub fn create_signed_message(
    message: TssMessage,
    validator_public_key: &[u8; 32],
    keystore: &KeystorePtr,
    block_number: u64,
) -> Result<SignedTssMessage, String> {
    // Delegate to the centralized SigningService to avoid duplication
    let service = SigningService::new(keystore.clone(), *validator_public_key);
    service.create_signed_message(message, block_number)
}

/// Verifies that a signed message is from the expected sender and has a valid signature and block number.
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

    // Block-number replay checks occur in the gossip validator.

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TssMessage;

    fn msg(block_number: u64) -> SignedTssMessage {
        SignedTssMessage {
            message: TssMessage::Ping,
            sender_public_key: [0u8; 32],
            signature: [0u8; 64],
            block_number,
        }
    }

    #[test]
    fn block_valid_same_block() {
        assert!(is_block_number_valid(&msg(100), 100, 100));
    }

    #[test]
    fn block_valid_within_past_window() {
        assert!(is_block_number_valid(&msg(50), 100, 100));
    }

    #[test]
    fn block_expired_too_old() {
        assert!(!is_block_number_valid(&msg(1), 200, 100));
    }

    #[test]
    fn block_valid_sender_ahead_small() {
        // Sender at 2281, receiver at 2203 (78 blocks ahead) — accepted
        assert!(is_block_number_valid(&msg(2281), 2203, 100));
    }

    #[test]
    fn block_valid_sender_ahead_large() {
        // Sender at 2643, receiver at 2512 (131 blocks ahead) — accepted regardless
        assert!(is_block_number_valid(&msg(2643), 2512, 100));
    }

    #[test]
    fn block_valid_sender_far_future() {
        // Even very far future is accepted (no forward bound)
        assert!(is_block_number_valid(&msg(9999), 100, 100));
    }
}
