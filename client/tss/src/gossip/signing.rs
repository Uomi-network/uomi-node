use codec::Encode;
use sp_keystore::KeystorePtr;
use sp_core::sr25519;
use uomi_runtime::pallet_uomi_engine::crypto::CRYPTO_KEY_TYPE as UOMI;
use crate::types::{TssMessage, SignedTssMessage};

/// Service responsible for signing TSS messages
pub struct SigningService {
    keystore: KeystorePtr,
    validator_public_key: [u8; 32],
}

impl SigningService {
    pub fn new(keystore: KeystorePtr, validator_public_key: [u8; 32]) -> Self {
        Self {
            keystore,
            validator_public_key,
        }
    }

    /// Create a signed message using the keystore
    pub fn create_signed_message(&self, message: TssMessage) -> Result<SignedTssMessage, String> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Failed to get current time: {}", e))?
            .as_secs();
        
        // Create the payload to sign (message + public key + timestamp)
        let mut payload = Vec::new();
        payload.extend_from_slice(&message.encode());
        payload.extend_from_slice(&self.validator_public_key);
        payload.extend_from_slice(&current_time.to_le_bytes());
        
        // Sign the payload using the keystore
        let signature_result = self.keystore.sign_with(
            UOMI,
            sr25519::CRYPTO_ID,
            &self.validator_public_key,
            &payload,
        ).map_err(|e| format!("Failed to sign message: {:?}", e))?;

        let signature_bytes = signature_result.ok_or("Failed to get signature from keystore")?;
        let signature: [u8; 64] = signature_bytes.try_into()
            .map_err(|_| "Invalid signature length")?;
        
        Ok(SignedTssMessage {
            message,
            sender_public_key: self.validator_public_key,
            signature,
            timestamp: current_time,
        })
    }
}