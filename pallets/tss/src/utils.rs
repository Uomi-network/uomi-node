use crate::types::{PublicKey, Signature};
use sp_core::ecdsa;
use sp_runtime::traits::Verify;

pub trait SignatureVerification<PublicKey> {
    fn verify(key: &PublicKey, message: &[u8], sig: &Signature) -> bool;
}

pub struct Verifier {}

impl SignatureVerification<PublicKey> for Verifier {
    fn verify(key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
        // Convert PublicKey to [u8; 33] for ECDSA public key
        let pubkey_bytes: [u8; 33] = match key.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false, // Public key must be exactly 33 bytes
        };
        let pubkey = ecdsa::Public(pubkey_bytes);

        // Convert Signature to [u8; 65] for ECDSA signature
        let signature_bytes: [u8; 65] = match sig.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false, // Signature must be exactly 65 bytes
        };
        let signature = ecdsa::Signature(signature_bytes);

        // Verify the signature; it hashes the message internally with blake2_256
        signature.verify(message, &pubkey)
    }
}

pub fn verify_signature<T: crate::Config>(key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    T::SignatureVerifier::verify(key, message, sig)
}