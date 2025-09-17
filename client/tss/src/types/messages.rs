use codec::{Decode, Encode};
use sp_core::sr25519;
use sp_io::crypto::sr25519_verify;
use uomi_runtime::pallet_tss::types::SessionId;
use sp_core::Pair;

use crate::ecdsa::ECDSAPhase;

/// Type alias for TSS Peer ID
pub type TSSPeerId = Vec<u8>;
/// Type alias for TSS Public Key
pub type TSSPublic = Vec<u8>;
/// Type alias for TSS Signature
pub type TSSSignature = Vec<u8>;

/// Main TSS message enum containing all possible message types
#[derive(Encode, Decode, Debug, Clone)]
pub enum TssMessage {
    /// Utilities
    // Announce now optionally includes the challenge nonce it answers (0 if none)
    Announce(u16, TSSPeerId, TSSPublic, TSSSignature, u32),
    /// GetInfo now carries requester's public key and a challenge nonce the responder must echo in its Announce
    GetInfo(TSSPublic, u32),
    Ping,

    /// FROST
    DKGRound1(SessionId, Vec<u8>),
    DKGRound2(SessionId, Vec<u8>, TSSPeerId),
    SigningCommitment(SessionId, Vec<u8>),
    SigningCommitmentP2p(SessionId, Vec<u8>, TSSPeerId),
    SigningPackage(SessionId, Vec<u8>),
    SigningPackageP2p(SessionId, Vec<u8>, TSSPeerId),
    SigningShare(SessionId, Vec<u8>),
    SigningShareP2p(SessionId, Vec<u8>, TSSPeerId),

    /// ECDSA OPEN TSS
    /// Utils
    ECDSAMessageBroadcast(SessionId, String, Vec<u8>, ECDSAPhase),
    ECDSAMessageSubset(SessionId, String, Vec<u8>, ECDSAPhase),
    ECDSAMessageP2p(SessionId, String, TSSPeerId, Vec<u8>, ECDSAPhase),

    /// Utils Keygen
    ECDSAMessageKeygen(SessionId, String, Vec<u8>),
    /// Utils Reshare
    ECDSAMessageReshare(SessionId, String, Vec<u8>),
    /// Utils Sign Offline
    ECDSAMessageSign(SessionId, String, Vec<u8>),
    /// Utils Sign Online
    ECDSAMessageSignOnline(SessionId, String, Vec<u8>),

    /// Retry Mechanism
    ECDSARetryRequest(SessionId, ECDSAPhase, u8, Vec<String>),      // session_id, phase, round, list of missing participant indices
    ECDSARetryResponse(SessionId, ECDSAPhase, u8, String, Vec<u8>), // session_id, phase, round, sender_index, resent_data
}

/// A signed TSS message that provides cryptographic authenticity
#[derive(Encode, Decode, Debug, Clone)]
pub struct SignedTssMessage {
    /// The actual message content
    pub message: TssMessage,
    /// The sender's public key (32 bytes for sr25519)
    pub sender_public_key: [u8; 32],
    /// Message signature using sender's private key
    pub signature: [u8; 64],
    /// Block number to prevent replay attacks (monotonic on-chain reference)
    pub block_number: u64,
}

impl SignedTssMessage {}