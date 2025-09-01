use frame_support::{parameter_types, BoundedVec};
use sp_std::prelude::*;
use scale_info::prelude::string::String;
use codec::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
use frame_support::traits::Get;

const MAX_KEY_SIZE: u32 = 64;
const MAX_SHARE_SIZE: u32 = 128;
// Aggregated public keys (e.g. uncompressed secp256k1) can be 65 bytes. We previously
// limited this to 33 (compressed form) which caused client side BoundedVec errors when
// uncompressed keys were submitted. Increase to 65 to accept both representations.
const MAX_PUBLIC_KEY_SIZE: u32 = 65;
const MAX_SIGNATURE_SIZE: u32 = 65;
const MAX_NUMBER_OF_SHARES: u32 = 65_536;
const MAX_MESSAGE_SIZE: u32 = 4096; // 4 KB
const MAX_CID_SIZE: u32 = 59;
const MAX_RPC_URL_SIZE: u32 = 256;
const MAX_CHAIN_NAME_SIZE: u32 = 32;
const MAX_TX_HASH_SIZE: u32 = 66; // 0x + 64 hex chars
const MAX_PENDING_NONCES: u32 = 64; // window size for outstanding nonces per agent+chain

parameter_types! {
    pub const MaxKeySize: u32 = MAX_KEY_SIZE;
    pub const MaxShareSize: u32  = MAX_SHARE_SIZE; // TODO CHECK
    pub const MaxPublicKeySize: u32  = MAX_PUBLIC_KEY_SIZE; // TODO CHECK
    pub const MaxSignatureSize: u32  = MAX_SIGNATURE_SIZE; // TODO CHECK
    pub const MaxNumberOfShares: u32 = MAX_NUMBER_OF_SHARES;
    pub const MaxMessageSize: u32 = MAX_MESSAGE_SIZE;
    pub const MaxCidSize: u32 = MAX_CID_SIZE;
    pub const MinimumValidatorThreshold: u32 = 67; // 67% of 100
    pub const MaxRpcUrlSize: u32 = MAX_RPC_URL_SIZE;
    pub const MaxChainNameSize: u32 = MAX_CHAIN_NAME_SIZE;
    pub const MaxTxHashSize: u32 = MAX_TX_HASH_SIZE;
    pub const MaxPendingNonces: u32 = MAX_PENDING_NONCES;


}
pub type Key = BoundedVec<u8, MaxKeySize>;
pub type SessionId = u64;

pub type ParticipantId = u32;
pub type Share = BoundedVec<u8, MaxShareSize>;
pub type PublicKey = BoundedVec<u8, MaxPublicKeySize>;
pub type Signature = BoundedVec<u8, MaxSignatureSize>;
pub type NftId = BoundedVec<u8, MaxCidSize>;

// ---------------- Nonce Tracking Types (agent multi-chain) -----------------
use codec::{Compact};
use crate::types::MaxTxHashSize as _MaxTxHashSizeAlias; // avoid unused warnings if refactored

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub enum PendingStatus {
    /// Allocated but not yet submitted to RPC (no hash)
    Allocated,
    /// RPC accepted (tx hash present)
    Accepted(BoundedVec<u8, MaxTxHashSize>),
    /// Temporary failure (e.g. networking) with retry counter
    FailedTemp(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct PendingNonce {
    pub nonce: u64,
    pub status: PendingStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, Default)]
pub struct NonceState {
    /// Highest nonce ever allocated (Some) or None if none allocated yet
    pub last_allocated: Option<u64>,
    /// Highest contiguous nonce with Accepted status (Some) or None
    pub last_accepted: Option<u64>,
    /// Outstanding nonces above last_accepted (unsorted vector kept sorted by logic)
    pub pending: BoundedVec<PendingNonce, MaxPendingNonces>,
}

/// Chain configuration for multi-chain support
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct ChainConfig {
    pub chain_id: u32,
    pub name: BoundedVec<u8, MaxChainNameSize>,
    pub rpc_url: BoundedVec<u8, MaxRpcUrlSize>,
    pub is_testnet: bool,
}

/// Transaction status for tracking
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub enum TransactionStatus {
    Pending,
    Submitted,
    Confirmed,
    Failed,
}

/// RPC response wrapper
#[derive(Debug, Clone, Encode, Decode, TypeInfo)]
pub struct RpcResponse {
    pub tx_hash: Option<String>,
    pub block_hash: Option<String>,
    pub status: TransactionStatus,
}
