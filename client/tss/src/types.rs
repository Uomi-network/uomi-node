use frame_support::{parameter_types, BoundedVec};
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender};


const MAX_KEY_SIZE: u32 = 64;
const MAX_SHARE_SIZE: u32 = 128;
const MAX_PUBLIC_KEY_SIZE: u32 = 128;
const MAX_SIGNATURE_SIZE: u32 = 128;
const MAX_NUMBER_OF_SHARES: u32 = 10;
const MAX_MESSAGE_SIZE: u32 = 4096; // 4 KB
const MAX_CID_SIZE: u32 = 59;

parameter_types! {
    pub const MaxKeySize: u32 = MAX_KEY_SIZE;
    pub const MaxShareSize: u32  = MAX_SHARE_SIZE; // TODO CHECK
    pub const MaxPublicKeySize: u32  = MAX_PUBLIC_KEY_SIZE; // TODO CHECK
    pub const MaxSignatureSize: u32  = MAX_SIGNATURE_SIZE; // TODO CHECK
    pub const MaxNumberOfShares: u32 = MAX_NUMBER_OF_SHARES;
    pub const MaxMessageSize: u32 = MAX_MESSAGE_SIZE;
    pub const MaxCidSize: u32 = MAX_CID_SIZE;

}
pub type Key = BoundedVec<u8, MaxKeySize>;
pub type SessionId = u64;

pub type ParticipantId = u32;
pub type Share = BoundedVec<u8, MaxShareSize>;
pub type PublicKey = BoundedVec<u8, MaxPublicKeySize>;
pub type Signature = BoundedVec<u8, MaxSignatureSize>;
pub type AgentCid = BoundedVec<u8, MaxCidSize>;



/// Represents a TSS public key as a byte vector.
pub type TSSPublic = Vec<u8>;
/// Represents a TSS signature as a byte vector.
pub type TSSSignature = Vec<u8>;
/// Represents a TSS Peer ID as a byte vector.
pub type TSSPeerId = Vec<u8>;

