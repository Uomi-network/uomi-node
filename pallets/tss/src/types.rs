use frame_support::{parameter_types, BoundedVec};


const MAX_KEY_SIZE: u32 = 64;
const MAX_SHARE_SIZE: u32 = 128;
const MAX_PUBLIC_KEY_SIZE: u32 = 33;
const MAX_SIGNATURE_SIZE: u32 = 65;
const MAX_NUMBER_OF_SHARES: u32 = 65_536;
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
    pub const MinimumValidatorThreshold: u32 = 67; // 67% of 100


}
pub type Key = BoundedVec<u8, MaxKeySize>;
pub type SessionId = u64;

pub type ParticipantId = u32;
pub type Share = BoundedVec<u8, MaxShareSize>;
pub type PublicKey = BoundedVec<u8, MaxPublicKeySize>;
pub type Signature = BoundedVec<u8, MaxSignatureSize>;
pub type NftId = BoundedVec<u8, MaxCidSize>;

