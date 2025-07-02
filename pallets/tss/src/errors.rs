use frame_support::inherent::IsFatalError;
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_std::vec::Vec;

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct EmptyInherent;

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct AggregatedKeyInherent {
    pub session_id: crate::types::SessionId,
    pub public_key: Vec<u8>,
}

#[derive(Encode)]
#[cfg_attr(feature = "std", derive(Debug, Decode))]
pub enum InherentError {
    // Define your specific errors here
    InvalidInherentValue,
}

impl IsFatalError for InherentError {
    fn is_fatal_error(&self) -> bool {
        match self {
            InherentError::InvalidInherentValue => true,
        }
    }
}