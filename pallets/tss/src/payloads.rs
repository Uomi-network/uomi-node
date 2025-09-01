use frame_support::pallet_prelude::*;
use frame_support::BoundedVec;
use frame_system::offchain::{SignedPayload, SigningTypes};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

use crate::types::{MaxMessageSize, PublicKey, SessionId};
use crate::types::MaxTxHashSize;
use crate::types::NftId;


#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct UpdateValidatorsPayload<T: crate::Config> {
    pub validators: Vec<T::AccountId>,
    pub public: T::Public,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct ReportParticipantsPayload<T: crate::Config> {
    pub session_id: SessionId,
    pub reported_participants: BoundedVec<T::AccountId, <T as crate::Config>::MaxNumberOfShares>,
    pub public: T::Public,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct CreateSigningSessionPayload<T: crate::Config> {
    // Unique request identifier from OPOC Outputs
    pub request_id: sp_core::U256,
    pub nft_id: sp_core::U256,
    // Target chain for which the signing (transaction) is requested
    pub chain_id: u32,
    pub message: BoundedVec<u8, MaxMessageSize>,
    pub public: T::Public,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct GapFillerSigningSessionPayload<T: crate::Config> {
    /// Synthetic unique request id for gap filler (keccak256 of marker + nft + chain + nonce)
    pub request_id: sp_core::U256,
    pub nft_id: sp_core::U256,
    pub chain_id: u32,
    pub nonce: u64,
    pub message: BoundedVec<u8, MaxMessageSize>,
    pub public: T::Public,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct UpdateLastOpocRequestIdPayload<T: crate::Config> {
    pub last_request_id: sp_core::U256,
    pub public: T::Public,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct ReportParticipantsCountPayload<T: crate::Config> {
    pub session_id: SessionId,
    pub public: T::Public,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct SubmitDKGResultPayload<T: crate::Config> {
    pub session_id: SessionId,
    pub public_key: PublicKey,
    pub public: T::Public,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct SubmitSignatureResultPayload<T: crate::Config> {
    pub session_id: SessionId,
    pub signature: crate::types::Signature,
    pub public: T::Public,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct SubmitFsaTransactionPayload<T: crate::Config> {
    pub session_id: SessionId,
    /// Unique request id linking to FsaTransactionRequests storage entry (allows direct removal without session scan)
    pub request_id: sp_core::U256,
    pub chain_id: u32,
    pub tx_hash: BoundedVec<u8, MaxTxHashSize>,
    pub nft_id: NftId,
    pub public: T::Public,
}

impl<T: crate::Config> ReportParticipantsPayload<T> {
    pub fn new(
        session_id: SessionId,
        reported_participants: BoundedVec<T::AccountId, <T as crate::Config>::MaxNumberOfShares>,
        public: T::Public,
    ) -> Self {
        Self {
            session_id,
            reported_participants,
            public,
        }
    }
}

impl<T: SigningTypes + crate::Config> SignedPayload<T> for ReportParticipantsPayload<T> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

impl<T: SigningTypes + crate::Config> SignedPayload<T> for UpdateValidatorsPayload<T> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

impl<T: SigningTypes + crate::Config> SignedPayload<T> for ReportParticipantsCountPayload<T> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

impl<T: SigningTypes + crate::Config> SignedPayload<T> for SubmitDKGResultPayload<T> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

impl<T: SigningTypes + crate::Config> SignedPayload<T> for SubmitSignatureResultPayload<T> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

impl<T: SigningTypes + crate::Config> SignedPayload<T> for SubmitFsaTransactionPayload<T> {
    fn public(&self) -> T::Public { self.public.clone() }
}

impl<T: SigningTypes + crate::Config> SignedPayload<T> for CreateSigningSessionPayload<T> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

impl<T: SigningTypes + crate::Config> SignedPayload<T> for GapFillerSigningSessionPayload<T> {
    fn public(&self) -> T::Public { self.public.clone() }
}

impl<T: SigningTypes + crate::Config> SignedPayload<T> for UpdateLastOpocRequestIdPayload<T> {
    fn public(&self) -> T::Public { self.public.clone() }
}