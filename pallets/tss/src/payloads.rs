use frame_support::pallet_prelude::*;
use frame_support::BoundedVec;
use frame_system::offchain::{SignedPayload, SigningTypes};
use scale_info::TypeInfo;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

use crate::types::{MaxMessageSize, PublicKey, SessionId};


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
    pub nft_id: sp_core::U256,
    pub message: BoundedVec<u8, MaxMessageSize>,
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

impl<T: SigningTypes + crate::Config> SignedPayload<T> for CreateSigningSessionPayload<T> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}