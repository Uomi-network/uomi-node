use codec::{Decode, Encode};
use frame_support::{
   BoundedVec,
   pallet_prelude::RuntimeDebug,
};
use frame_system::offchain::{SignedPayload, SigningTypes};
use sp_core::U256;

use crate::{
   MaxDataSize,
   types::Version,
};

// PayloadNodesOutputs

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
pub struct PayloadNodesOutputs<Public> {
    pub request_id: U256,
    pub output_data: BoundedVec<u8, MaxDataSize>,
    pub public: Public,
}

impl <T: SigningTypes> SignedPayload<T> for PayloadNodesOutputs<T::Public> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

// PayloadNodesVersions

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
pub struct PayloadNodesVersions<Public> {
    pub version: Version,
    pub public: Public,
}

impl <T: SigningTypes> SignedPayload<T> for PayloadNodesVersions<T::Public> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

// PayloadNodesOpocL0Inferences

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
pub struct PayloadNodesOpocL0Inferences<Public> {
    pub request_id: U256,
    pub inference_index: u32,
    pub inference_proof: BoundedVec<u8, MaxDataSize>,
    pub public: Public,
}

impl <T: SigningTypes> SignedPayload<T> for PayloadNodesOpocL0Inferences<T::Public> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}
