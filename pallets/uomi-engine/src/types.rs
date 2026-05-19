use sp_core::{U256, H160};
use sp_runtime::BoundedVec;
use crate::MaxDataSize;

pub type Version = u32;
pub type AiModelKey = U256;
pub type RequestId = U256;
pub type NftId = U256;
pub type BlockNumber = U256;
pub type Address = H160;
pub type Data = BoundedVec<u8, MaxDataSize>;
pub type InferenceBalance = u128;

#[derive(
    codec::Encode,
    codec::Decode,
    Clone,
    Copy,
    PartialEq,
    Eq,
    frame_support::pallet_prelude::RuntimeDebug,
    scale_info::TypeInfo,
    frame_support::pallet_prelude::MaxEncodedLen,
    Default,
    frame_support::pallet_prelude::DecodeWithMemTracking,
)]
pub struct InferenceMetrics {
    pub tokens_in: u32,
    pub tokens_out: u32,
}

#[derive(
    codec::Encode,
    codec::Decode,
    Clone,
    Copy,
    PartialEq,
    Eq,
    frame_support::pallet_prelude::RuntimeDebug,
    scale_info::TypeInfo,
    frame_support::pallet_prelude::MaxEncodedLen,
    Default,
    frame_support::pallet_prelude::DecodeWithMemTracking,
)]
pub struct ModelPrice {
    pub price_per_input_token: InferenceBalance,
    pub price_per_output_token: InferenceBalance,
    pub base_fee: InferenceBalance,
}
