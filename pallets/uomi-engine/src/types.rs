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
