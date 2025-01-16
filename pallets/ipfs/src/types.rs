use frame_support::{ parameter_types, BoundedVec };
use frame_system::pallet_prelude::BlockNumberFor;

use sp_core::U256;

parameter_types! {
    pub const MaxCidSize: u32 = 59;
}
pub type Cid = BoundedVec<u8, MaxCidSize>;
pub type NftId = U256;
pub type BlockNumber<T> = BlockNumberFor<T>;
pub type ExpirationBlockNumber = U256;
pub type UsableFromBlockNumber = U256;
