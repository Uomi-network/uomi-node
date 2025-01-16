use sp_core::U256;
use sp_std::vec::Vec;
use frame_support::pallet_prelude::{DispatchError, DispatchResult};
use frame_system::pallet_prelude::BlockNumberFor;
use pallet_ipfs::types::{Cid, UsableFromBlockNumber, ExpirationBlockNumber};

pub trait IpfsInterface<T: frame_system::Config> {
    fn get_agent_cid(nft_id: U256) -> Result<Cid, DispatchError>;
    fn get_cid_status(cid: &Cid) -> Result<(ExpirationBlockNumber, UsableFromBlockNumber), DispatchError>;
    fn get_file(cid: &Cid) -> Result<Vec<u8>, sp_runtime::offchain::http::Error>;
    fn pin_file(origin: <T as frame_system::Config>::RuntimeOrigin, cid: Cid, duration: BlockNumberFor<T>) -> DispatchResult;
}