use crate::{ types::Cid, Config, NodesPins };
use sp_runtime::DispatchResult;

pub fn add_node_pin<T: Config>(cid: &Cid, node_id: &T::AccountId) -> DispatchResult {
    NodesPins::<T>::insert(cid, node_id, true);
    Ok(())
}
pub fn remove_node_pin<T: Config>(cid: Cid, node_id: T::AccountId) -> DispatchResult {
    NodesPins::<T>::remove(cid, node_id);
    Ok(())
}
