use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use uomi_runtime::pallet_tss::TssOffenceType;

use crate::types::SessionId;

pub trait ClientManager<B: BlockT> {
    fn best_hash(&self) -> <<B as BlockT>::Header as HeaderT>::Hash;
    fn report_participants(
        &self,
        hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        inactive_participants: Vec<[u8; 32]>,
    ) -> Result<(), String>;
    fn submit_dkg_result(
        &self,
        hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        aggregated_key: Vec<u8>,
    ) -> Result<(), String>;
    fn report_tss_offence(
        &self,
        hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        offence_type: TssOffenceType,
        offenders: Vec<[u8; 32]>,
    ) -> Result<(), String>;
}