use crate::{
    client::ClientManager,
    types::{SessionId},
    SessionManager,
};
use sc_network_types::PeerId;
use sp_runtime::traits::Block as BlockT;
use std::vec::Vec;
use log::info;

impl<B: BlockT, C: ClientManager<B>> SessionManager<B, C> {
    // Add the participant as active, so that it doesn't get reported as bad actor
    pub fn add_active_participant(&self, session_id: &SessionId, peer_id: &PeerId) {
        let mut active_participants = self.participant_manager.active_participants.lock().unwrap();
        let participants = active_participants.entry(*session_id).or_insert_with(Vec::new);
        let pid = peer_id.to_bytes();
        if participants.contains(&pid) {
            // Already recorded, skip noisy log
            return;
        }
        participants.push(pid);
        // Fetch n for progress (SessionData = (t,n,coordinator,msg))
        let sessions_data = self.session_core.sessions_data.lock().unwrap();
        let maybe_n = sessions_data.get(session_id).map(|d| d.1).unwrap_or(0);
        drop(sessions_data);
        info!("[TSS] Adding Active Participant {:?} (active_count={}/{})", peer_id, participants.len(), maybe_n);
        drop(active_participants);
    }

    /// Checks what participants have not participated actively
    pub fn get_inactive_participants(&self, session_id: &SessionId) -> Vec<[u8; 32]> {
        if !self.is_authorized_for_session(session_id) {
            return Vec::new();
        }
        let mut inactive_participants = Vec::new();

        let sessions_data = self.session_core.sessions_data.lock().unwrap();
        let session_data = sessions_data.get(session_id).cloned();
        drop(sessions_data);
        
        if let Some((_, _, _, _)) = session_data {
            let peer_mapper = self.session_core.peer_mapper.lock().unwrap();
            let participants = peer_mapper.sessions_participants.lock().unwrap().clone();
            drop(peer_mapper);
            let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
            let active_participants = self.participant_manager.active_participants.lock().unwrap();
            let empty_vec = Vec::new();
            let active_participants_in_session = active_participants.get(session_id).unwrap_or(&empty_vec);
            info!("[TSS] Active Participants In Session: {:?}", active_participants_in_session);
            if let Some(session_participants) = participants.get(session_id) {
                for (_identifier, account_id) in session_participants.iter() {
                    let peer_id = peer_mapper.get_peer_id_from_account_id(account_id);
                    if let Some(peer_id) = peer_id {
                        if peer_id.to_bytes() != self.session_core.local_peer_id && !active_participants_in_session.contains(&peer_id.to_bytes()) {
                            inactive_participants.push(account_id.clone().try_into().unwrap());
                        }
                    } else {
                        // If the peer_id is not found, we assume it's inactive
                        inactive_participants.push(account_id.clone().try_into().unwrap());
                    }
                }
            }
            drop(active_participants);
            drop(participants);
            drop(peer_mapper);
        }
        inactive_participants
    }
}
