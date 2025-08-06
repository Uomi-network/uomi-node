use crate::{
    client::ClientManager,
    types::{SessionId},
    SessionManager,
};
use sp_runtime::traits::Block as BlockT;
use std::{
    vec::Vec,
};
use uomi_runtime::pallet_tss::TssOffenceType;
use log::{info, error};


impl<B: BlockT, C: ClientManager<B>> SessionManager<B, C> {
    /// Cleanup expired sessions
    pub fn cleanup_expired_sessions(&mut self) {
        let now = std::time::Instant::now();
        let mut expired_sessions = Vec::new();
        
        // Identify expired sessions
        {
            let timestamps = self.session_core.session_timestamps.lock().unwrap();
            for (session_id, timestamp) in timestamps.iter() {
                if now.duration_since(*timestamp).as_secs() > self.session_core.session_timeout {
                    expired_sessions.push(*session_id);
                }
            }
        }
        
        // Clean up expired sessions
        for session_id in expired_sessions {
            info!("[TSS] Cleaning up expired session {}", session_id);

            // Get the inactive participants for reporting them
            let inactive_participants = self.get_inactive_participants(&session_id);
            if inactive_participants.len() > 0 { 
                let best_hash = self.client.best_hash();
                
                // Report participants using the existing mechanism
                let _ = self.client.report_participants(best_hash, session_id, inactive_participants.clone());
                
                // Determine the offence type based on session state
                let offence_type = {
                    let dkg_states = self.state_managers.dkg_state_manager.dkg_session_states.lock().unwrap();
                    let signing_states = self.state_managers.signing_state_manager.signing_session_states.lock().unwrap();
                    
                    if dkg_states.contains_key(&session_id) {
                        TssOffenceType::DkgNonParticipation
                    } else if signing_states.contains_key(&session_id) {
                        TssOffenceType::SigningNonParticipation
                    } else {
                        TssOffenceType::UnresponsiveBehavior
                    }
                };
                
                // Report TSS offence for slashing
                if let Err(e) = self.client.report_tss_offence(best_hash, session_id, offence_type, inactive_participants.clone()) {
                    error!("[TSS] Failed to report TSS offence for session {}: {:?}", session_id, e);
                } else {
                    info!("[TSS] Successfully reported TSS offence for session {} with {} offenders", session_id, inactive_participants.len());
                }
            }

            // Remove from all session data structures
            {
                let mut session_data = self.session_core.sessions_data.lock().unwrap();
                session_data.remove(&session_id);
            }
            
            {
                let mut sessions_participants = self.participant_manager.sessions_participants.lock().unwrap();
                sessions_participants.remove(&session_id);
            }
            
            {
                let mut dkg_states = self.state_managers.dkg_state_manager.dkg_session_states.lock().unwrap();
                dkg_states.remove(&session_id);
            }
            
            {
                let mut signing_states = self.state_managers.signing_state_manager.signing_session_states.lock().unwrap();
                signing_states.remove(&session_id);
            }
            
            {
                let mut timestamps = self.session_core.session_timestamps.lock().unwrap();
                timestamps.remove(&session_id);
            }
            
            {
                let mut buffer = self.buffer.lock().unwrap();
                buffer.remove(&session_id);
            }
        }
    }

    
}
