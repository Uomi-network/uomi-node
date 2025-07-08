use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sc_network::PeerId;
use crate::{SessionId, TSSPeerId, TSSParticipant, PeerMapper, ClientManager, SessionError};
use sp_runtime::traits::Block as BlockT;

/// Handles session state and participant management
pub struct SessionState<B: BlockT, C: ClientManager<B>> {
    sessions_data: Arc<Mutex<HashMap<SessionId, (u16, u16, Vec<u8>, Vec<u8>)>>>,
    session_timestamps: Arc<Mutex<HashMap<SessionId, std::time::Instant>>>,
    session_timeout: u64,
    peer_mapper: Arc<Mutex<PeerMapper>>,
    active_participants: Arc<Mutex<HashMap<SessionId, Vec<TSSPeerId>>>>,
    client: C,
    _phantom: std::marker::PhantomData<B>,
}

impl<B: BlockT, C: ClientManager<B>> SessionState<B, C> {
    pub fn new(
        sessions_data: Arc<Mutex<HashMap<SessionId, (u16, u16, Vec<u8>, Vec<u8>)>>>,
        session_timestamps: Arc<Mutex<HashMap<SessionId, std::time::Instant>>>,
        session_timeout: u64,
        peer_mapper: Arc<Mutex<PeerMapper>>,
        active_participants: Arc<Mutex<HashMap<SessionId, Vec<TSSPeerId>>>>,
        client: C,
    ) -> Self {
        Self {
            sessions_data,
            session_timestamps,
            session_timeout,
            peer_mapper,
            active_participants,
            client,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add session data with validation
    pub fn add_session_data(
        &mut self,
        session_id: SessionId,
        t: u16,
        n: u16,
        coordinator: TSSParticipant,
        participants: Vec<TSSParticipant>,
        message: Vec<u8>,
    ) -> Result<(), SessionError> {
        // Check if session already exists
        if self.session_exists(&session_id) {
            log::warn!("[TSS] Session {} already exists, refusing to create again", session_id);
        //    return Err(SessionError::SessionAlreadyExists);
        }
        
        // Validate threshold requirements
        if t == 0 || n == 0 || t > n {
            log::error!("[TSS] Invalid threshold parameters t={}, n={}", t, n);
            return Err(SessionError::GenericError(format!("Invalid threshold parameters: t={}, n={}", t, n)));
        }
        
        // Validate participants list
        if participants.len() != n as usize {
            log::error!(
                "[TSS] Mismatch between participant count and n parameter: {} vs {}",
                participants.len(),
                n
            );
            return Err(SessionError::GenericError(format!(
                "Participant count ({}) doesn't match n parameter ({})",
                participants.len(), n
            )));
        }

        // Add the session data
        let mut sessions_data = self.sessions_data.lock().unwrap();
        sessions_data.insert(session_id, (t, n, coordinator.to_vec(), message));
        drop(sessions_data);

        let mut peer_mapper = self.peer_mapper.lock().unwrap();
        peer_mapper.create_session(session_id, participants.clone());
        drop(peer_mapper);
        
        // Record session creation time for timeout tracking
        let mut timestamps = self.session_timestamps.lock().unwrap();
        timestamps.insert(session_id, std::time::Instant::now());
        drop(timestamps);
        
        log::info!("[TSS] Successfully created session {}", session_id);
        Ok(())
    }

    /// Get session data with timeout check
    pub fn get_session_data(&self, session_id: &SessionId) -> Option<(u16, u16, Vec<u8>, Vec<u8>)> {
        // Check for session timeout
        if self.is_session_timed_out(session_id) {
            return None;
        }
        
        self.sessions_data.lock().unwrap().get(session_id).cloned()
    }

    // Add the participant as active, so that it doesn't get reported as bad actor
    pub fn add_active_participant(&self, session_id: &SessionId, peer_id: &PeerId) {
        log::info!("[TSS] Adding Active Participant {:?}", peer_id);
        let mut active_participants = self.active_participants.lock().unwrap();
        let participants = active_participants.entry(*session_id).or_insert_with(Vec::new);
        participants.push(peer_id.to_bytes());
        drop(active_participants);
    }

    /// Checks what participants have not participated actively
    pub fn get_inactive_participants(&self, session_id: &SessionId) -> Vec<[u8; 32]> {
        if !self.is_authorized_for_session(session_id) {
            return Vec::new();
        }
        let mut inactive_participants = Vec::new();

        let sessions_data = self.sessions_data.lock().unwrap();
        let session_data = sessions_data.get(session_id).cloned();
        drop(sessions_data);
        
        if let Some((_, _, _, _)) = session_data {
            let peer_mapper = self.peer_mapper.lock().unwrap();
            let participants = peer_mapper.sessions_participants().lock().unwrap().clone();
            drop(peer_mapper);
            let mut peer_mapper = self.peer_mapper.lock().unwrap();
            
            // Check each participant
            if let Some(session_participants) = participants.get(session_id) {
                for (identifier, public_key) in session_participants {
                    let peer_id = peer_mapper.get_peer_id_from_identifier(session_id, &identifier.clone());
                    if let Some(peer_id) = peer_id {
                        let active_participants = self.active_participants.lock().unwrap();
                        if let Some(active_list) = active_participants.get(session_id) {
                            if !active_list.contains(&peer_id.to_bytes()) {
                                inactive_participants.push(public_key.clone().try_into().unwrap());
                            }
                        } else {
                            inactive_participants.push(public_key.clone().try_into().unwrap());
                        }
                    }
                }
            }
        }
        inactive_participants
    }

    /// Cleanup expired sessions
    pub fn cleanup_expired_sessions(&mut self) {
        let now = std::time::Instant::now();
        let mut expired_sessions = Vec::new();
        
        // Identify expired sessions
        {
            let timestamps = self.session_timestamps.lock().unwrap();
            for (session_id, timestamp) in timestamps.iter() {
                if now.duration_since(*timestamp).as_secs() > self.session_timeout {
                    expired_sessions.push(*session_id);
                }
            }
        }
        
        // Clean up expired sessions
        for session_id in expired_sessions {
            log::info!("[TSS] Cleaning up expired session {}", session_id);

            // Get the inactive participants for reporting them
            let inactive_participants = self.get_inactive_participants(&session_id);
            if inactive_participants.len() > 0 { 
                let best_hash = self.client.best_hash();
                let _ = self.client.report_participants(best_hash, session_id, inactive_participants.clone());
            }

            // Remove from all session data structures
            {
                let mut sessions_data = self.sessions_data.lock().unwrap();
                sessions_data.remove(&session_id);
            }
            {
                let mut timestamps = self.session_timestamps.lock().unwrap();
                timestamps.remove(&session_id);
            }
            {
                let mut active_participants = self.active_participants.lock().unwrap();
                active_participants.remove(&session_id);
            }
            {
                let mut peer_mapper = self.peer_mapper.lock().unwrap();
                peer_mapper.remove_session(&session_id);
            }
        }
    }

    // Helper methods that need to be implemented based on SessionValidator
    fn session_exists(&self, session_id: &SessionId) -> bool {
        self.sessions_data.lock().unwrap().contains_key(session_id)
    }

    fn is_session_timed_out(&self, session_id: &SessionId) -> bool {
        let timestamps = self.session_timestamps.lock().unwrap();
        if let Some(timestamp) = timestamps.get(session_id) {
            let elapsed = timestamp.elapsed().as_secs();
            return elapsed > self.session_timeout;
        }
        false
    }

    fn is_authorized_for_session(&self, session_id: &SessionId) -> bool {
        // This would need to be implemented based on peer_mapper logic
        // For now, returning true as a placeholder
        true
    }
}