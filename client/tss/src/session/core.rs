use std::{collections::HashMap, sync::{Arc, Mutex}};
use sc_network::PeerId;

use crate::{
    types::{SessionId, SessionData, TSSParticipant, TSSPublic, SessionError},
    network::PeerMapper,
};

/// Core session management functionality
pub struct SessionCore {
    pub sessions_data: Arc<Mutex<HashMap<SessionId, SessionData>>>,
    pub session_timestamps: Arc<Mutex<HashMap<SessionId, std::time::Instant>>>,
    pub session_timeout: u64,
    pub validator_key: TSSPublic,
    pub local_peer_id: Vec<u8>,
    pub peer_mapper: Arc<Mutex<PeerMapper>>,
}

impl SessionCore {
    pub fn new(
        sessions_data: Arc<Mutex<HashMap<SessionId, SessionData>>>,
        session_timestamps: Arc<Mutex<HashMap<SessionId, std::time::Instant>>>,
        session_timeout: u64,
        validator_key: TSSPublic,
        local_peer_id: Vec<u8>,
        peer_mapper: Arc<Mutex<PeerMapper>>,
    ) -> Self {
        Self {
            sessions_data,
            session_timestamps,
            session_timeout,
            validator_key,
            local_peer_id,
            peer_mapper,
        }
    }

    /// Check if a session exists
    pub fn session_exists(&self, session_id: &SessionId) -> bool {
        self.sessions_data.lock().unwrap().contains_key(session_id)
    }
    
    /// Check if a session has timed out
    pub fn is_session_timed_out(&self, session_id: &SessionId) -> bool {
        let timestamps = self.session_timestamps.lock().unwrap();
        if let Some(timestamp) = timestamps.get(session_id) {
            let elapsed = timestamp.elapsed().as_secs();
            return elapsed > self.session_timeout;
        }
        false
    }
    
    /// Check if node is authorized to participate in a session
    pub fn is_authorized_for_session(&self, session_id: &SessionId) -> bool {
        let mut peer_mapper = self.peer_mapper.lock().unwrap();
        let id = if let Ok(local_pid) = PeerId::from_bytes(&self.local_peer_id[..]) {
            peer_mapper.get_id_from_peer_id(session_id, &local_pid)
        } else {
            log::error!("[TSS] Invalid local_peer_id bytes; cannot determine authorization for session {:?}", session_id);
            None
        };
        drop(peer_mapper);
        id.is_some()
    }

    /// Add session data with validation
    pub fn add_session_data(
        &self,
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
            log::warn!("[TSS] Session {} has timed out", session_id);
            return None;
        }
        
        self.sessions_data.lock().unwrap().get(session_id).cloned()
    }

    /// Check if this node is the coordinator for a session
    pub fn is_coordinator(&self, session_id: &SessionId) -> bool {
        if let None = self.get_session_data(session_id) {
            return false;
        }

        let (_, _, coordinator, _) = self.get_session_data(session_id).unwrap();

        coordinator == self.validator_key[..]
    }
}