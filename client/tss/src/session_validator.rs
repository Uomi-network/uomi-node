use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sc_network::PeerId;
use crate::{SessionId, TSSPeerId, TSSPublic, PeerMapper};

/// Handles session validation and authorization logic
pub struct SessionValidator {
    sessions_data: Arc<Mutex<HashMap<SessionId, (u16, u16, Vec<u8>, Vec<u8>)>>>,
    session_timestamps: Arc<Mutex<HashMap<SessionId, std::time::Instant>>>,
    session_timeout: u64,
    peer_mapper: Arc<Mutex<PeerMapper>>,
    local_peer_id: TSSPeerId,
    validator_key: TSSPublic,
}

impl SessionValidator {
    pub fn new(
        sessions_data: Arc<Mutex<HashMap<SessionId, (u16, u16, Vec<u8>, Vec<u8>)>>>,
        session_timestamps: Arc<Mutex<HashMap<SessionId, std::time::Instant>>>,
        session_timeout: u64,
        peer_mapper: Arc<Mutex<PeerMapper>>,
        local_peer_id: TSSPeerId,
        validator_key: TSSPublic,
    ) -> Self {
        Self {
            sessions_data,
            session_timestamps,
            session_timeout,
            peer_mapper,
            local_peer_id,
            validator_key,
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
        let id = peer_mapper.get_id_from_peer_id(
            session_id,
            &PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
        );
        drop(peer_mapper);
        id.is_some()
    }

    pub fn is_coordinator(&self, session_id: &SessionId) -> bool {
        if let None = self.get_session_data(session_id) {
            return false;
        }

        let (_, _, coordinator, _) = self.get_session_data(session_id).unwrap();

        coordinator == self.validator_key[..]
    }

    /// Get session data with timeout check
    fn get_session_data(&self, session_id: &SessionId) -> Option<(u16, u16, Vec<u8>, Vec<u8>)> {
        // Check for session timeout
        if self.is_session_timed_out(session_id) {
            return None;
        }
        
        self.sessions_data.lock().unwrap().get(session_id).cloned()
    }
}