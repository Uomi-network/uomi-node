use crate::types::{SessionId, TSSParticipant, TSSPublic};
use sc_network_types::PeerId;
use frost_ed25519::Identifier;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn empty_hash_map<K, V>() -> HashMap<K, V> {
    HashMap::new()
}

#[derive(Debug, Clone)]
pub struct PeerMapper {
    peers: HashMap<PeerId, TSSPublic>,
    pub sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    pub sessions_participants_u16: Arc<Mutex<HashMap<SessionId, HashMap<u16, TSSPublic>>>>,
    pub validator_ids: Arc<Mutex<HashMap<TSSPublic, u32>>>,
}

impl PeerMapper {
    pub fn new(
        sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    ) -> Self {
        PeerMapper {
            peers: HashMap::new(),
            sessions_participants,
            sessions_participants_u16: Arc::new(Mutex::new(HashMap::new())),
            validator_ids: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn peers(&self) -> Arc<Mutex<HashMap<PeerId, TSSPublic>>> {
        Arc::new(Mutex::new(self.peers.clone()))
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        log::info!("Removing Peer {:?}", peer_id);
        self.peers.remove(peer_id);
    }   
    
    pub fn get_account_id_from_peer_id(&mut self, peer_id: &PeerId) -> Option<&TSSPublic> {
        self.peers.get(peer_id)
    }

    pub fn get_peer_id_from_account_id(&mut self, account_id: &TSSPublic) -> Option<&PeerId> {
        self.peers
            .iter()
            .find_map(|(key, val)| if val == account_id { Some(key) } else { None })
    }

    // Modified to use validator ID as identifier where possible
    pub fn get_peer_id_from_identifier(
        &mut self,
        session_id: &SessionId,
        identifier: &Identifier,
    ) -> Option<&PeerId> {
        let sessions_participants = self.sessions_participants.lock().unwrap();
        let session = sessions_participants.get(session_id);

        if let Some(session) = session {
            let account_id = session.get(identifier).cloned();

            drop(sessions_participants);
            if let Some(account_id) = account_id {
                return self.get_peer_id_from_account_id(&account_id);
            }
        }

        None
    }

    pub fn get_peer_id_from_id(&mut self, session_id: &SessionId, id: u16) -> Option<&PeerId> {
        let sessions_participants = self.sessions_participants_u16.lock().unwrap();
        let session = sessions_participants.get(session_id);

        if let Some(session) = session {
            log::info!("Session found");
            let account_id = session.get(&id).cloned();

            drop(sessions_participants);
            if let Some(account_id) = account_id {
                log::info!("Account found {:?}", account_id);

                return self.get_peer_id_from_account_id(&account_id);
            } else {
                log::info!("Account not found");
            }
        } else {
            log::info!("Session not found");
        }

        None
    }

    pub fn get_identifier_from_peer_id(
        &mut self,
        session_id: &SessionId,
        peer_id: &PeerId,
    ) -> Option<Identifier> {
        let account_id = self.peers.get(peer_id).cloned();
        if let Some(account_id) = account_id {
            self.get_identifier_from_account_id(session_id, &account_id)
        } else {
            None
        }
    }

    pub fn get_id_from_peer_id(&mut self, session_id: &SessionId, peer_id: &PeerId) -> Option<u16> {
        let account_id = self.peers.get(peer_id).cloned();

        if let Some(account_id) = account_id {
            self.get_id_from_account_id(session_id, &account_id)
        } else {
            None
        }
    }

    pub fn get_id_from_account_id(
        &mut self,
        session_id: &SessionId,
        account_id: &TSSPublic,
    ) -> Option<u16> {
        let handle = self.sessions_participants_u16.lock().unwrap();
        let session = handle.get(session_id);

        if let None = session {
            return None;
        }

        for (_, (key, val)) in session.unwrap().iter().enumerate() {
            if val == account_id {
                return Some(*key);
            }
        }
        drop(handle);

        return None;
    }

    // Modified to use validator ID if available
    pub fn get_identifier_from_account_id(
        &mut self,
        session_id: &SessionId,
        account_id: &TSSPublic,
    ) -> Option<Identifier> {
        // First try to get the validator ID
        let validator_id = self.get_validator_id(account_id);
        
        if let Some(id) = validator_id {
            // If we have a validator ID, convert it to Identifier
            let identifier: Identifier = u16::try_from(id).unwrap_or(u16::MAX).try_into().unwrap();
            return Some(identifier);
        }
        
        // If no validator ID is found, fall back to the original method
        let handle = self.sessions_participants.lock().unwrap();
        let session = handle.get(session_id);

        if let None = session {
            return None;
        }

        log::debug!(
            "[TSS] get_identifier_from_account_id({:?}, {:?}) from session = {:?}",
            session_id,
            account_id,
            session
        );

        for (_, (key, val)) in session.unwrap().iter().enumerate() {
            if val == account_id {
                return Some(key.clone());
            }
        }
        drop(handle);

        return None;
    }

    pub fn get_account_id_from_identifier(
        &mut self,
        session_id: &SessionId,
        identifier: &Identifier,
    ) -> Option<TSSPublic> {
        let sessions_participants = self.sessions_participants.lock().unwrap();
        let session = sessions_participants.get(session_id);

        if let Some(session) = session {
            let account_id = session.get(identifier).cloned();

            drop(sessions_participants);
            return account_id;
        }

        None
    }

    // Modified to use validator IDs
    pub fn create_session(&mut self, session_id: SessionId, participants: Vec<TSSParticipant>) {
        let mut sessions_participants = self.sessions_participants.lock().unwrap();
        let mut sessions_participants_u16 = self.sessions_participants_u16.lock().unwrap();

        let entry_sessions_participants = sessions_participants
            .entry(session_id)
            .or_insert(empty_hash_map());
        let entry_sessions_participants_u16 = sessions_participants_u16
            .entry(session_id)
            .or_insert(empty_hash_map());

        for (index, val) in participants.iter().enumerate() {
            // Try to get validator ID for this participant
            let validator_id = self.get_validator_id(&val.to_vec())
                .unwrap_or_else(|| (index + 1) as u32); // Fall back to index+1 if no validator ID
            
            // Convert validator_id to Identifier
            
            let identifier: Identifier = u16::try_from(validator_id).unwrap_or_default().try_into().unwrap();
 
            
            entry_sessions_participants.insert(identifier, val.to_vec());
            entry_sessions_participants_u16.insert(u16::try_from(validator_id).unwrap(), val.to_vec());
            
            log::debug!("[TSS] Added participant with validator ID {} to session {} with index {}", validator_id, session_id, index);
        }
        drop(sessions_participants);
        drop(sessions_participants_u16);
    }

    pub fn add_peer(&mut self, peer_id: PeerId, public_key_data: TSSPublic) {
        log::info!("Adding Peer {:?} with public key {:?}", peer_id, public_key_data);
        self.peers.insert(peer_id, public_key_data);
    }

    pub fn get_validator_id(&self, public_key: &TSSPublic) -> Option<u32> {
        let validator_ids = self.validator_ids.lock().unwrap();
        let id = validator_ids.get(public_key).cloned();
        drop(validator_ids);
        id
    }

    pub fn get_validator_account_from_id(&mut self, id: u32) -> Option<TSSPublic> {
        let validator_ids = self.validator_ids.lock().unwrap();
        let account = validator_ids.iter().find_map(|(key, val)| {
            if *val == id {
                Some(key.clone())
            } else {
                None
            }
        });
        drop(validator_ids);
        account
    }

    pub fn set_validator_id(&mut self, public_key: TSSPublic, id: u32) {
        log::debug!("[TSS] Set validator ID {} for public key {:?}", id, public_key);
        let mut validator_ids = self.validator_ids.lock().unwrap();
        validator_ids.insert(public_key, id);
        drop(validator_ids);
    }
}