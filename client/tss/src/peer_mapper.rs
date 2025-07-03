use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use frost_ed25519::Identifier;
use sc_network::PeerId;
use uomi_runtime::pallet_tss::types::SessionId;

use crate::{TSSPublic, TSSParticipant};

/// Errors that can occur during peer mapping operations
#[derive(Debug, Clone, PartialEq)]
pub enum PeerMapperError {
    SessionNotFound,
    PeerNotFound,
    IdentifierNotFound,
    InvalidValidatorId,
    LockError,
}

/// Manages the mapping between peers, sessions, and validator IDs
pub struct PeerMapper {
    /// Maps peer IDs to their public keys
    peers: HashMap<PeerId, TSSPublic>,
    /// Maps session participants using Frost identifiers
    sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    /// Maps validator public keys to their assigned IDs
    validator_ids: Arc<Mutex<HashMap<TSSPublic, u32>>>,
}

impl PeerMapper {
    /// Creates a new PeerMapper instance
    pub fn new(
        sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    ) -> Self {
        Self {
            peers: HashMap::new(),
            sessions_participants,
            validator_ids: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Adds a peer with their public key
    pub fn add_peer(&mut self, peer_id: PeerId, public_key: TSSPublic) -> Result<(), PeerMapperError> {
        log::info!("Adding peer {:?} with public key {:?}", peer_id, public_key);
        self.peers.insert(peer_id, public_key);
        Ok(())
    }

    /// Gets the public key for a peer
    pub fn get_peer_public_key(&self, peer_id: &PeerId) -> Option<&TSSPublic> {
        self.peers.get(peer_id)
    }

    /// Gets the peer ID for a given public key
    pub fn get_peer_id_by_public_key(&self, public_key: &TSSPublic) -> Option<&PeerId> {
        self.peers
            .iter()
            .find_map(|(peer_id, key)| if key == public_key { Some(peer_id) } else { None })
    }

    /// Sets a validator ID for a public key
    pub fn set_validator_id(&self, public_key: TSSPublic, validator_id: u32) -> Result<(), PeerMapperError> {
        let mut validator_ids = self.validator_ids
            .lock()
            .map_err(|_| PeerMapperError::LockError)?;
        
        validator_ids.insert(public_key.clone(), validator_id);
        log::debug!("Set validator ID {} for public key {:?}", validator_id, public_key);
        Ok(())
    }

    /// Gets the validator ID for a public key
    pub fn get_validator_id(&self, public_key: &TSSPublic) -> Result<Option<u32>, PeerMapperError> {
        let validator_ids = self.validator_ids
            .lock()
            .map_err(|_| PeerMapperError::LockError)?;
        
        Ok(validator_ids.get(public_key).copied())
    }

    /// Gets the public key for a validator ID
    pub fn get_public_key_by_validator_id(&self, validator_id: u32) -> Result<Option<TSSPublic>, PeerMapperError> {
        let validator_ids = self.validator_ids
            .lock()
            .map_err(|_| PeerMapperError::LockError)?;
        
        let public_key = validator_ids
            .iter()
            .find_map(|(key, &id)| if id == validator_id { Some(key.clone()) } else { None });
        
        Ok(public_key)
    }

    /// Creates a new session with participants
    pub fn create_session(&self, session_id: SessionId, participants: Vec<TSSParticipant>) -> Result<(), PeerMapperError> {
        let mut sessions_participants = self.sessions_participants
            .lock()
            .map_err(|_| PeerMapperError::LockError)?;

        let session_map = sessions_participants
            .entry(session_id)
            .or_insert_with(HashMap::new);

        for (index, participant) in participants.iter().enumerate() {
            let public_key = participant.to_vec();
            
            // Try to get validator ID, fall back to index+1
            let validator_id = self.get_validator_id(&public_key)
                .unwrap_or(None)
                .unwrap_or_else(|| (index + 1) as u32);
            
            // Convert validator_id to Identifier
            let identifier = self.validator_id_to_identifier(validator_id)?;
            
            session_map.insert(identifier, public_key);
            
            log::info!(
                "[TSS] Added participant with validator ID {} to session {}",
                validator_id,
                session_id
            );
        }

        Ok(())
    }

    /// Gets the identifier for a peer in a specific session
    pub fn get_peer_identifier(&self, session_id: &SessionId, peer_id: &PeerId) -> Result<Option<Identifier>, PeerMapperError> {
        let public_key = self.peers.get(peer_id)
            .ok_or(PeerMapperError::PeerNotFound)?;
        
        self.get_identifier_by_public_key(session_id, public_key)
    }

    /// Gets the identifier for a public key in a specific session
    pub fn get_identifier_by_public_key(&self, session_id: &SessionId, public_key: &TSSPublic) -> Result<Option<Identifier>, PeerMapperError> {
        // First try to get the validator ID
        if let Ok(Some(validator_id)) = self.get_validator_id(public_key) {
            return Ok(Some(self.validator_id_to_identifier(validator_id)?));
        }
        
        // Fall back to searching in the session participants
        let sessions_participants = self.sessions_participants
            .lock()
            .map_err(|_| PeerMapperError::LockError)?;
        
        let session = sessions_participants.get(session_id)
            .ok_or(PeerMapperError::SessionNotFound)?;

        log::debug!(
            "[TSS] get_identifier_by_public_key({:?}, {:?}) from session = {:?}",
            session_id,
            public_key,
            session
        );

        let identifier = session
            .iter()
            .find_map(|(id, key)| if key == public_key { Some(*id) } else { None });

        Ok(identifier)
    }

    /// Gets the peer ID for an identifier in a specific session
    pub fn get_peer_by_identifier(&self, session_id: &SessionId, identifier: &Identifier) -> Result<Option<PeerId>, PeerMapperError> {
        let sessions_participants = self.sessions_participants
            .lock()
            .map_err(|_| PeerMapperError::LockError)?;
        
        let session = sessions_participants.get(session_id)
            .ok_or(PeerMapperError::SessionNotFound)?;

        if let Some(public_key) = session.get(identifier) {
            Ok(self.get_peer_id_by_public_key(public_key).copied())
        } else {
            Ok(None)
        }
    }

    /// Converts a validator ID to a Frost Identifier
    fn validator_id_to_identifier(&self, validator_id: u32) -> Result<Identifier, PeerMapperError> {
        let id_u16 = u16::try_from(validator_id)
            .map_err(|_| PeerMapperError::InvalidValidatorId)?;
        
        id_u16.try_into()
            .map_err(|_| PeerMapperError::InvalidValidatorId)
    }

    /// Gets all peers in a session
    pub fn get_session_peers(&self, session_id: &SessionId) -> Result<Vec<PeerId>, PeerMapperError> {
        let sessions_participants = self.sessions_participants
            .lock()
            .map_err(|_| PeerMapperError::LockError)?;
        
        let session = sessions_participants.get(session_id)
            .ok_or(PeerMapperError::SessionNotFound)?;

        let mut peers = Vec::new();
        for public_key in session.values() {
            if let Some(peer_id) = self.get_peer_id_by_public_key(public_key) {
                peers.push(*peer_id);
            }
        }

        Ok(peers)
    }

    /// Checks if a peer is part of a session
    pub fn is_peer_in_session(&self, session_id: &SessionId, peer_id: &PeerId) -> Result<bool, PeerMapperError> {
        match self.get_peer_identifier(session_id, peer_id) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(PeerMapperError::PeerNotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Gets the number of participants in a session
    pub fn get_session_size(&self, session_id: &SessionId) -> Result<usize, PeerMapperError> {
        let sessions_participants = self.sessions_participants
            .lock()
            .map_err(|_| PeerMapperError::LockError)?;
        
        let session = sessions_participants.get(session_id)
            .ok_or(PeerMapperError::SessionNotFound)?;

        Ok(session.len())
    }

    /// Removes a session
    pub fn remove_session(&self, session_id: &SessionId) -> Result<bool, PeerMapperError> {
        let mut sessions_participants = self.sessions_participants
            .lock()
            .map_err(|_| PeerMapperError::LockError)?;
        
        Ok(sessions_participants.remove(session_id).is_some())
    }

    /// Gets all active session IDs
    pub fn get_active_sessions(&self) -> Result<Vec<SessionId>, PeerMapperError> {
        let sessions_participants = self.sessions_participants
            .lock()
            .map_err(|_| PeerMapperError::LockError)?;
        
        Ok(sessions_participants.keys().copied().collect())
    }

    // Legacy methods for backward compatibility - these can be deprecated later
    
    #[deprecated(note = "Use get_peer_public_key instead")]
    pub fn _get_account_id_from_peer_id(&mut self, peer_id: &PeerId) -> Option<&TSSPublic> {
        self.get_peer_public_key(peer_id)
    }

    #[deprecated(note = "Use get_peer_id_by_public_key instead")]
    pub fn get_peer_id_from_account_id(&mut self, account_id: &TSSPublic) -> Option<&PeerId> {
        self.get_peer_id_by_public_key(account_id)
    }

    #[deprecated(note = "Use get_peer_by_identifier instead")]
    pub fn get_peer_id_from_identifier(&mut self, session_id: &SessionId, identifier: &Identifier) -> Option<PeerId> {
        self.get_peer_by_identifier(session_id, identifier).ok().flatten()
    }

    #[deprecated(note = "Use get_peer_identifier instead")]
    pub fn get_identifier_from_peer_id(&mut self, session_id: &SessionId, peer_id: &PeerId) -> Option<Identifier> {
        self.get_peer_identifier(session_id, peer_id).ok().flatten()
    }

    #[deprecated(note = "Use get_identifier_by_public_key instead")]
    pub fn get_identifier_from_account_id(&mut self, session_id: &SessionId, account_id: &TSSPublic) -> Option<Identifier> {
        self.get_identifier_by_public_key(session_id, account_id).ok().flatten()
    }

    #[deprecated(note = "Use get_public_key_by_validator_id instead")]
    pub fn _get_validator_account_from_id(&mut self, id: u32) -> Option<TSSPublic> {
        self.get_public_key_by_validator_id(id).ok().flatten()
    }

    // Additional methods needed for backward compatibility with existing code
    
    pub fn get_peer_id_from_id(&mut self, session_id: &SessionId, id: u16) -> Option<PeerId> {
        self.validator_id_to_identifier(id as u32)
            .ok()
            .and_then(|identifier| self.get_peer_id_from_identifier(session_id, &identifier))
    }

    pub fn get_id_from_peer_id(&mut self, session_id: &SessionId, peer_id: &PeerId) -> Option<u16> {
        if let Some(public_key) = self.peers.get(peer_id) {
            if let Ok(Some(validator_id)) = self.get_validator_id(public_key) {
                return u16::try_from(validator_id).ok();
            }
        }
        None
    }

    pub fn get_id_from_account_id(&mut self, session_id: &SessionId, account_id: &TSSPublic) -> Option<u16> {
        if let Ok(Some(validator_id)) = self.get_validator_id(account_id) {
            return u16::try_from(validator_id).ok();
        }
        None
    }

    pub fn set_validator_id_mut(&mut self, public_key: TSSPublic, id: u32) {
        let _ = self.set_validator_id(public_key, id);
    }

    pub fn add_peer_mut(&mut self, peer_id: PeerId, public_key_data: TSSPublic) {
        let _ = self.add_peer(peer_id, public_key_data);
    }

    pub fn create_session_mut(&mut self, session_id: SessionId, participants: Vec<TSSParticipant>) {
        let _ = self.create_session(session_id, participants);
    }

    // Getter for sessions_participants to maintain compatibility
    pub fn sessions_participants(&self) -> &Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>> {
        &self.sessions_participants
    }

    // Direct access to peers for compatibility
    pub fn peers(&self) -> &HashMap<PeerId, TSSPublic> {
        &self.peers
    }

    pub fn peers_mut(&mut self) -> &mut HashMap<PeerId, TSSPublic> {
        &mut self.peers
    }
}
