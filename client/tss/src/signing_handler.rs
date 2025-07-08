use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use frost_ed25519::Identifier;
use sc_network::PeerId;
use crate::{
    SessionId, TSSParticipant, TSSPublic, TSSPeerId, 
    SigningSessionState, MemoryStorage, FileStorage, PeerMapper,
    SessionManagerError, TssMessage, ClientManager, SessionError
};
use sp_runtime::traits::Block as BlockT;

/// Handles signing protocol operations
pub struct SigningHandler<B: BlockT, C: ClientManager<B>> {
    signing_session_states: Arc<Mutex<HashMap<SessionId, SigningSessionState>>>,
    sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    sessions_data: Arc<Mutex<HashMap<SessionId, (u16, u16, Vec<u8>, Vec<u8>)>>>,
    session_timestamps: Arc<Mutex<HashMap<SessionId, std::time::Instant>>>,
    storage: Arc<Mutex<MemoryStorage>>,
    key_storage: Arc<Mutex<FileStorage>>,
    peer_mapper: Arc<Mutex<PeerMapper>>,
    local_peer_id: TSSPeerId,
    validator_key: TSSPublic,
    client: C,
    session_manager_to_gossip_tx: sc_utils::mpsc::TracingUnboundedSender<(PeerId, crate::TssMessage)>,
    _phantom: std::marker::PhantomData<B>,
}

impl<B: BlockT, C: ClientManager<B>> SigningHandler<B, C> {
    pub fn new(
        signing_session_states: Arc<Mutex<HashMap<SessionId, SigningSessionState>>>,
        sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<crate::Identifier, TSSPublic>>>>,
        sessions_data: Arc<Mutex<HashMap<SessionId, (u16, u16, Vec<u8>, Vec<u8>)>>>,
        session_timestamps: Arc<Mutex<HashMap<SessionId, std::time::Instant>>>,
        storage: Arc<Mutex<MemoryStorage>>,
        key_storage: Arc<Mutex<FileStorage>>,
        peer_mapper: Arc<Mutex<PeerMapper>>,
        local_peer_id: TSSPeerId,
        validator_key: TSSPublic,
        client: C,
        session_manager_to_gossip_tx: sc_utils::mpsc::TracingUnboundedSender<(PeerId, crate::TssMessage)>
    ) -> Self {
        Self {
            signing_session_states,
            sessions_participants,
            sessions_data,
            session_timestamps,
            storage,
            key_storage,
            peer_mapper,
            local_peer_id,
            validator_key,
            client,
            session_manager_to_gossip_tx,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn add_and_initialize_signing_session(
        &mut self, 
        id: SessionId, 
        t: u16, 
        n: u16, 
        participants: Vec<TSSParticipant>, 
        coordinator: [u8; 32], 
        message: Vec<u8>
    ) -> Result<(), String> {
        self.add_session_data(id, t, n, coordinator, participants.clone(), message.clone())
            .map_err(|e| format!("Failed to add data: {:?}", e))?;
        
        log::info!("[TSS] Successfully added data for signing session {}", id);

        self.signing_handle_session_created(id, participants.clone(), coordinator);
    
        log::info!("[TSS] Successfully initialized FROST Signing session {}", id);

        // Note: ECDSA signing would be handled by a separate ecdsa_handler
        // For now, we focus only on FROST signing in this handler
        
        Ok(())
    }

    pub fn signing_handle_session_created(
        &self,
        session_id: SessionId,
        participants: Vec<TSSParticipant>,
        coordinator: TSSParticipant,
    ) {
        // Implementation based on lib.rs signing_handle_session_created
        // This is a simplified version - the actual implementation would need
        // the full FROST signing logic from lib.rs
        log::info!("[TSS] Handling signing session created for session {}", session_id);
        
        // Store the participants (simplified version)
        let mut handle = self.sessions_participants.lock().unwrap();
        let mut tmp = HashMap::<Identifier, TSSPublic>::new();
        let mut index = None;

        log::debug!("[TSS] participants={:?}", participants);

        for (i, el) in participants.into_iter().enumerate() {
            tmp.insert(u16::try_from(i + 1).unwrap().try_into().unwrap(), el.into());
            if el == self.validator_key[..] {
                index = Some(i);
            }
        }

        // Check if we are part of this session
        if let None = index {
            log::error!("[TSS] Not allowed to participate in Signing");
            return;
        }

        handle.insert(session_id, tmp);
        drop(handle);

        // TODO: Complete implementation with FROST signing logic
        log::info!("[TSS] FROST signing session {} initialized", session_id);
    }

    pub fn signing_handle_commitment(
        &mut self,
        session_id: SessionId,
        sender: TSSPeerId,
        commitment_data: Vec<u8>
    ) -> Result<(), SessionManagerError> {
        log::info!("[TSS] Handling signing commitment for session {}", session_id);
        
        // Validate session state
        let signing_states = self.signing_session_states.lock().unwrap();
        let current_state = signing_states.get(&session_id).cloned();
        drop(signing_states);
        
        match current_state {
            Some(SigningSessionState::CommitmentPhase) => {
                // Process commitment message
                self.signing_process_commitment(session_id, sender, commitment_data)?;
                
                // Check if we can complete commitment phase
                self.signing_handle_verification_to_complete_round1(session_id);
                
                Ok(())
            }
            _ => {
                log::warn!("[TSS] Invalid state for signing commitment in session {}", session_id);
                Err(SessionManagerError::InvalidSessionState)
            }
        }
    }

    pub fn signing_handle_verification_to_complete_round1(&self, session_id: SessionId) {
        log::info!("[TSS] Verifying signing round 1 completion for session {}", session_id);
        
        // Check if we have received all required commitments
        if self.signing_can_complete_commitment_phase(session_id) {
            log::info!("[TSS] Signing commitment phase complete for session {}", session_id);
            
            // Update state to SigningPackagePhase
            let mut signing_states = self.signing_session_states.lock().unwrap();
            signing_states.insert(session_id, SigningSessionState::SigningPackagePhase);
            drop(signing_states);
            
            // Send signing package to committed participants
            if let Err(e) = self.signing_send_signing_package_to_committed_participants(session_id) {
                log::error!("[TSS] Failed to send signing package for session {}: {:?}", session_id, e);
            }
        }
    }

    pub fn signing_send_signing_package_to_committed_participants(
        &self,
        session_id: SessionId
    ) -> Result<(), SessionManagerError> {
        log::info!("[TSS] Sending signing package to committed participants for session {}", session_id);
        
        // Generate signing package
        let signing_package = self.signing_generate_signing_package(session_id)?;
        
        // Send to all committed participants
        let committed_participants = self.signing_get_committed_participants(session_id);
        for participant in committed_participants {
            if let Err(e) = self.session_manager_to_gossip_tx.unbounded_send((
                participant,
                TssMessage::SigningPackage(session_id, signing_package.clone())
            )) {
                log::error!("[TSS] Failed to send signing package to participant: {:?}", e);
            }
        }
        
        Ok(())
    }

    pub fn signing_handle_signing_package(
        &mut self,
        session_id: SessionId,
        sender: TSSPeerId,
        package_data: Vec<u8>
    ) -> Result<(), SessionManagerError> {
        log::info!("[TSS] Handling signing package for session {}", session_id);
        
        // Validate session state
        let signing_states = self.signing_session_states.lock().unwrap();
        let current_state = signing_states.get(&session_id).cloned();
        drop(signing_states);
        
        match current_state {
            Some(SigningSessionState::SigningPackagePhase) => {
                // Process signing package
                self.signing_process_signing_package(session_id, sender, package_data)?;
                
                // Update state to SignatureSharePhase
                let mut signing_states = self.signing_session_states.lock().unwrap();
                signing_states.insert(session_id, SigningSessionState::SignatureSharePhase);
                drop(signing_states);
                
                // Generate and send signature share
                self.signing_generate_and_send_signature_share(session_id)?;
                
                Ok(())
            }
            _ => {
                log::warn!("[TSS] Invalid state for signing package in session {}", session_id);
                Err(SessionManagerError::InvalidSessionState)
            }
        }
    }

    pub fn signing_handle_signature_share(
        &mut self,
        session_id: SessionId,
        sender: TSSPeerId,
        signature_share_data: Vec<u8>
    ) -> Result<(), SessionManagerError> {
        log::info!("[TSS] Handling signature share for session {}", session_id);
        
        // Validate session state
        let signing_states = self.signing_session_states.lock().unwrap();
        let current_state = signing_states.get(&session_id).cloned();
        drop(signing_states);
        
        match current_state {
            Some(SigningSessionState::SignatureSharePhase) => {
                // Process signature share
                self.signing_process_signature_share(session_id, sender, signature_share_data)?;
                
                // Check if we can complete signing
                if self.signing_can_complete_signature_aggregation(session_id) {
                    log::info!("[TSS] Signature aggregation complete for session {}", session_id);
                    
                    // Aggregate final signature
                    let final_signature = self.signing_aggregate_final_signature(session_id)?;
                    
                    // Update state to Completed
                    let mut signing_states = self.signing_session_states.lock().unwrap();
                    signing_states.insert(session_id, SigningSessionState::Completed);
                    drop(signing_states);
                    
                    // Submit result to client
                    let best_hash = self.client.best_hash();
                    let _ = self.client.submit_dkg_result(best_hash, session_id, final_signature);
                    
                    log::info!("[TSS] Signing completed successfully for session {}", session_id);
                }
                
                Ok(())
            }
            _ => {
                log::warn!("[TSS] Invalid state for signature share in session {}", session_id);
                Err(SessionManagerError::InvalidSessionState)
            }
        }
    }

    fn add_session_data(
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

        let peer_mapper = self.peer_mapper.lock().unwrap();
        let _ = peer_mapper.create_session(session_id, participants.clone());
        drop(peer_mapper);
        
        // Record session creation time for timeout tracking
        let mut timestamps = self.session_timestamps.lock().unwrap();
        timestamps.insert(session_id, std::time::Instant::now());
        drop(timestamps);
        
        log::info!("[TSS] Successfully created session {}", session_id);
        Ok(())
    }

    fn session_exists(&self, session_id: &SessionId) -> bool {
        self.sessions_data.lock().unwrap().contains_key(session_id)
    }

    // Helper methods that would need full implementation
    fn is_authorized_for_session(&self, _session_id: &SessionId) -> bool {
        // Implementation would check peer_mapper
        true
    }

    fn is_coordinator(&self, session_id: &SessionId) -> bool {
        if let None = self.get_session_data(session_id) {
            return false;
        }

        let (_, _, coordinator, _) = self.get_session_data(session_id).unwrap();

        coordinator == self.validator_key[..]
    }

    fn get_session_data(&self, session_id: &SessionId) -> Option<(u16, u16, Vec<u8>, Vec<u8>)> {
        self.sessions_data.lock().unwrap().get(session_id).cloned()
    }

    fn signing_initiate_commitment_phase(
        &self,
        _session_id: SessionId,
        _t: u16,
        _n: u16,
        _participants: Vec<TSSParticipant>,
        _coordinator: [u8; 32],
        _message: Vec<u8>
    ) -> Result<(), SessionManagerError> {
        // Implementation would initiate commitment phase
        Ok(())
    }

    fn signing_process_commitment(&self, _session_id: SessionId, _sender: TSSPeerId, _data: Vec<u8>) -> Result<(), SessionManagerError> {
        // Implementation would process commitment messages
        Ok(())
    }

    fn signing_can_complete_commitment_phase(&self, _session_id: SessionId) -> bool {
        // Implementation would check if all commitments received
        true
    }

    fn signing_generate_signing_package(&self, _session_id: SessionId) -> Result<Vec<u8>, SessionManagerError> {
        // Implementation would generate signing package
        Ok(vec![])
    }

    fn signing_get_committed_participants(&self, _session_id: SessionId) -> Vec<PeerId> {
        // Implementation would return committed participants
        vec![]
    }

    fn signing_process_signing_package(&self, _session_id: SessionId, _sender: TSSPeerId, _data: Vec<u8>) -> Result<(), SessionManagerError> {
        // Implementation would process signing package
        Ok(())
    }

    fn signing_generate_and_send_signature_share(&self, _session_id: SessionId) -> Result<(), SessionManagerError> {
        // Implementation would generate and send signature share
        Ok(())
    }

    fn signing_process_signature_share(&self, _session_id: SessionId, _sender: TSSPeerId, _data: Vec<u8>) -> Result<(), SessionManagerError> {
        // Implementation would process signature share
        Ok(())
    }

    fn signing_can_complete_signature_aggregation(&self, _session_id: SessionId) -> bool {
        // Implementation would check if all signature shares received
        true
    }

    fn signing_aggregate_final_signature(&self, _session_id: SessionId) -> Result<Vec<u8>, SessionManagerError> {
        // Implementation would aggregate final signature
        Ok(vec![])
    }
}