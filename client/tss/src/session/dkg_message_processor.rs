use crate::{
    client::ClientManager,
    dkg_session,
    dkghelpers::StorageType,
    types::{SessionId, SessionManagerError, TSSParticipant, TSSPeerId, TSSPublic},  
    SessionManager,
    session::{DKGSessionState, SessionError},
    empty_hash_map,
};
use frost_ed25519::{
    keys::dkg::{
        round1::{Package, SecretPackage},
        round2,
    },
    Identifier,
};
use sc_network::PeerId;
use sp_runtime::traits::Block as BlockT;
use std::collections::BTreeMap;
use uomi_runtime::pallet_tss::TssOffenceType;
use crate::dkghelpers::Storage;

impl<B: BlockT, C: ClientManager<B>> SessionManager<B, C> {
    
    pub fn dkg_handle_round1_message(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        sender: PeerId,
    ) -> Result<(), SessionManagerError> {
        let current_state = self.state_managers.dkg_state_manager.get_state(&session_id);

        // STEP 1: For sure, we need to store the message for later use.
        let mut storage = self.storage_manager.storage.lock().unwrap();

        let mut peer_mapper_handle = self.session_core.peer_mapper.lock().unwrap();

        let identifier = peer_mapper_handle.get_identifier_from_peer_id(&session_id, &sender);

        log::info!(
            "[TSS] Apparently peer_id = {:?} is associated with identifier = {:?}",
            sender,
            identifier
        );

        if let None = identifier {
            log::warn!(
                "[TSS]: Couldn't find identifier fo Session {} and peer_id {:?}. Ignoring message.",
                session_id,
                sender
            );

            return Err(SessionManagerError::IdentifierNotFound);
        }

        let identifier = identifier.unwrap();
        log::info!(
            "[TSS] Stored received message from identifier {:?}",
            identifier.clone()
        );
        storage.store_round1_packages(session_id, identifier, &bytes[..]);
        drop(peer_mapper_handle);

        // STEP 2: If we haven't started yet, wait for our time to come
        // This can happen for example if someone received the event from the pallet before us and has
        // already started. Should be handled gracefulyl
        if current_state < DKGSessionState::Round1Initiated {
            // Only process if we've initiated Round 1
            log::warn!(
                "[TSS]: Received DKGRound1 for session {} but local state is {:?}. Ignoring message.",
                session_id,
                current_state
            );
            return Err(SessionManagerError::SessionNotYetInitiated);
        }

        drop(storage);

        log::info!("[TSS] calling handle_verification_to_complete_round1()");
        self.dkg_handle_verification_to_complete_round1(session_id);

        Ok(())
    }

    fn dkg_handle_verification_to_complete_round1(&self, session_id: SessionId) {
        let storage = self.storage_manager.storage.lock().unwrap();

        // This should not actually happen since the state is updated when we store the secret package from round 1
        // but you never know...
        let data = storage.read_secret_package_round1(session_id);

        if let Err(_e) = data {
            log::warn!(
                "[TSS]: Received DKGRound1 for session {} but local round 1 data not ready yet. Ignoring message.",
                session_id
            );
            return; // Ignore if local data not ready (should not happen with state check)
        }

        let data = data.unwrap();
        let n = data.max_signers();

        let round1_packages = storage.fetch_round1_packages(session_id).unwrap();
        drop(storage); // Release lock

        log::info!("[TSS] debug round1_packages = {:?}", round1_packages);

        if round1_packages.keys().len() >= (n - 1).into() {
            self.dkg_verify_and_start_round2(session_id, data, round1_packages)
        }
    }

    fn dkg_verify_and_start_round2(
        &self,
        session_id: SessionId,
        round1_secret_package: SecretPackage, // Pass the secret package directly
        round1_packages: BTreeMap<Identifier, Package>,
    ) {
        match dkg_session::round2_verify_round1_participants(
            session_id,
            round1_secret_package,
            &round1_packages,
        ) {
            Err(e) => {
                log::error!(
                    "[TSS]: Error in round2_verify_round1_participants for session {}: {:?}",
                    session_id,
                    e
                );
                // Update session state to Failed
                self.state_managers.dkg_state_manager.set_state(session_id, DKGSessionState::Failed);
                
                // Report cryptographic failure for slashing - report all participants that submitted round1 packages
                // since we can't determine which specific participant caused the verification failure
                let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
                let mut offenders = Vec::new();
                
                for identifier in round1_packages.keys() {
                    if let Some(account_id) = peer_mapper.get_account_id_from_identifier(&session_id, identifier) {
                        if let Ok(account_bytes) = account_id.as_slice().try_into() {
                            offenders.push(account_bytes);
                        }
                    }
                }
                drop(peer_mapper);
                
                if !offenders.is_empty() {
                    let best_hash = self.client.best_hash();
                    if let Err(e) = self.client.report_tss_offence(best_hash, session_id, TssOffenceType::InvalidCryptographicData, offenders) {
                        log::error!("[TSS] Failed to report InvalidCryptographicData offence for session {}: {:?}", session_id, e);
                    } else {
                        log::info!("[TSS] Successfully reported InvalidCryptographicData offence for session {} for round1 verification failure", session_id);
                    }
                }
            }
            Ok((secret, round2_packages)) => {
                log::info!("[TSS] Round 1 Verification completed. Continuing now with Round 2");
                // Update session state to Round1Completed
                self.state_managers.dkg_state_manager.set_state(session_id, DKGSessionState::Round1Completed);
                log::info!("[TSS] 1");

                let empty = empty_hash_map();
                let handle_participants = self.participant_manager.sessions_participants.lock().unwrap();
                let participants = handle_participants.get(&session_id).unwrap_or(&empty); // Use HashMap::new() directly
                log::info!("[TSS] 2");

                for (identifier, package) in round2_packages {
                    let account_id = participants.get(&identifier);

                    if let None = account_id {
                        log::error!(
                            "[TSS]: Account ID not found for identifier {:?} in session {}",
                            identifier,
                            session_id
                        );
                        continue; // Handle error???
                    }

                    if *(account_id.unwrap()) == self.session_core.validator_key {
                        // don't send stuff to yourself
                        log::info!(
                            "[TSS] Skipping message to myself for session {}",
                            session_id
                        );
                        continue;
                    }
                    log::info!("[TSS] 3");

                    let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
                    if let Some(peer_id) =
                        peer_mapper.get_peer_id_from_account_id(account_id.unwrap())
                    {
                        log::info!("[TSS] 4");
                        let dkg_message = crate::types::TssMessage::DKGRound2(
                            session_id,
                            package.serialize().unwrap(),
                            peer_id.to_bytes(),
                        );
                        if let Err(e) = self.send_signed_message(dkg_message) {
                            log::error!("[TSS] Failed to send DKGRound2 message: {:?}", e);
                        }
                    } else {
                        log::error!("[TSS] PeerID not found, cannot send message")
                    }
                    log::info!("[TSS] 5");

                    drop(peer_mapper);
                }
                drop(handle_participants);
                log::info!("[TSS] 6");
                let mut storage = self.storage_manager.storage.lock().unwrap();
                storage
                    .store_data(
                        session_id,
                        crate::dkghelpers::StorageType::DKGRound2SecretPackage,
                        &(secret.serialize().unwrap()),
                        None,
                    )
                    .unwrap();
                drop(storage);
                log::info!("[TSS] 7");

                // Update session state to Round2Initiated after sending Round2 messages
                self.state_managers.dkg_state_manager.set_state(session_id, DKGSessionState::Round2Initiated);
                // drop(session_state_lock);
                log::info!("[TSS] 8");

                // This is not gonna happen but just in case
                if let Err(e) = self.dkg_verify_and_complete(session_id) {
                    log::error!(
                        "[TSS] There was an error verifying Round2 to complete DKG {:?}",
                        e
                    )
                }
            }
        };
    }

    pub fn dkg_handle_round2_message(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        recipient: &TSSPeerId,
        sender: PeerId,
    ) -> Result<(), SessionManagerError> {
        let current_state = self.state_managers.dkg_state_manager.get_state(&session_id);

        if current_state < DKGSessionState::Round2Initiated {
            // Only process if we've initiated Round 2
            log::warn!(
                "[TSS]: Received DKGRound2 for session {} but local state is {:?}. Ignoring message.",
                session_id,
                current_state
            );

            return Err(SessionManagerError::Round2SecretPackageNotYetAvailable);
        }

        if self.session_core.local_peer_id != recipient[..] {
            log::warn!(
                "[TSS]: Received DKGRound2 for session {} for peer {:?} but it's not for us ({:?}). Ignoring message.",
                session_id, PeerId::from_bytes(&recipient), self.session_core.local_peer_id
            );
            return Ok(());
        }

        let mut storage = self.storage_manager.storage.lock().unwrap();

        let mut peer_mapper_handle = self.session_core.peer_mapper.lock().unwrap();

        let identifier = peer_mapper_handle.get_identifier_from_peer_id(&session_id, &sender);

        if let None = identifier {
            // this can never happen, but we handle it anyway.
            log::warn!(
                "[TSS]: Couldn't find identifier fo Session {} and peer_id {:?}. Ignoring message.",
                session_id,
                sender
            );

            return Err(SessionManagerError::IdentifierNotFound);
        }

        let identifier = identifier.unwrap();

        if let Err(e) = round2::Package::deserialize(&bytes[..]) {
            log::error!(
                "[TSS] Error {:?} Invalid data received as DKGRound2 = {:?}",
                e,
                bytes
            );
            
            // Report InvalidCryptographicData offence for the sender
            let best_hash = self.client.best_hash();
            // Convert peer id to account_id using the peer_mapper 
            let account_id = peer_mapper_handle
                .get_account_id_from_peer_id(&sender);

            if let None = account_id {
                log::error!("[TSS] Account ID not found for sender {:?}", sender);
                return Err(SessionManagerError::IdentifierNotFound);
            }

            let offenders: Vec<[u8; 32]> = vec![account_id.unwrap().as_slice().try_into().unwrap()];

            if let Err(e) = self.client.report_tss_offence(best_hash, session_id, TssOffenceType::InvalidCryptographicData, offenders) {
                log::error!("[TSS] Failed to report InvalidCryptographicData offence for session {}: {:?}", session_id, e);
            } else {
                log::info!("[TSS] Successfully reported InvalidCryptographicData offence for session {} for sender {:?}", session_id, sender);
            }
            
            return Err(SessionManagerError::DeserializationError);
        }
        storage.store_round2_packages(session_id, identifier, &bytes[..]);

        drop(peer_mapper_handle);
        drop(storage);

        if let Err(e) = self.dkg_verify_and_complete(session_id) {
            log::error!(
                "[TSS] There was an error verifying Round2 to complete DKG {:?}",
                e
            )
        }

        return Ok(());
    }

    fn dkg_verify_and_complete(&self, session_id: SessionId) -> Result<(), SessionManagerError> {
        // Process the buffered messages before checking anything else
        self.dkg_process_buffer_for_round2(session_id);

        // Use the extracted DKG session completion module
        match dkg_session::verify_and_complete(
            session_id,
            self.storage_manager.storage.clone(),
            self.storage_manager.key_storage.clone(),
            self.state_managers.dkg_state_manager.dkg_session_states.clone(),
            self.session_core.peer_mapper.clone(),
            &self.session_core.validator_key,
        ) {
            Ok(_) => {
                log::info!("[TSS] DKG session {} completed successfully", session_id);
            }
            Err(SessionManagerError::DkgPart3Failed(_)) => {
                // Handle DKG part 3 failure with offence reporting
                let storage = self.storage_manager.storage.lock().unwrap();
                let round2_packages = storage.fetch_round2_packages(session_id).unwrap();
                drop(storage);
                
                // Report DKG failure - report all participants that submitted round2 packages
                // since we can't determine which specific participant caused the verification failure
                let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
                let mut offenders = Vec::new();
                
                for identifier in round2_packages.keys() {
                    if let Some(account_id) = peer_mapper.get_account_id_from_identifier(&session_id, identifier) {
                        if let Ok(account_bytes) = account_id.as_slice().try_into() {
                            offenders.push(account_bytes);
                        }
                    }
                }
                drop(peer_mapper);
                
                if !offenders.is_empty() {
                    let best_hash = self.client.best_hash();
                    if let Err(e) = self.client.report_tss_offence(best_hash, session_id, uomi_runtime::pallet_tss::TssOffenceType::InvalidCryptographicData, offenders) {
                        log::error!("[TSS] Failed to report InvalidCryptographicData offence for session {}: {:?}", session_id, e);
                    } else {
                        log::info!("[TSS] Successfully reported InvalidCryptographicData offence for session {} for DKG part3 failure", session_id);
                    }
                }
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// Process a new DKG session creation
    pub fn dkg_handle_session_created(
        &self,
        session_id: SessionId,
        n: u64,
        t: u64,
        participants: Vec<TSSParticipant>,
    ) -> Result<(), SessionError>
    where
        B: BlockT,
    {
        // Use the extracted DKG session module
        let (r1, _secret) = dkg_session::handle_session_created(
            session_id,
            n,
            t,
            participants.clone(),
            &self.session_core.validator_key,
            self.storage_manager.storage.clone(),
            self.state_managers.dkg_state_manager.dkg_session_states.clone(),
        )?;

        // Send round 1 message
        let dkg_round1_message = crate::types::TssMessage::DKGRound1(session_id, r1.serialize().unwrap());
        match self.send_signed_message(dkg_round1_message) {
            Ok(_) => log::info!("[TSS] Signed Round 1 message broadcasted for session {}", session_id),
            Err(e) => {
                log::error!("[TSS] Failed to send signed round 1 message for session {}: {:?}", session_id, e);
                return Err(SessionError::GenericError(format!("Failed to send signed round 1 message: {:?}", e)));
            }
        }

        // Process any buffered messages for this session
        let mut handle = self.buffer.lock().unwrap();
        let entries = handle.entry(session_id).or_default().clone();
        drop(handle);

        for (peer_id, message) in entries {
            match message {
                crate::types::TssMessage::DKGRound1(_, bytes) => {
                    log::info!(
                        "[TSS] Processing buffered DKGRound1 message for session {} from peer_id {:?}",
                        session_id,
                        PeerId::from_bytes(&peer_id[..]).unwrap().to_base58()
                    );
                    if let Err(e) = self.dkg_handle_round1_message(
                        session_id,
                        &bytes,
                        PeerId::from_bytes(&peer_id[..]).unwrap(),
                    ) {
                        log::error!(
                            "[TSS] Error processing buffered DKGRound1 message for session {}: {:?}",
                            session_id,
                            e
                        );
                    }
                }
                _ => (), // ignore other message types for now
            }
        }

        // Try to complete round 1 if we have enough messages already
        self.dkg_handle_verification_to_complete_round1(session_id);
        
        Ok(())
    }

    pub fn dkg_process_buffer_for_round2(&self, session_id: SessionId) {
        let messages = {
            let mut buffer = self.buffer.lock().unwrap();
            buffer.entry(session_id).or_default().clone()
        };

        for (peer_id, message) in messages {
            // Process the (peer_id, message) pair without holding the lock
            match message {
                crate::types::TssMessage::DKGRound2(_, bytes, recipient) => {
                    log::info!(
                        "[TSS] Handling buffered message from peer_id {:?}",
                        PeerId::from_bytes(&peer_id[..]).unwrap().to_base58()
                    );
                    if let Err(e) = self.dkg_handle_round2_message(
                        session_id,
                        &bytes,
                        &recipient,
                        PeerId::from_bytes(&peer_id[..]).unwrap(),
                    ) {
                        log::error!(
                            "[TSS] There was an error while handling buffered message {:?}",
                            e
                        );
                    }
                }
                _ => (), // ignore the rest
            }
        }
    }
}