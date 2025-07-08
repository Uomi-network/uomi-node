use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use frost_ed25519::keys::dkg;
use frost_ed25519::{
    Identifier,
    keys::dkg::{
        round1::{Package, SecretPackage},
        round2,
    },
};
use sc_network::PeerId;
use crate::{
    SessionId, TSSParticipant, TSSPublic, TSSPeerId, 
    DKGSessionState, MemoryStorage, Storage, FileStorage, PeerMapper,
    SessionManagerError, TssMessage, ClientManager, dkground2, dkghelpers, empty_hash_map
};
use sp_runtime::traits::Block as BlockT;


/// Handles DKG (Distributed Key Generation) protocol operations
pub struct DKGHandler<B: BlockT> {
    dkg_session_states: Arc<Mutex<HashMap<SessionId, DKGSessionState>>>,
    sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    storage: Arc<Mutex<MemoryStorage>>,
    key_storage: Arc<Mutex<FileStorage>>,
    peer_mapper: Arc<Mutex<PeerMapper>>,
    local_peer_id: TSSPeerId,
    validator_key: TSSPublic,
    session_manager_to_gossip_tx: sc_utils::mpsc::TracingUnboundedSender<(PeerId, TssMessage)>,
    buffer: Arc<Mutex<HashMap<SessionId, Vec<(TSSPeerId, TssMessage)>>>>,
    _phantom: std::marker::PhantomData<B>,
}

impl<B: BlockT> DKGHandler<B> {
    pub fn new(
        dkg_session_states: Arc<Mutex<HashMap<SessionId, DKGSessionState>>>,
        sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
        storage: Arc<Mutex<MemoryStorage>>,
        key_storage: Arc<Mutex<FileStorage>>,
        peer_mapper: Arc<Mutex<PeerMapper>>,
        local_peer_id: TSSPeerId,
        validator_key: TSSPublic,
        session_manager_to_gossip_tx: sc_utils::mpsc::TracingUnboundedSender<(PeerId, TssMessage)>,
        buffer: Arc<Mutex<HashMap<SessionId, Vec<(TSSPeerId, TssMessage)>>>>,
        _phantom: std::marker::PhantomData<B>,
    ) -> Self {
        Self {
            dkg_session_states,
            sessions_participants,
            storage,
            key_storage,
            peer_mapper,
            local_peer_id,
            validator_key,
            session_manager_to_gossip_tx,
            buffer,
            _phantom,
        }
    }

    pub fn dkg_handle_round1_message(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        sender: PeerId,
    ) -> Result<(), SessionManagerError> {
        let session_state_lock = self.dkg_session_states.lock().unwrap();
        let current_state = session_state_lock
            .get(&session_id)
            .copied()
            .unwrap_or(DKGSessionState::Idle);
        drop(session_state_lock); // Release lock

        // STEP 1: For sure, we need to store the message for later use.
        let mut storage = self.storage.lock().unwrap();

        let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();

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
        let storage = self.storage.lock().unwrap();

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
        match dkground2::round2_verify_round1_participants(
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
                // Optionally handle failure state here, e.g., update session state to Failed
                let mut session_state_lock = self.dkg_session_states.lock().unwrap();
                session_state_lock.insert(session_id, DKGSessionState::Failed);
                drop(session_state_lock);
            }
            Ok((secret, round2_packages)) => {
                log::info!("[TSS] Round 1 Verification completed. Continuing now with Round 2");
                // Update session state to Round1Completed
                let mut session_state_lock = self.dkg_session_states.lock().unwrap();
                session_state_lock.insert(session_id, DKGSessionState::Round1Completed);
                drop(session_state_lock);
                log::info!("[TSS] 1");

                let empty = empty_hash_map();
                let handle_participants = self.sessions_participants.lock().unwrap();
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

                    if *(account_id.unwrap()) == self.validator_key {
                        // don't send stuff to yourself
                        log::info!(
                            "[TSS] Skipping message to myself for session {}",
                            session_id
                        );
                        continue;
                    }
                    log::info!("[TSS] 3");

                    let mut peer_mapper = self.peer_mapper.lock().unwrap();
                    if let Some(peer_id) =
                        peer_mapper.get_peer_id_from_account_id(account_id.unwrap())
                    {
                        log::info!("[TSS] 4");
                        let _ = self
                            .session_manager_to_gossip_tx
                            .unbounded_send((
                                peer_id.clone(),
                                TssMessage::DKGRound2(
                                    session_id,
                                    package.serialize().unwrap(),
                                    peer_id.to_bytes(),
                                ),
                            ))
                            .unwrap();
                    } else {
                        log::error!("[TSS] PeerID not found, cannot send message")
                    }
                    log::info!("[TSS] 5");

                    drop(peer_mapper);
                }
                drop(handle_participants);
                log::info!("[TSS] 6");
                let mut storage = self.storage.lock().unwrap();
                storage
                    .store_data(
                        session_id,
                        dkghelpers::StorageType::DKGRound2SecretPackage,
                        &(secret.serialize().unwrap()),
                        None,
                    )
                    .unwrap();
                drop(storage);
                log::info!("[TSS] 7");

                // Update session state to Round2Initiated after sending Round2 messages
                let mut session_state_lock = self.dkg_session_states.lock().unwrap();
                session_state_lock.insert(session_id, DKGSessionState::Round2Initiated);
                drop(session_state_lock);
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

    pub fn dkg_process_buffer_for_round2(&self, session_id: SessionId) {
        let messages = {
            let mut buffer = self.buffer.lock().unwrap();
            buffer.entry(session_id).or_default().clone()
        };

        for (peer_id, message) in messages {
            // Process the (peer_id, message) pair without holding the lock
            match message {
                TssMessage::DKGRound2(_, bytes, recipient) => {
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

    fn dkg_verify_and_complete(&self, session_id: SessionId) -> Result<(), SessionManagerError> {
        // Process the buffered messages before checking anything else
        self.dkg_process_buffer_for_round2(session_id);

        let storage = self.storage.lock().unwrap();

        let round2_secret_package = storage.read_secret_package_round2(session_id);
        if let Err(_e) = round2_secret_package {
            log::warn!(
                "[TSS]: Received DKGRound2 for session {} but local round 2 secret package not ready yet.",
                session_id
            );
            return Err(SessionManagerError::Round2SecretPackageNotYetAvailable);
        }
        let round2_secret_package = round2_secret_package.unwrap();

        let n = round2_secret_package.max_signers();

        let round1_packages = storage.fetch_round1_packages(session_id).unwrap();
        let round2_packages = storage.fetch_round2_packages(session_id).unwrap();
        drop(storage); // Release lock

        if round2_packages.keys().len() >= (n - 1).into() {
            match dkg::part3(&round2_secret_package, &round1_packages, &round2_packages) {
                Ok((private_key, public_key)) => {


                    let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();
                    let whoami_identifier = peer_mapper_handle.get_identifier_from_account_id(&session_id, &self.validator_key);

                    if let None = whoami_identifier {
                        log::error!("[TSS] We are not allowed to participate in the signing phase");
                        return Err(SessionManagerError::IdentifierNotFound);
                    }

                    drop(peer_mapper_handle);



                    let mut storage = self.key_storage.lock().unwrap();
                    let _ = storage.store_data(
                        session_id,
                        dkghelpers::StorageType::PubKey,
                        &public_key.serialize().unwrap()[..],
                        Some(&whoami_identifier.unwrap().serialize()),
                    );
                    if let Err(error) = storage.store_data(
                        session_id,
                        dkghelpers::StorageType::Key,
                        &private_key.serialize().unwrap()[..],
                        Some(&whoami_identifier.unwrap().serialize()),
                    ) {
                        log::error!("[TSS] There was an error storing key {:?}", error);
                    }
                    drop(storage);
                    log::info!(
                        "[TSS]: DKG Part 3 successful for session {}. Public Key: {:?}",
                        session_id,
                        public_key
                    );
                    // Update session state to KeyGenerated
                    let mut session_state_lock = self.dkg_session_states.lock().unwrap();
                    session_state_lock.insert(session_id, DKGSessionState::KeyGenerated);
                    drop(session_state_lock); // Release lock
                }
                Err(e) => {
                    log::error!(
                        "[TSS]: DKG Part 3 failed for session {}: {:?}",
                        session_id,
                        e
                    );
                    // Update session state to Failed
                    let mut session_state_lock = self.dkg_session_states.lock().unwrap();
                    session_state_lock.insert(session_id, DKGSessionState::Failed);
                    drop(session_state_lock); // Release lock
                }
            }
        }

        Ok(())
    }


    pub fn dkg_handle_round2_message(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        recipient: &TSSPeerId,
        sender: PeerId,
    ) -> Result<(), SessionManagerError> {
        let session_state_lock = self.dkg_session_states.lock().unwrap();
        let current_state = session_state_lock
            .get(&session_id)
            .copied()
            .unwrap_or(DKGSessionState::Idle);
        drop(session_state_lock); // Release lock

        if current_state < DKGSessionState::Round2Initiated {
            // Only process if we've initiated Round 2
            log::warn!(
                "[TSS]: Received DKGRound2 for session {} but local state is {:?}. Ignoring message.",
                session_id,
                current_state
            );

            return Err(SessionManagerError::Round2SecretPackageNotYetAvailable);
        }

        if self.local_peer_id != *recipient {
            log::warn!(
                "[TSS]: Received DKGRound2 for session {} for peer {:?} but it's not for us ({:?}). Ignoring message.",
                session_id, PeerId::from_bytes(&recipient), self.local_peer_id
            );
            return Ok(());
        }

        let mut storage = self.storage.lock().unwrap();

        let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();

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

    /// Handle the creation of a new DKG session
    pub fn dkg_handle_session_created(
        &self,
        session_id: SessionId,
        n: u64,
        t: u64,
        participants: Vec<TSSParticipant>,
    ) -> Result<(), crate::SessionError> {
        log::info!("[TSS] DKG session {} created with t={}, n={}, participants: {:?}", session_id, t, n, participants.len());

        // Store the participants
        let mut sessions_participants = self.sessions_participants.lock().unwrap();
        let mut participant_map = std::collections::HashMap::<Identifier, TSSPublic>::new();

        let mut my_index = None;

        // Map participants to identifiers (1-based indexing)
        for (i, participant) in participants.iter().enumerate() {
            let identifier: Identifier = u16::try_from(i + 1).unwrap().try_into().unwrap();
            participant_map.insert(identifier, participant.to_vec());

            // Check if we are part of this session
            if *participant == *self.validator_key {
                my_index = Some(i + 1);
            }
        }

        sessions_participants.insert(session_id, participant_map);
        drop(sessions_participants);

        // Check if we are authorized to participate
        if my_index.is_none() {
            log::warn!("[TSS] Not authorized to participate in DKG session {}", session_id);
            return Err(crate::SessionError::NotAuthorized);
        }

        let my_identifier: Identifier = u16::try_from(my_index.unwrap()).unwrap().try_into().unwrap();
        log::info!("[TSS] My identifier for session {}: {:?}", session_id, my_identifier);

        // Generate round 1 secret package
        match crate::dkground1::generate_round1_secret_package(
            t as u16,
            n as u16,
            my_identifier,
            session_id,
        ) {
            Ok((round1_package, round1_secret_package)) => {
                // Store our secret package
                let mut storage = self.storage.lock().unwrap();
                if let Err(e) = storage.store_data(
                    session_id,
                    crate::dkghelpers::StorageType::DKGRound1SecretPackage,
                    &round1_secret_package.serialize().unwrap(),
                    None,
                ) {
                    log::error!("[TSS] Failed to store round1 secret package: {:?}", e);
                    return Err(crate::SessionError::GenericError(format!("Storage error: {:?}", e)));
                }
                drop(storage);

                // Update session state to Round1Initiated
                let mut dkg_states = self.dkg_session_states.lock().unwrap();
                dkg_states.insert(session_id, crate::DKGSessionState::Round1Initiated);
                drop(dkg_states);

                // Broadcast round 1 package to other participants
                let serialized_package = round1_package.serialize().unwrap();
                
                let sessions_participants = self.sessions_participants.lock().unwrap();
                let participant_map = sessions_participants.get(&session_id).unwrap();
                
                for (identifier, participant_key) in participant_map.iter() {
                    // Don't send to ourselves
                    if *participant_key == self.validator_key {
                        continue;
                    }

                    let mut peer_mapper = self.peer_mapper.lock().unwrap();
                    if let Some(peer_id) = peer_mapper.get_peer_id_from_account_id(participant_key) {
                        if let Err(e) = self.session_manager_to_gossip_tx.unbounded_send((
                            peer_id.clone(),
                            crate::TssMessage::DKGRound1(session_id, serialized_package.clone()),
                        )) {
                            log::error!("[TSS] Failed to send DKGRound1 message to peer {:?}: {:?}", peer_id, e);
                        }
                    } else {
                        log::warn!("[TSS] Could not find peer_id for participant {:?}", participant_key);
                    }
                    drop(peer_mapper);
                }
                drop(sessions_participants);

                log::info!("[TSS] DKG session {} initiated successfully", session_id);
                Ok(())
            }
            Err(e) => {
                log::error!("[TSS] Failed to generate round1 secret package: {:?}", e);
                Err(crate::SessionError::GenericError(format!("DKG round1 generation failed: {:?}", e)))
            }
        }
    }
}