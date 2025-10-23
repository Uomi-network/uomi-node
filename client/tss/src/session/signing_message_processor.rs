use crate::{
    client::ClientManager,
    dkghelpers::StorageType,
    signing,
    types::{SessionId, SessionManagerError, TSSParticipant, TSSPeerId, TSSPublic},
    SessionManager,
    session::{SigningSessionState},
    empty_hash_map,
};
use frost_ed25519::{
    round1::SigningCommitments,
    round2::{sign as frost_round2_sign, SignatureShare},
    Identifier, Signature, SigningPackage,
};
use sc_network_types::PeerId;
use sp_runtime::traits::Block as BlockT;
use std::{
    collections::{btree_map::Keys, HashMap},
    num::TryFromIntError,
};
use uomi_runtime::pallet_tss::TssOffenceType;
use log::{info, debug, error};

use crate::dkghelpers::Storage;

impl<B: BlockT, C: ClientManager<B>> SessionManager<B, C> {
    
    pub fn signing_handle_session_created(
        &self,
        session_id: SessionId,
        participants: Vec<TSSParticipant>,
        coordinator: TSSParticipant,
    ) where
        B: BlockT,
    {
        // Store the participants using stable validator IDs as Identifiers
        let mut handle = self.participant_manager.sessions_participants.lock().unwrap();
        let mut tmp = HashMap::<Identifier, TSSPublic>::new();

        log::debug!("[TSS] participants={:?}", participants);

        let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
        for el in participants.into_iter() {
            if let Some(identifier) = peer_mapper.get_identifier_from_account_id(&session_id, &el.to_vec()) {
                tmp.insert(identifier, el.into());
            } else {
                log::warn!(
                    "[TSS] Could not resolve validator ID for participant during signing session {}",
                    session_id
                );
            }
        }
        drop(peer_mapper);

        // Ensure we are authorized (we must have an identifier)
        let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
        let whoami_identifier = peer_mapper.get_identifier_from_account_id(&session_id, &self.session_core.validator_key);
        drop(peer_mapper);

        if whoami_identifier.is_none() {
            log::error!("[TSS] Not allowed to participate in Signing (identifier not found)");
            return;
        }

        handle.insert(session_id, tmp);
        drop(handle);

        log::debug!("[TSS]: Event received from Signing, starting round 1");

    // Resolve underlying DKG session id for key material (may be same as signing session)
    let dkg_session_id = {
        let map = self.signing_to_dkg.lock().unwrap();
        *map.get(&session_id).unwrap_or(&session_id)
    };
    let key_storage = self.storage_manager.key_storage.lock().unwrap();
    let key_package = key_storage.get_key_package(dkg_session_id, &whoami_identifier.unwrap());

        if let Err(error) = key_package {
            log::error!("[TSS] Error fetching Key Package {:?}", error);
            return;
        }
        // Generate commitments and nonces from the key_package.signing_share()
        let (nonces, commitments) =
            signing::frost::generate_signing_commitments_and_nonces(key_package.unwrap());

        drop(key_storage);

        let mut storage = self.storage_manager.storage.lock().unwrap();
        // Store the nonces
        if let Err(error) = storage.store_data(
            session_id,
            StorageType::SigningNonces,
            &(nonces.serialize().unwrap()[..]),
            None,
        ) {
            log::error!("[TSS] Error storing nonces {:?}", error);
        }

        drop(storage);

        self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::Round1Initiated);

        // And send the commitment to our coordinator
        let mut peer_handle = self.session_core.peer_mapper.lock().unwrap();
        let peer_id = peer_handle.get_peer_id_from_account_id(&coordinator.to_vec());
        if let Some(peer_id) = peer_id {
            let signing_commitment_message = crate::types::TssMessage::SigningCommitmentP2p(session_id, commitments.serialize().unwrap(), peer_id.to_bytes());
            match self.send_signed_message(signing_commitment_message) {
                Err(error) => log::error!(
                    "[TSS] There was an error sending signed commitments to the coordinator {:?}",
                    error
                ),
                Ok(_) => {
                    // Update session state to Round1Completed
                    self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::Round1Completed);
                    log::debug!("[TSS] Setting Round1Completed");
                }
            }
        }
        drop(peer_handle);
    }

    pub fn signing_handle_commitment(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        sender: PeerId,
    ) -> Result<(), SessionManagerError> {
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
            "[TSS] Stored received commitment message from identifier {:?}",
            identifier.clone()
        );
        storage.store_commitment(session_id, identifier, &bytes[..]);
        drop(peer_mapper_handle);
        drop(storage);

        let current_state = self.state_managers.signing_state_manager.get_state(&session_id);

        if current_state >= SigningSessionState::Round2Completed {
            return Ok(());
        }

        if self.is_coordinator(&session_id) {
            log::debug!("[TSS] calling signing_handle_verification_to_complete_round1()");
            self.signing_handle_verification_to_complete_round1(session_id);
        }
        Ok(())
    }

    fn signing_handle_verification_to_complete_round1(&self, session_id: SessionId) {
        let storage = self.storage_manager.storage.lock().unwrap();

        let commitments = storage.fetch_commitments(session_id).unwrap();
        drop(storage); // Release lock

        log::debug!("[TSS] debug commitments = {:?}", commitments);

        let keys = commitments.keys();

        let session_data = self.session_core.sessions_data.lock().unwrap();

        let session_data = session_data.get(&session_id);

        if let None = session_data {
            log::error!("[TSS] Session doesn't exist");
            return;
        }
        let (t,_,_,message) = session_data.unwrap();

        if u16::try_from(keys.len()).unwrap() < *t {
            return;
        }
        
        let message = &message[..];

        let signing_package = signing::frost::get_signing_package(message, commitments.clone());

        self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::Round2Initiated);

        if let Err(error) = signing_package.serialize() {
            log::error!(
                "[TSS] There was an error serializing signing package {:?}",
                error
            );
        }

        let mut storage = self.storage_manager.storage.lock().unwrap();
        if let Err(error) = storage.store_data(
            session_id,
            StorageType::SigningPackage,
            &(signing_package.serialize().unwrap())[..],
            None,
        ) {
            log::error!(
                "[TSS] There was an error storing signing package {:?}",
                error
            );
        }

        self.signing_send_signing_package_to_committed_participants(
            session_id,
            signing_package,
            keys,
        );
    }

    fn signing_send_signing_package_to_committed_participants(
        &self,
        session_id: SessionId,
        signing_package: SigningPackage,
        committed: Keys<'_, Identifier, SigningCommitments>,
    ) {
        let mut peer_mapper_handle = self.session_core.peer_mapper.lock().unwrap();

        let signing_package = signing_package.serialize().unwrap();

        for identifier in committed {
            let peer_id = peer_mapper_handle.get_peer_id_from_identifier(&session_id, identifier);

            if let None = peer_id {
                // this shouldn't have happened
                log::error!(
                    "[TSS] PeerId Not Found In Session {:?} for Identifier {:?}",
                    session_id,
                    identifier
                );
                continue;
            }

            let peer_id = peer_id.unwrap(); // We already checked for None above
            let signing_package_message = crate::types::TssMessage::SigningPackageP2p(session_id.clone(), signing_package.clone(), peer_id.to_bytes());
            if let Err(error) = self.send_signed_message(signing_package_message) {
                log::error!(
                    "[TSS] There was an error sending signed signing package {:?}",
                    error
                );
                return;
                // what do we do? start over?
            }
        }
        self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::Round2Completed);
        log::debug!("[TSS] Setting Round2Completed");

        drop(peer_mapper_handle);
    }

    pub fn signing_handle_signing_package(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        _sender: PeerId,
    ) -> Result<(), SessionManagerError> {
        let signing_package = SigningPackage::deserialize(bytes);

        log::debug!("[TSS] Debug SigningPackage = {:?}", signing_package);

        log::debug!("[TSS] Handling signing package from coordinator");

        // Update session state to Round1Completed
        self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::Round2Initiated);

        if let Err(error) = signing_package {
            log::error!(
                "[TSS] There was an error deserializing the Signing Package {:?}",
                error
            );
            
            // Report InvalidCryptographicData offence for the sender
            let best_hash = self.client.best_hash();

            // Convert peer id to account_id using the peer_mapper
            let mut peer_mapper_guard = self.session_core.peer_mapper.lock().unwrap();
            let _sender = peer_mapper_guard
                .get_account_id_from_peer_id(&_sender)
                .cloned();
            drop(peer_mapper_guard);

            if let None = _sender {
                log::error!("[TSS] Account ID not found for sender {:?}", _sender);
                return Err(SessionManagerError::IdentifierNotFound);
            } 

            let offenders: Vec<[u8; 32]> = vec![_sender.unwrap().as_slice().try_into().unwrap()];
            if let Err(e) = self.client.report_tss_offence(best_hash, session_id, TssOffenceType::InvalidCryptographicData, offenders) {
                log::error!("[TSS] Failed to report InvalidCryptographicData offence for session {}: {:?}", session_id, e);
            } else {
                log::debug!("[TSS] Successfully reported InvalidCryptographicData offence for session {} ", session_id);
            }
            
            return Err(SessionManagerError::DeserializationError);
        }

        // STEP 1: For sure, we need to store the message for later use.
        let storage = self.storage_manager.storage.lock().unwrap();
        let nonces = storage.read_nonces(session_id);

        if let Err(error) = nonces {
            log::error!(
                "[TSS] There was an error fetching nonces from the storage {:?}",
                error
            );
        }

        let mut peer_mapper_handle = self.session_core.peer_mapper.lock().unwrap();
        let whoami_identifier = peer_mapper_handle.get_identifier_from_account_id(&session_id, &self.session_core.validator_key);

        log::debug!("[TSS] WHOAMI Id: {:?}", whoami_identifier);

        if let None = whoami_identifier {
            log::error!("[TSS] We are not allowed to participate in the signing phase");
            return Err(SessionManagerError::IdentifierNotFound);
        }
        let dkg_session_id = {
            let map = self.signing_to_dkg.lock().unwrap();
            *map.get(&session_id).unwrap_or(&session_id)
        };
        let key_storage = self.storage_manager.key_storage.lock().unwrap();
        let key_package = key_storage.get_key_package(dkg_session_id, &whoami_identifier.unwrap());
        drop(key_storage);
        drop(peer_mapper_handle);
        if let Err(error) = key_package {
            log::error!("[TSS] Error fetching the key package {:?}", error);
        }

        // If there are not enough signing commitments, we cannot proceed
        if (&signing_package.as_ref()).unwrap().signing_commitments().len() < (*(&key_package.as_ref()).unwrap().min_signers()).into() {
            log::debug!("[TSS] FROST round 2 signing requires at least {:?} signers, for now only {:?} provided", key_package.unwrap().min_signers(), signing_package.unwrap().signing_commitments().len());
            return Ok(());
        }

        // If this participant has not yet committed, we wait until he does:
        if let None = &signing_package.as_ref().unwrap()
            .signing_commitments()
            .get(&whoami_identifier.unwrap())
        {
            log::debug!("[TSS] Signing commitment not found for participant {:?}, waiting...", whoami_identifier.unwrap());
            return Ok(());
        }

        let signature_share = frost_round2_sign(
            &signing_package.unwrap(),
            &nonces.unwrap(),
            &key_package.unwrap(),
        )
        .unwrap();

        log::debug!("[TSS] Signature share generated, ready to send");

        drop(storage);

        let data = self.get_session_data(&session_id);
        
        if let None = data {
            log::error!("[TSS] No data found in Storage");
        }

        let (_, _, coordinator, _) = data.unwrap();

        log::debug!("Coordinator = {:?}", coordinator.clone());

        let mut peer_mapper_handle = self.session_core.peer_mapper.lock().unwrap();

        let coordinator = peer_mapper_handle.get_peer_id_from_account_id(&coordinator);

        if let Some(coordinator) = coordinator {
            log::debug!("I found that coordinator is associated with peer_id = {:?}", coordinator);
            let signing_share_message = crate::types::TssMessage::SigningShareP2p(session_id, signature_share.serialize(), coordinator.to_bytes());
            match self.send_signed_message(signing_share_message) {
                Err(error) => log::error!(
                    "[TSS] There was an error sending signed Signature Share to the coordinator {:?}",
                    error
                ),
                Ok(_) => {
                    log::debug!("[TSS] Signed Signing Share sent to coordinator {:?}", coordinator);
                    // Update session state to Round1Completed
                    self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::Round2Completed);
                    log::debug!("[TSS] Signin State updated to SigningSessionState::Round2Completed");
                }
            }
        } else {
            log::error!("[TSS] Missing coordinator information, for peer {:?}", coordinator);
        }
        
        Ok(())
    }

    pub fn signing_handle_signature_share(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        sender: PeerId,
    ) -> Result<Signature, SessionManagerError> {
        let signature_share = SignatureShare::deserialize(bytes);
        // Update session state to Round1Completed
        self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::Round3Initiated);
        
        if let Err(error) = signature_share {
            log::error!(
                "[TSS] There was an error deserializing the Signature Share {:?}",
                error
            );
            
            // Report InvalidCryptographicData offence for the sender
            let best_hash = self.client.best_hash();

            // Convert peer id to account_id using the peer_mapper
            let sender = self.session_core.peer_mapper.lock().unwrap()
                .get_account_id_from_peer_id(&sender).cloned();

            if let None = sender {
                log::error!("[TSS] Account ID not found for sender {:?}", sender);
                return Err(SessionManagerError::IdentifierNotFound);
            }   

            let offenders: Vec<[u8; 32]> = vec![sender.unwrap().as_slice().try_into().unwrap()];
            if let Err(e) = self.client.report_tss_offence(best_hash, session_id, TssOffenceType::InvalidCryptographicData, offenders) {
                log::error!("[TSS] Failed to report InvalidCryptographicData offence for session {}: {:?}", session_id, e);
            } else {
                log::debug!("[TSS] Successfully reported InvalidCryptographicData offence for session {}", session_id);
            }
            
            return Err(SessionManagerError::DeserializationError);
        }
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
            "[TSS] Stored received signature share message from identifier {:?}",
            identifier.clone()
        );
        storage.store_signature_share(session_id, identifier, &bytes[..]);
        drop(peer_mapper_handle);
        drop(storage);

        let storage = self.storage_manager.storage.lock().unwrap();

        let signature_shares = storage.fetch_signature_shares(session_id);

        if let Err(error) = signature_shares {
            log::error!(
                "[TSS] Error fetching Signature Shares for SesssionId {:?} {:?}",
                session_id,
                error
            );
            return Err(SessionManagerError::DeserializationError);
        }

        let data = self.get_session_data(&session_id);
        if let None = data {
            log::error!("[TSS] No data found in Storage");
        }

        let (t, _, _, _) = data.unwrap();

        let signature_shares = signature_shares.unwrap();
        log::info!("signature_shares = {:?}", signature_shares);

        if signature_shares.len() >= t.into() {
            let signing_package = storage.read_signing_package(session_id);

            if let Err(error) = signing_package {
                log::error!(
                    "[TSS] Error fetching Signing Package for SesssionId {:?} {:?}",
                    session_id,
                    error
                );
            }

            let dkg_session_id = {
                let map = self.signing_to_dkg.lock().unwrap();
                *map.get(&session_id).unwrap_or(&session_id)
            };
            let key_storage = self.storage_manager.key_storage.lock().unwrap();
            let mut peer_mapper_handle = self.session_core.peer_mapper.lock().unwrap();
            let whoami_identifier = peer_mapper_handle.get_identifier_from_account_id(&session_id, &self.session_core.validator_key);

            if let None = whoami_identifier {
                log::error!("[TSS] We are not allowed to participate in the signing phase");
                return Err(SessionManagerError::IdentifierNotFound);
            }
            let pubkeys = key_storage.get_pubkey(dkg_session_id, &whoami_identifier.unwrap());
            drop(peer_mapper_handle);

            if let Err(error) = signing_package {
                log::error!(
                    "[TSS] Error fetching Signing Package for SesssionId {:?} {:?}",
                    session_id,
                    error
                );
            }

            let signature = frost_ed25519::aggregate(
                &signing_package.unwrap(),
                &signature_shares,
                &pubkeys.unwrap(),
            );

            if let Err(error) = signature {
                log::error!("[TSS] Error aggregating Signature {:?}", error);

                // Update session state to Failed
                self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::Failed);
                
                // Report signing failure - this could be due to invalid signature shares
                // Let the timeout mechanism handle participant reporting
                return Err(SessionManagerError::SignatureAggregationError);
            }

            self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::SignatureGenerated);

            drop(storage);
            drop(key_storage);

            return Ok(signature.unwrap());
        }
        log::error!("[TSS] Only {:?} signature shares received. Needing {:?} to proceed", signature_shares.len(), t);
        return Err(SessionManagerError::SignatureNotReadyYet);
    }
}