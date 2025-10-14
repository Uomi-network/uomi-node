use crate::{
    client::ClientManager,
    ecdsa::{ECDSAError, ECDSAIndexWrapper, ECDSAManager, ECDSAPhase},
    types::SessionId,
    SessionManager,
};
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use sp_runtime::traits::Block as BlockT;
use std::sync::MutexGuard;
use uomi_runtime::pallet_tss::TssOffenceType;
use crate::dkghelpers::Storage;
use sc_network_types::PeerId;
use crate::session::signing_state_manager::SigningSessionState; // Reuse signing session states for ECDSA observability

impl<B: BlockT, C: ClientManager<B>> SessionManager<B, C> {
    
    pub fn handle_buffer_and_sending_messages_for_sign_online(
        &self,
        session_id: &u64,
        msg: &Vec<u8>,
        manager: &mut MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, ECDSAError>, ECDSAPhase) {
        match manager.handle_sign_online_buffer(*session_id) {
            Err(ECDSAError::SignOnlineMsgHandlerError(error, index)) => {
                // Report the offender
                // First we translate the index into an account_id
                let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
                
                let account_id = peer_mapper.get_validator_account_from_id(index.0.parse::<u32>().unwrap());
                drop(peer_mapper);

                if let Some(account_id) = account_id {
                    // Report the offender
                    let offenders: Vec<[u8; 32]> = vec![account_id.clone()[..].try_into().unwrap()];
                    let best_hash = self.client.best_hash();
                    if let Err(e) = self.client.report_tss_offence(best_hash, *session_id, TssOffenceType::InvalidCryptographicData, offenders) {
                        log::error!("[TSS] Failed to report InvalidCryptographicData offence for session {}: {:?}", session_id, e);
                    } else {
                        log::info!("[TSS] Successfully reported InvalidCryptographicData offence for session {} for sender", session_id);
                    }
                }
            },
            Err(error) => log::error!(
                "[TSS] There was an error consuming the sign online buffer {:?}",
                error
            ),
            Ok(handled_buffer) => {
                for sending_message in handled_buffer {
                    self.handle_ecdsa_sending_messages(
                        *session_id,
                        sending_message,
                        manager,
                        ECDSAPhase::SignOnline,
                    );
                }
            }
        }
        (
            manager.handle_sign_online_message(*session_id, index, &msg),
            ECDSAPhase::SignOnline,
        )
    }

    pub fn handle_buffer_and_sending_messages_for_sign_offline(
        &self,
        session_id: &u64,
        msg: &Vec<u8>,
        manager: &mut MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, ECDSAError>, ECDSAPhase) {
        match manager.handle_sign_buffer(*session_id) {
            Err(ECDSAError::SignMsgHandlerError(error, index)) => {
                // Report the offender
                // First we translate the index into an account_id
                let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
                
                let account_id = peer_mapper.get_validator_account_from_id(index.0.parse::<u32>().unwrap());
                drop(peer_mapper);

                if let Some(account_id) = account_id {
                    // Report the offender
                    let offenders: Vec<[u8; 32]> = vec![account_id.clone()[..].try_into().unwrap()];
                    let best_hash = self.client.best_hash();
                    if let Err(e) = self.client.report_tss_offence(best_hash, *session_id, TssOffenceType::InvalidCryptographicData, offenders) {
                        log::error!("[TSS] Failed to report InvalidCryptographicData offence for session {}: {:?}", session_id, e);
                    } else {
                        log::info!("[TSS] Successfully reported InvalidCryptographicData offence for session {} for sender", session_id);
                    }
                }
            },
            Err(error) => log::error!(
                "[TSS] There was an error consuming the sign buffer {:?}",
                error
            ),
            Ok(handled_buffer) => {
                log::debug!("[TSS] Consumed buffer");
                log::debug!("[TSS] Handling sending messages received from buffer");
                for sending_message in handled_buffer {
                    self.handle_ecdsa_sending_messages(
                        *session_id,
                        sending_message,
                        manager,
                        ECDSAPhase::Sign,
                    );
                }
            }
        }
        (
            manager.handle_sign_message(*session_id, index, &msg),
            ECDSAPhase::Sign,
        )
    }

    pub fn handle_buffer_and_sending_messages_for_keygen(
        &self,
        session_id: &u64,
        msg: &Vec<u8>,
        manager: &mut MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, ECDSAError>, ECDSAPhase) {
        match manager.handle_keygen_buffer(*session_id) {
            Err(ECDSAError::KeygenMsgHandlerError(error, index)) => {

                log::error!("[TSS] Keygen message handler error: {:?}", error);
                // Report the offender
                // First we translate the index into an account_id
                let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
                
                let account_id = peer_mapper.get_validator_account_from_id(index.0.parse::<u32>().unwrap());
                drop(peer_mapper);

                if let Some(account_id) = account_id {
                    // Report the offender
                    let offenders: Vec<[u8; 32]> = vec![account_id.clone()[..].try_into().unwrap()];
                    let best_hash = self.client.best_hash();
                    if let Err(e) = self.client.report_tss_offence(best_hash, *session_id, TssOffenceType::InvalidCryptographicData, offenders) {
                        log::error!("[TSS] Failed to report InvalidCryptographicData offence for session {}: {:?}", session_id, e);
                    } else {
                        log::info!("[TSS] Successfully reported InvalidCryptographicData offence for session {} for sender", session_id);
                    }
                }
            },
            Err(error) => log::error!(
                "[TSS] There was an error consuming the keygen buffer {:?}",
                error
            ),
            Ok(handled_buffer) => {
                for sending_message in handled_buffer {
                    self.handle_ecdsa_sending_messages(
                        *session_id,
                        sending_message,
                        manager,
                        ECDSAPhase::Key,
                    );
                }
            }
        }
        // Try to handle the keygen message
        let keygen_result = manager.handle_keygen_message(*session_id, index, &msg);
        
        // If keygen session doesn't exist, log error and suggest session recreation
        if matches!(keygen_result, Err(ECDSAError::KeygenNotFound)) {
            log::error!(
                "[TSS] ECDSA keygen session {} not found when processing message. Session may need to be recreated.",
                session_id
            );
            // Return a more specific error instead of letting it become "Generic error"
            return (Err(ECDSAError::KeygenNotFound), ECDSAPhase::Key);
        }
        
        (keygen_result, ECDSAPhase::Key)
    }

    pub fn handle_buffer_and_sending_messages_for_reshare(
        &self,
        session_id: &u64,
        msg: &Vec<u8>,
        manager: &mut MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, ECDSAError>, ECDSAPhase) {
        match manager.handle_reshare_buffer(*session_id) {
            Err(ECDSAError::ReshareMsgHandlerError(error, index)) => {
                // Report the offender
                // First we translate the index into an account_id
                let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
                
                let account_id = peer_mapper.get_validator_account_from_id(index.0.parse::<u32>().unwrap());
                drop(peer_mapper);

                if let Some(account_id) = account_id {
                    // Report the offender
                    let offenders: Vec<[u8; 32]> = vec![account_id.clone()[..].try_into().unwrap()];
                    let best_hash = self.client.best_hash();
                    if let Err(e) = self.client.report_tss_offence(best_hash, *session_id, TssOffenceType::InvalidCryptographicData, offenders) {
                        log::error!("[TSS] Failed to report InvalidCryptographicData offence for session {}: {:?}", session_id, e);
                    } else {
                        log::info!("[TSS] Successfully reported InvalidCryptographicData offence for session {} for sender", session_id);
                    }
                }
            },
            Err(error) => log::error!(
                "[TSS] There was an error consuming the reshare buffer {:?}",
                error
            ),
            Ok(handled_buffer) => {
                for sending_message in handled_buffer {
                    self.handle_ecdsa_sending_messages(
                        *session_id,
                        sending_message,
                        manager,
                        ECDSAPhase::Reshare,
                    );
                }
            }
        }
        // Try to handle the reshare message
        let reshare_result = manager.handle_reshare_message(*session_id, index, &msg);
        
        // If reshare session doesn't exist, log error and suggest session recreation
        if matches!(reshare_result, Err(ECDSAError::ReshareNotFound)) {
            log::error!(
                "[TSS] ECDSA reshare session {} not found when processing message. Session may need to be recreated.",
                session_id
            );
            // Return a more specific error instead of letting it become "Generic error"
            return (Err(ECDSAError::ReshareNotFound), ECDSAPhase::Reshare);
        }
        
        (reshare_result, ECDSAPhase::Reshare)
    }

    pub fn handle_ecdsa_sending_messages(
        &self,
        session_id: SessionId,
        sending_messages: SendingMessages,
        ecdsa_manager: &mut MutexGuard<'_, ECDSAManager>,
        phase: ECDSAPhase,
    ) {
        match sending_messages {
            SendingMessages::P2pMessage(msg) => {
                self.handle_p2p_message(session_id, msg, ecdsa_manager, phase);
            }
            SendingMessages::BroadcastMessage(msg) | SendingMessages::SubsetMessage(msg) => {
                self.handle_broadcast_message(session_id, msg, ecdsa_manager, phase);
            }
            SendingMessages::KeyGenSuccessWithResult(msg) => {
                self.handle_keygen_success(session_id, msg, ecdsa_manager);
            }
            SendingMessages::ReshareKeySuccessWithResult(msg) => {
                self.handle_reshare_success(session_id, msg, ecdsa_manager);
            }
            SendingMessages::SignOfflineSuccessWithResult(msg) => {
                self.handle_sign_offline_success(session_id, msg);
            }
            SendingMessages::SignOnlineSuccessWithResult(msg) => {
                self.handle_sign_online_success(session_id, msg);
            }
            msg => log::debug!(
                "[TSS] Other message in handle_ecdsa_sending_messages {:?}",
                msg
            ),
        }
    }

    fn get_local_index(&self, session_id: &SessionId) -> Option<String> {
        let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
        let index = match PeerId::from_bytes(&self.session_core.local_peer_id[..]) {
            Ok(local_pid) => peer_mapper
                .get_id_from_peer_id(session_id, &local_pid)
                .clone(),
            Err(e) => {
                log::error!("[TSS] Invalid local_peer_id bytes when resolving local index: {:?}", e);
                None
            }
        };
        drop(peer_mapper);

        if index.is_none() {
            log::error!("[TSS] We are not allowed in this session {:?}", session_id);
        }

        index.map(|i| i.to_string())
    }

    fn handle_phase_message(
        &self,
        session_id: &SessionId,
        data: &Vec<u8>,
        ecdsa_manager: &mut MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
        phase: &ECDSAPhase,
    ) -> Option<SendingMessages> {
        let result = match phase {
            ECDSAPhase::Key => self.handle_buffer_and_sending_messages_for_keygen(
                session_id,
                data,
                ecdsa_manager,
                index,
            ),
            ECDSAPhase::Reshare => self.handle_buffer_and_sending_messages_for_reshare(
                session_id,
                data,
                ecdsa_manager,
                index,
            ),
            ECDSAPhase::Sign => self.handle_buffer_and_sending_messages_for_sign_offline(
                session_id,
                data,
                ecdsa_manager,
                index,
            ),
            ECDSAPhase::SignOnline => self.handle_buffer_and_sending_messages_for_sign_online(
                session_id,
                data,
                ecdsa_manager,
                index,
            ),
        };

        match result {
            (Err(error), _) => {
                log::error!("[TSS] Error sending messages {:?}", error);
                None
            }
            (Ok(sending_messages), _) => Some(sending_messages),
        }
    }

    fn send_message_to_recipient(
        &self,
        session_id: SessionId,
        recipient_id: &str,
        sender_index: &str,
        data: Vec<u8>,
        phase: &ECDSAPhase,
    ) {
        log::info!("[TSS] Acquired lock on mapper");
        let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
        let recipient = peer_mapper
            .get_peer_id_from_id(&session_id, recipient_id.parse::<u16>().unwrap())
            .cloned();
        drop(peer_mapper);
        log::info!("[TSS] Dropped lock on mapper");

        if let Some(recipient) = recipient {
            let ecdsa_message = crate::types::TssMessage::ECDSAMessageP2p(
                session_id,
                sender_index.to_string(),
                recipient.to_bytes(),
                data,
                phase.clone(),
            );
            if let Err(error) = self.send_signed_message(ecdsa_message) {
                log::error!("[TSS] Error sending signed ECDSA P2P message: {:?}", error);
            }
            // After successful send, opportunistically try flushing any queued outbound (cheap if none)
            self.flush_pending_outbound_for_session(session_id);
        } else {
            log::warn!("[TSS][P2P][QUEUE] Recipient mapping missing; queueing outbound P2P session_id={} recipient_id={} phase={:?} bytes={} ", session_id, recipient_id, phase, data.len());
            self.queue_outbound_p2p(session_id, recipient_id.to_string(), sender_index.to_string(), data, phase.clone());
        }
    }

    fn store_result_data(
        &self,
        session_id: SessionId,
        storage_type: crate::dkghelpers::StorageType,
        data: &[u8],
    ) -> Result<(), ()> {
        let id = self.get_my_identifier(session_id);
        let mut storage = self.storage_manager.key_storage.lock().unwrap();

        if let Err(error) = storage.store_data(
            session_id,
            storage_type,
            data,
            Some(&id.serialize()),
        ) {
            log::error!("[TSS] There was an error storing data {:?}", error);
            return Err(());
        }

        drop(storage);
        Ok(())
    }

    fn handle_p2p_message(
        &self,
        session_id: SessionId,
        msg: std::collections::HashMap<String, Vec<u8>>,
        ecdsa_manager: &mut MutexGuard<'_, ECDSAManager>,
        phase: ECDSAPhase,
    ) {
        log::info!("[TSS] SendingMessages::P2pMessage");
        
        let index = match self.get_local_index(&session_id) {
            Some(idx) => idx,
            None => return,
        };

        for (id, data) in msg {
            if id == index {
                let sending_messages_after_handling = self.handle_phase_message(
                    &session_id,
                    &data,
                    ecdsa_manager,
                    ECDSAIndexWrapper(id),
                    &phase,
                );

                match sending_messages_after_handling {
                    Some(msg) => {
                        self.handle_ecdsa_sending_messages(
                            session_id,
                            msg,
                            ecdsa_manager,
                            phase.clone(),
                        );
                    }
                    None => {
                        log::warn!("[TSS] Probably there was an error");
                    }
                }

                continue;
            }

            self.send_message_to_recipient(session_id, &id, &index, data, &phase);
        }
    }

    fn handle_broadcast_message(
        &self,
        session_id: SessionId,
        msg: Vec<u8>,
        ecdsa_manager: &mut MutexGuard<'_, ECDSAManager>,
        phase: ECDSAPhase,
    ) {
        log::info!(
            "[TSS] SendingMessages::BroadcastMessage, acquiring lock on peer mapper"
        );

        let index = match self.get_local_index(&session_id) {
            Some(idx) => idx,
            None => return,
        };

        log::debug!(
            "[TSS] SendingMessages::BroadcastMessage, phase = {:?}",
            phase
        );

        let sending_messages = self.handle_phase_message(
            &session_id,
            &msg,
            ecdsa_manager,
            ECDSAIndexWrapper(index.clone()),
            &phase,
        );

        log::debug!(
            "[TSS] SendingMessages::BroadcastMessage, done, sending message to gossip"
        );

        let broadcast_message = crate::types::TssMessage::ECDSAMessageBroadcast(
            session_id,
            index,
            msg,
            phase.clone(),
        );
        if let Err(e) = self.send_signed_message(broadcast_message) {
            log::error!("[TSS] Failed to send signed broadcast message: {:?}", e);
        }

        match sending_messages {
            Some(msg) => {
                self.handle_ecdsa_sending_messages(session_id, msg, ecdsa_manager, phase);
            }
            None => {
                log::warn!("[TSS] Probably there was an error");
            }
        }
    }

    fn handle_keygen_success(
        &self,
        session_id: SessionId,
        msg: String,
        ecdsa_manager: &mut MutexGuard<'_, ECDSAManager>,
    ) {
        log::info!("[TSS] ECDSA Keygen successful, storing keys {:?}", msg);

        if self.store_result_data(
            session_id,
            crate::dkghelpers::StorageType::EcdsaKeys,
            msg.as_bytes(),
        ).is_err() {
            log::error!("[TSS] Failed to store ECDSA keys");
            return;
        }

        let index = match self.get_local_index(&session_id) {
            Some(idx) => idx,
            None => {
                log::error!("[TSS] Index is not, shouldn't have happened, returning");
                return;
            }
        };



        let maybe_agg_key = extract_agg_key(&msg);
        match maybe_agg_key {
            Ok(agg_key_bytes) => {
                if agg_key_bytes.len() > 80 { // sanity log to help in future debugging
                    log::warn!("[TSS] Extracted aggregated key length {} seems large; expected <=65", agg_key_bytes.len());
                }
                if let Err(err) = self.client.submit_dkg_result(self.client.best_hash(), session_id, agg_key_bytes) {
                    log::error!("[TSS] Error submitting DKG result to chain: {:?}", err);
                }
            }
            Err(parse_err) => {
                log::error!("[TSS] Failed to parse aggregated key from DKG result JSON: {}", parse_err);
            }
        }

        let session_data = self.get_session_data(&session_id);

        match session_data {
            Some((t, n, _coordinator, _message)) => {
                self.ecdsa_create_sign_offline_phase(
                    session_id,
                    t,
                    n,
                    msg,
                    index,
                    ecdsa_manager,
                );
            }
            None => {
                log::error!("[TSS] Session data not found, returning");
                return;
            }
        };
    }

    fn handle_reshare_success(
        &self,
        session_id: SessionId,
        msg: String,
        ecdsa_manager: &mut MutexGuard<'_, ECDSAManager>,
    ) {
        log::info!("[TSS] ECDSA Reshare successful, storing keys {:?}", msg);

        if self.store_result_data(
            session_id,
            crate::dkghelpers::StorageType::EcdsaKeys,
            msg.as_bytes(),
        ).is_err() {
            return;
        }

        if let Err(err) = self.client.complete_reshare_session(self.client.best_hash(), session_id) {
            log::error!("[TSS] Error submitting DKG reshare result to chain: {:?}", err);
        }

        let index = match self.get_local_index(&session_id) {
            Some(idx) => idx,
            None => {
                log::error!("[TSS] Index is not, shouldn't have happened, returning");
                return;
            }
        };

        let session_data = self.get_session_data(&session_id);

        match session_data {
            Some((t, n, _coordinator, _message)) => {
                self.ecdsa_create_sign_offline_phase(
                    session_id,
                    t,
                    n,
                    msg,
                    index,
                    ecdsa_manager,
                );
            }
            None => {
                log::error!("[TSS] Session data not found, returning");
                return;
            }
        };
    }

    fn handle_sign_offline_success(&self, session_id: SessionId, msg: String) {
        log::debug!("[TSS] SendingMessages::SignOfflineSuccessWithResult");
        
        if self.store_result_data(
            session_id,
            crate::dkghelpers::StorageType::EcdsaOfflineOutput,
            msg.as_bytes(),
        ).is_err() {
            return;
        }

        // Map ECDSA offline completion to Round1Initiated + Round2Completed to preserve legacy monitoring semantics.
        // If already beyond these states (e.g., race), do not regress.
        let current = self.state_managers.signing_state_manager.get_state(&session_id);
        if current < SigningSessionState::Round1Initiated {
            self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::Round1Initiated);
        }
        if current < SigningSessionState::Round2Completed {
            self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::Round2Completed);
        }

    // Fallback queue removed: no draining logic
    }

    fn handle_sign_online_success(&self, session_id: SessionId, msg: String) {
        log::debug!("[TSS] SendingMessages::SignOnlineSuccessWithResult");
        
        if self.store_result_data(
            session_id,
            crate::dkghelpers::StorageType::EcdsaOnlineOutput,
            msg.as_bytes(),
        ).is_err() {
            return;
        }

        // Online phase success corresponds to final signature generation.
        // Only set if we haven't already recorded it.
        let current = self.state_managers.signing_state_manager.get_state(&session_id);
        if current < SigningSessionState::SignatureGenerated {
            self.state_managers.signing_state_manager.set_state(session_id, SigningSessionState::SignatureGenerated);
        }

        if let Some(sig_bytes) = parse_signature_bytes(&msg) {
            if let Err(e) = self.client.submit_signature_result(self.client.best_hash(), session_id, sig_bytes.clone()) {
                log::error!("[TSS] Failed to submit online signature result unsigned extrinsic: {}", e);
            } else {
                log::info!("[TSS] Submitted online signature result for session {} ({} bytes)", session_id, sig_bytes.len());
            }
        } else {
            log::warn!("[TSS] Could not extract signature bytes from online sign result to submit on-chain");
        }
    }

    pub fn get_my_identifier(
        &self,
        session_id: u64,
    ) -> frost_core::Identifier<frost_ed25519::Ed25519Sha512> {
        let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();

        let index = match PeerId::from_bytes(&self.session_core.local_peer_id[..]) {
            Ok(local_pid) => peer_mapper
                .get_id_from_peer_id(&session_id, &local_pid)
                .clone(),
            Err(e) => {
                log::error!("[TSS] Invalid local_peer_id bytes when getting my identifier: {:?}", e);
                None
            }
        };

        drop(peer_mapper);

        let _id = index.unwrap();
        log::info!("[TSS] My Id is {:?}", _id);
        let _id: frost_ed25519::Identifier = _id.try_into().unwrap();
        _id
    }
}

// Extract aggregated public key bytes from JSON result instead of submitting full JSON.
// Expected structure: { "pubkey": { "pk": ["<hex-compressed-or-uncompressed>", ...], ... }, ... }
// We take the first element of pubkey.pk[] as the aggregated key.
// Robust parsing with serde_json plus fallbacks (raw hex / bytes) for resilience.
pub(crate) fn extract_agg_key(msg: &str) -> Result<Vec<u8>, String> {
    let trimmed = msg.trim();
    if !trimmed.starts_with('{') { // fallback simple modes
        if trimmed.starts_with("0x") {
            return hex::decode(&trimmed[2..]).map_err(|e| format!("Invalid hex aggregated key: {e}"));
        }
        if trimmed.chars().all(|c| c.is_ascii_hexdigit()) && trimmed.len() % 2 == 0 {
            return hex::decode(trimmed).map_err(|e| format!("Invalid hex aggregated key: {e}"));
        }
        return Ok(msg.as_bytes().to_vec());
    }

    #[derive(serde::Deserialize)]
    struct PubKeyInner { pk: Vec<String> }
    #[derive(serde::Deserialize)]
    struct TopLevel { #[serde(default)] pubkey: Option<PubKeyInner> }

    // Try strict parsing first
    let parsed: TopLevel = serde_json::from_str(trimmed).map_err(|e| format!("JSON parse error: {e}"))?;
    let pk_list = parsed.pubkey.ok_or("Missing 'pubkey' object")?.pk;
    // pk_list is the set of coordinates (x, y)
    let first = pk_list.get(0).ok_or("'pubkey.pk' array empty")?;
    let second = pk_list.get(1).ok_or("'pubkey.pk' array too short")?;
    let key_hex = first.trim_start_matches("0x");
    let second_hex = second.trim_start_matches("0x");
    let bytes = hex::decode(format!("{key_hex}{second_hex}")).map_err(|e| format!("Failed to decode pk hex: {e}"))?;
    Ok(bytes)
}

// Attempt to extract a signature from various message formats
fn parse_signature_bytes(msg: &str) -> Option<Vec<u8>> {
    let trimmed = msg.trim();
    // if trimmed.starts_with("0x") && trimmed.len() > 4 {
    //     return hex::decode(&trimmed[2..]).ok();
    // }
    // if trimmed.chars().all(|c| c.is_ascii_hexdigit()) && trimmed.len() % 2 == 0 {
    //     return hex::decode(trimmed).ok();
    // }
    if trimmed.starts_with('{') {
        #[derive(serde::Deserialize)]
        struct SigWrapper { 
            // #[serde(default)] signature: Option<String>,
            #[serde(default)] r: Option<String>,
            #[serde(default)] s: Option<String>,
            #[serde(default)] recid: Option<u8>,
        }
        if let Ok(sw) = serde_json::from_str::<SigWrapper>(trimmed) {
            // Case 1: Nested single hex string (existing behaviour)
            // if let Some(sig_hex) = sw.signature {
            //     return parse_signature_bytes(&sig_hex);
            // }
            // Case 2: r + s (+ recid) JSON like {"s":"..","r":"..","recid":0}
            if let (Some(r_hex), Some(s_hex)) = (sw.r, sw.s) {
                let norm = |h: String| h.trim_start_matches("0x").to_string();
                let r_clean = norm(r_hex);
                let s_clean = norm(s_hex);

                // If r_clean.len() == 63 we add a leading zero
                let r_clean = if r_clean.len() == 63 {
                    format!("0{r_clean}")
                } else {
                    r_clean
                };

                // If s_clean.len() == 63 we add a leading zero
                let s_clean = if s_clean.len() == 63 {
                    format!("0{s_clean}")
                } else {
                    s_clean
                };

                // Require even length and hexadecimal
                if r_clean.len() % 2 == 0 && s_clean.len() % 2 == 0 &&
                    r_clean.chars().all(|c| c.is_ascii_hexdigit()) &&
                    s_clean.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let (Ok(mut r_bytes), Ok(mut s_bytes)) = (hex::decode(&r_clean), hex::decode(&s_clean)) {
                        let recid = sw.recid.unwrap_or(0);
                        if r_bytes.len() == 32 && s_bytes.len() == 32 { // canonical sizes
                            r_bytes.append(&mut s_bytes);
                            r_bytes.push(recid);
                            if r_bytes.len() <= 65 { return Some(r_bytes); }
                        } else {
                            // Fallback: concatenate even if not 32 each, still ensure bounded <=65
                            r_bytes.append(&mut s_bytes);
                            r_bytes.push(recid);
                            if r_bytes.len() <= 128 { return Some(r_bytes); }
                        }
                    }
                }
            }
        }
    }
    None
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_extract_agg_key() {
        let test_msg = "{\"index\":\"3\",\"participants\":[\"2\",\"3\",\"4\",\"5\",\"1\"],\"pubkey\":{\"pk\":[\"e38cff8a210ee94297111b08aaf5cb1c364ba008f3ac39ea20cfacd51022fe4c\",\"f4e890cfe699b58cbab33b212241b3b315927af48ae204cae0abae1b77c4d432\"],\"share_pks\":{\"4\":[\"240da99e7c39fe9ec117d81c021cbf74bf7a49b47553fbf397b44fa61b957cda\",\"45943a02f4093f306da762c22c9069d969cf30150de94f2c58b4296d9a73a1a3\"],\"1\":[\"dfcad00853b34e0573a7ff3fb0519156e1b906159aee4589bca2cef3963c3e6c\",\"c6cb8e473dd2b829475b3e9083f3593d1dc4db21d1562196ae03ba8e93a7c2f7\"],\"2\":[\"94d8247eccb6a2e65615db4c40b2a3160431908592154a1a3620347f5dbd193c\",\"8da043b72a3f8df73ec9da33d7a04d30f74e9d020d0821da147f91455707d2c9\"],\"5\":[\"79cb40902ee09bc21e43c294f6a4db300ab698a633f4b1676ef140c7ff4be850\",\"307bd4afc37b84bfe190afa92e357fffa8b81e00665c77702d66e13e01c9b36d\"],\"3\":[\"b0d1ffff1bf13602ee209ca8e9dce8a2e7a0140246f36515f1ec72bf9a6b2594\",\"4cf02eb78dc68aa951c19edc7580f4ad7a2e947a2ac9d043951668b6e21a0a20\"]}},\"privkey\":{\"cl_sk\":\"46a82b1662cc48a491678457a99fba1e2951c1be850f37941a3e47327947ccb72692572b217184a9769cebedd54cf7527e5a59070b97237f944104ff647de218275e6030764fffb1f9c0ac6ef9dbaf86fe6e527e3a58c0b03839ee2266163b2f246b14caea5c54bad8a9f24ccb1869967c8c5042ffa64974c4f85d8e24247c6a61b3720457f44727a28c50f70\",\"ec_sk\":\"606f42b0848225e3a0713c84cd77dbc5851cd0c66e4455e11ec8455b21dd6d8a\",\"share_sk\":\"567e06ab2e7111735c405765f9a9a956d8db58dcfb5aebd7dbf97efa724f52d2\"}}";
        let bytes = super::extract_agg_key(test_msg).unwrap();
        assert_eq!(bytes, hex::decode("e38cff8a210ee94297111b08aaf5cb1c364ba008f3ac39ea20cfacd51022fe4cf4e890cfe699b58cbab33b212241b3b315927af48ae204cae0abae1b77c4d432").unwrap());
        assert!(bytes.len() <= 65, "Unexpected aggregated key length");
    }

    #[test]
    fn test_parse_signature_r_s_recid() {
        let json = "{\"s\":\"816998f4a60aff70bfdfcdfe1f538f17998fc9b90819c474d6ce8103997396f\",\"r\":\"a70edf582a3b5cfeb90c49c80a46a3fb0152b97bb2684570d18cdace30b6b279\",\"recid\":0}";
        let sig = super::parse_signature_bytes(json).expect("should parse r,s,recid");
        assert_eq!(sig.len(), 65);
        assert_eq!(&hex::encode(&sig[0..32]), "a70edf582a3b5cfeb90c49c80a46a3fb0152b97bb2684570d18cdace30b6b279");
        assert_eq!(&hex::encode(&sig[32..64]), "0816998f4a60aff70bfdfcdfe1f538f17998fc9b90819c474d6ce8103997396f");
        assert_eq!(sig[64], 0u8);
    }
}