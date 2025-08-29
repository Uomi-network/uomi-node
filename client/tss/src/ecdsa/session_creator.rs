use crate::{
    client::ClientManager,
    dkghelpers::StorageType,
    ecdsa::{ECDSAManager, ECDSAPhase},
    types::{SessionId, TSSParticipant},
    SessionManager,
};
use frost_ed25519::Identifier;
use sp_runtime::traits::Block as BlockT;
use std::sync::MutexGuard;
use crate::dkghelpers::Storage;

impl<B: BlockT, C: ClientManager<B>> SessionManager<B, C> {
    
    pub fn ecdsa_create_keygen_phase(
        &self,
        id: SessionId,
        n: u16,
        t: u16,
        participants: Vec<TSSParticipant>,
    ) {
        log::info!(
            "[TSS][DIAG][Keygen] BEGIN create_keygen_phase session_id={} n={} t={} participants_len={}",
            id, n, t, participants.len()
        );
        let mut handler = self.ecdsa_manager.lock().unwrap();

        // Resolve our stable session index using PeerMapper (validator_id-backed), not array position
        let my_id: Option<u16> = {
            let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
            let mid = peer_mapper.get_id_from_account_id(&id, &self.session_core.validator_key);
            log::info!(
                "[TSS][DIAG][Keygen] resolved my_id={:?} for validator_key_prefix={:02x?}",
                mid,
                &self.session_core.validator_key[0..4]
            );
            mid
        };

        if my_id.is_none() {
            log::info!("[TSS][DIAG][Keygen] abort: we are not a participant (my_id is None)");
            return;
        }

        let my_id = my_id.unwrap();
        log::info!("[TSS][DIAG][Keygen] My Id = {}", my_id);

        // Collect validator IDs with detailed diagnostics (do not silently hide missing)
        let (participant_indices, missing_positions): (Vec<String>, Vec<usize>) = {
            let mut pm = self.session_core.peer_mapper.lock().unwrap();
            let mut collected = Vec::new();
            let mut missing = Vec::new();
            for (idx, p) in participants.iter().enumerate() {
                let vid_opt = pm.get_validator_id(&p.to_vec());
                log::info!(
                    "[TSS][DIAG][Keygen] participant idx={} pubkey_prefix={:02x?} validator_id={:?}",
                    idx,
                    &p.to_vec()[0..std::cmp::min(4, p.len())],
                    vid_opt
                );
                if let Some(vid) = vid_opt {
                    collected.push(vid.to_string());
                } else {
                    missing.push(idx);
                }
            }
            (collected, missing)
        };

        if !missing_positions.is_empty() {
            log::info!(
                "[TSS][DIAG][Keygen][WARNING] Missing validator IDs for participant positions {:?}; collected_count={} original_count={}",
                missing_positions,
                participant_indices.len(),
                participants.len()
            );
        } else {
            log::info!(
                "[TSS][DIAG][Keygen] All validator IDs present collected_count={} original_count={}",
                participant_indices.len(),
                participants.len()
            );
        }

        log::info!(
            "[TSS][DIAG][Keygen] participant_indices(list)={:?}",
            participant_indices
        );

        let keygen = handler.add_keygen(
            id,
            my_id.to_string(),
            participant_indices,
            t.into(),
            n.into(),
        );

        if let Some(_) = keygen {
            let msg = {
                let mut keygen = handler.get_keygen(id).unwrap();
                let r = keygen.process_begin();
                if r.is_err() {
                    log::info!("[TSS][DIAG][Keygen] process_begin error={:?}", r.as_ref().err());
                } else {
                    log::info!("[TSS][DIAG][Keygen] process_begin Ok");
                }
                r
            };

            match msg {
                Err(error) => log::error!("[TSS] Error beginning process {:?}", error),
                Ok(msg) => {
                    log::info!("[TSS][DIAG][Keygen] Dispatching SendingMessages");
                    self.handle_ecdsa_sending_messages(id, msg, &mut handler, ECDSAPhase::Key)
                }
            }
        }
        drop(handler);
        log::info!("[TSS][DIAG][Keygen] END create_keygen_phase session_id={}", id);
    }

    pub fn ecdsa_create_reshare_phase(
        &self,
        id: SessionId,
        n: u16,
        t: u16,
        participants: Vec<TSSParticipant>,
        old_participants: Vec<TSSParticipant>,
    ) {
    let my_id = match self.get_my_index(id) {
            Some(id) => id,
            None => {
                log::info!("[TSS] We are not allowed to participate");
                return;
            }
        };

        log::info!("[TSS] My Id = {:?}", my_id);

        let current_keys = self.get_current_keys(id, my_id);
        let mut handler = self.ecdsa_manager.lock().unwrap();

        let reshare_result = handler.add_reshare(
            id,
            my_id.to_string(),
            self.create_participant_indices(&old_participants),
            self.create_participant_indices(&participants),
            t.into(),
            n.into(),
            current_keys,
        );

        if reshare_result.is_none() {
            log::error!("[TSS] Failed to create reshare session");
            return;
        }

        let msg = match handler.get_reshare(id).unwrap().process_begin() {
            Ok(msg) => msg,
            Err(error) => {
                log::error!("[TSS] Error beginning reshare process: {:?}", error);
                return;
            }
        };

        self.handle_ecdsa_sending_messages(id, msg, &mut handler, ECDSAPhase::Reshare);
    }

    // Resolve our session-local index via PeerMapper for the given session
    fn get_my_index(&self, session_id: SessionId) -> Option<u16> {
        let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
        peer_mapper.get_id_from_account_id(&session_id, &self.session_core.validator_key)
    }

    fn get_current_keys(&self, id: SessionId, my_id: u16) -> Option<String> {
        let identifier: Identifier = my_id.try_into().ok()?;
        let storage = self.storage_manager.key_storage.lock().unwrap();
        
        match storage.read_data(id, StorageType::EcdsaKeys, Some(&identifier.serialize())) {
            Ok(keys) => String::from_utf8(keys).ok(),
            Err(_) => None,
        }
    }

    fn create_participant_indices(&self, participants: &[TSSParticipant]) -> Vec<String> {
        let v: Vec<String> = (1..=participants.len()).map(|el| el.to_string()).collect();
        log::info!(
            "[TSS][DIAG][Helper] create_participant_indices participants_len={} produced={:?}",
            participants.len(),
            v
        );
        v
    }

    pub fn ecdsa_create_sign_offline_phase(
        &self,
        id: SessionId,
        t: u16,
        n: u16,
        keys: String,
        index: String,
        ecdsa_manager: &mut MutexGuard<'_, ECDSAManager>,
    ) {
        log::info!(
            "[TSS][DIAG][SignOffline] BEGIN create_sign_offline_phase session_id={} t={} n={} my_index={} keys_len={}",
            id,
            t,
            n,
            index,
            keys.len()
        );
        let constructed_indices: Vec<String> = (1..=n).map(|el| el.to_string()).collect();
        log::info!(
            "[TSS][DIAG][SignOffline] constructed_indices={:?} (len={})",
            constructed_indices,
            constructed_indices.len()
        );
        let sign_offline = ecdsa_manager.add_sign(
            id,
            index,
            &constructed_indices,
            t.into(),
            n.into(),
            &keys,
        );

        if let Some(_) = sign_offline {
            let msg = {
                let sign_offline = ecdsa_manager.get_sign(id);
                if let None = sign_offline {
                    log::info!("[TSS][DIAG][SignOffline][ERROR] get_sign returned None after add_sign success");
                    return;
                }
                let r = sign_offline.unwrap().process_begin();
                if r.is_err() {
                    log::info!("[TSS][DIAG][SignOffline] process_begin error={:?}", r.as_ref().err());
                } else {
                    log::info!("[TSS][DIAG][SignOffline] process_begin Ok");
                }
                r
            };

            if let Err(error) = msg {
                log::error!("[TSS] Error beginning process {:?}", error);
                return;
            }
            log::info!(
                "[TSS] Calling handle_ecdsa_sending_messages with phase {:?}",
                ECDSAPhase::Sign
            );
            self.handle_ecdsa_sending_messages(id, msg.unwrap(), ecdsa_manager, ECDSAPhase::Sign);
        } else {
            log::info!("[TSS][DIAG][SignOffline][ERROR] add_sign returned None");
        }
        log::info!("[TSS][DIAG][SignOffline] END create_sign_offline_phase session_id={}", id);
    }

    pub fn ecdsa_create_sign_phase(
        &self,
        signing_session_id: SessionId,
        dkg_session_id: SessionId,
        participants: Vec<TSSParticipant>,
        message: Vec<u8>,
    ) {
        log::info!(
            "[TSS][DIAG][SignOnline] BEGIN create_sign_phase signing_session_id={} dkg_session_id={} participants_len={} message_len={}",
            signing_session_id,
            dkg_session_id,
            participants.len(),
            message.len()
        );
        // Use PeerMapper-provided index for this session
        let my_id = match self.get_my_index(dkg_session_id) {
            Some(idx) => idx,
            None => {
                log::info!("[TSS][DIAG][SignOnline] abort: not a participant (get_my_index None)");
                return;
            }
        };
        log::info!("[TSS][DIAG][SignOnline] my_id={}", my_id);
        let identifier: Identifier = my_id.try_into().unwrap();

        let mut handler = self.ecdsa_manager.lock().unwrap();
        let storage = self.storage_manager.key_storage.lock().unwrap();

        let offline_result = storage.read_data(
            dkg_session_id,
            StorageType::EcdsaOfflineOutput,
            Some(&identifier.serialize()),
        );

        if let Err(error) = offline_result {
            log::error!("[TSS] Error fetching keys {:?}", error);
            return;
        }

        drop(storage);

        let offline_str = String::from_utf8(offline_result.unwrap());
        if offline_str.is_err() {
            log::info!("[TSS][DIAG][SignOnline][ERROR] offline_output utf8 decode failed err={:?}", offline_str.as_ref().err());
            return;
        }
        let offline_str = offline_str.unwrap();
        log::info!(
            "[TSS][DIAG][SignOnline] offline_output_len={} prefix={:02x?}",
            offline_str.len(),
            &offline_str.as_bytes()[0..std::cmp::min(8, offline_str.len())]
        );
        let sign_online = handler.add_sign_online(signing_session_id, &offline_str, message.clone());

        if let None = sign_online {
            log::error!("[TSS][DIAG][SignOnline][ERROR] add_sign_online returned None");
        }

        if let Some(_) = sign_online {
            let msg = {
                let mut sign_online_handle = handler.get_sign_online(signing_session_id).unwrap();
                let r = sign_online_handle.process_begin();
                if r.is_err() {
                    log::info!("[TSS][DIAG][SignOnline] process_begin error={:?}", r.as_ref().err());
                } else {
                    log::info!("[TSS][DIAG][SignOnline] process_begin Ok");
                }
                r
            };

            if let Err(error) = msg {
                log::error!("[TSS] Error beginning process {:?}", error);
                return;
            }

            log::info!("[TSS][DIAG][SignOnline] Dispatching SendingMessages");
            self.handle_ecdsa_sending_messages(signing_session_id, msg.unwrap(), &mut handler, ECDSAPhase::SignOnline);
        }
        drop(handler);
        log::info!(
            "[TSS][DIAG][SignOnline] END create_sign_phase signing_session_id={}",
            signing_session_id
        );

        // Attempt to drain any buffered sign_online messages now that the phase exists
        {
            let mut mgr = self.ecdsa_manager.lock().unwrap();
            if let Err(e) = mgr.handle_sign_online_buffer(signing_session_id) {
                log::warn!("[TSS][DIAG][SignOnline][BUFFER] Failed draining sign_online buffer for session {} err={:?}", signing_session_id, e);
            } else {
                log::info!("[TSS][DIAG][SignOnline][BUFFER] Drained sign_online buffer for session {}", signing_session_id);
            }
        }
    }
}