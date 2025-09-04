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
        id: SessionId,               // new session id
        n: u16,
        t: u16,
        participants: Vec<TSSParticipant>,      // new participants
        old_participants: Vec<TSSParticipant>,  // old participants
        old_id: SessionId                       // old (completed) session id whose key material we reuse
    ) {
        // Index in the NEW participant list determines our role in new session
        let my_new_id = match self.get_my_index(id) {
            Some(idx) => idx,
            None => {
                log::info!("[TSS][Reshare] Not a participant of new session {}", id);
                return;
            }
        };
        log::info!("[TSS][Reshare] My new Id = {:?}", my_new_id);

        // We must fetch our prior share from the OLD session using our index there.
        // It's possible our index changed due to validator set reshuffle. Derive old index separately.
        let my_old_id = match self.get_my_index(old_id) {
            Some(idx) => idx,
            None => {
                log::warn!("[TSS][Reshare] We didn't participate in old session {} so no prior keys; starting fresh", old_id);
                0u16 // Will cause lookup to fail gracefully
            }
        };

        let current_keys = self.get_current_keys_from_old_session(old_id, my_old_id);
        let mut handler = self.ecdsa_manager.lock().unwrap();

        // Build participant id lists using validator IDs (stable) rather than positional indices
        let (old_ids, new_ids) = {
            let pm = self.session_core.peer_mapper.lock().unwrap();
            let mut missing_any = false;
            let mut gather = |list: &Vec<TSSParticipant>, label: &str| -> Vec<String> {
                list.iter().enumerate().filter_map(|(i, pk)| {
                    match pm.get_validator_id(&pk.to_vec()) {
                        Some(v) => Some(v.to_string()),
                        None => {
                            missing_any = true;
                            log::warn!("[TSS][Reshare] Missing validator_id for {} participant idx={} pk_prefix={:02x?}; deferring reshare init", label, i, &pk.to_vec()[0..std::cmp::min(4, pk.len())]);
                            None
                        }
                    }
                }).collect()
            };
            let old_ids = gather(&old_participants, "old");
            let new_ids = gather(&participants, "new");
            if missing_any {
                log::warn!("[TSS][Reshare] Aborting reshare phase creation session_id={} due to missing validator IDs (will rely on future retry/event)", id);
                return; // Safe early exit; higher-level logic expected to retry when IDs populate
            }
            (old_ids, new_ids)
        };

        log::info!("[TSS][Reshare] Using validator-id participant vectors old_ids={:?} new_ids={:?}", old_ids, new_ids);

        let reshare_result = handler.add_reshare(
            id,
            my_new_id.to_string(),
            old_ids,
            new_ids,
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

    fn get_current_keys_from_old_session(&self, old_session_id: SessionId, my_old_id: u16) -> Option<String> {
        if my_old_id == 0 { return None; }
        let identifier: Identifier = my_old_id.try_into().ok()?;
        let storage = self.storage_manager.key_storage.lock().unwrap();
        match storage.read_data(old_session_id, StorageType::EcdsaKeys, Some(&identifier.serialize())) {
            Ok(keys) => {
                let utf8 = String::from_utf8(keys).ok();
                if utf8.is_some() { log::info!("[TSS][Reshare] Loaded prior key share from old_session_id={} old_index={}", old_session_id, my_old_id); }
                utf8
            },
            Err(_) => {
                log::warn!("[TSS][Reshare] No prior key share found for old_session_id={} old_index={}", old_session_id, my_old_id);
                None
            },
        }
    }

    // NOTE: create_participant_indices retained for legacy keygen path; reshare now uses validator IDs.
    fn create_participant_indices(&self, participants: &[TSSParticipant]) -> Vec<String> {
        (1..=participants.len()).map(|el| el.to_string()).collect()
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
        // Build participant index list from validator IDs (stable) if available; fallback to 1..=n
        let constructed_indices: Vec<String> = {
            let mut pm = self.session_core.peer_mapper.lock().unwrap();
            // sessions_participants_u16 maps session_id -> HashMap<u16 (validator_id), TSSPublic>
            let handle = pm.sessions_participants_u16.lock().unwrap();
            if let Some(session_map) = handle.get(&id) {
                let mut keys: Vec<u16> = session_map.keys().cloned().collect();
                keys.sort_unstable();
                let v: Vec<String> = keys.into_iter().map(|k| k.to_string()).collect();
                log::info!(
                    "[TSS][DIAG][SignOffline] constructed_indices(from validator IDs)={:?} (len={})",
                    v,
                    v.len()
                );
                v
            } else {
                let fallback: Vec<String> = (1..=n).map(|el| el.to_string()).collect();
                log::warn!(
                    "[TSS][DIAG][SignOffline][FALLBACK] No session participants mapping found for session_id={}; using sequential indices {:?}",
                    id, fallback
                );
                fallback
            }
        };
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

        if let Err(error) = &offline_result {
            log::warn!("[TSS][DIAG][SignOnline] Offline output missing for dkg_session_id={} (err={:?}); scheduling offline generation first", dkg_session_id, error);
            drop(storage);
            // Need t,n,keys for offline phase. Retrieve DKG key material first.
            let (t,n,keys_str,index_str) = {
                // Get DKG session data for threshold/participants
                let session_data = self.get_session_data(&dkg_session_id);
                if session_data.is_none() { log::error!("[TSS][DIAG][SignOnline][FALLBACK] Missing session data for dkg_session_id={}", dkg_session_id); return; }
                let (t,n,_coord,_msg) = session_data.unwrap();
                // Fetch keygen result (EcdsaKeys)
                let key_storage = self.storage_manager.key_storage.lock().unwrap();
                let keygen_bytes = key_storage.read_data(dkg_session_id, StorageType::EcdsaKeys, Some(&identifier.serialize()));
                if let Err(e) = keygen_bytes { log::error!("[TSS][DIAG][SignOnline][FALLBACK] Missing keygen keys for offline generation err={:?}", e); return; }
                let keys_utf8 = String::from_utf8(keygen_bytes.unwrap()).unwrap_or_default();
                (t,n,keys_utf8,my_id.to_string())
            };
            // Start offline phase now (id = dkg_session_id for offline output)
            self.ecdsa_create_sign_offline_phase(dkg_session_id, t, n, keys_str, index_str, &mut handler);
            // Queue this online request until offline completes
            {
                let mut pending = self.pending_sign_online_after_offline.lock().unwrap();
                pending.entry(signing_session_id).or_insert_with(Vec::new).push(message.clone());
            }
            log::info!("[TSS][DIAG][SignOnline][FALLBACK] Queued online sign request signing_session_id={} awaiting offline completion", signing_session_id);
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