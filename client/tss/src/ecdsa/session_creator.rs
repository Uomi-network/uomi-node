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
        let mut handler = self.ecdsa_manager.lock().unwrap();

        // Resolve our stable session index using PeerMapper (validator_id-backed), not array position
        let my_id: Option<u16> = {
            let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
            peer_mapper.get_id_from_account_id(&id, &self.session_core.validator_key)
        };

        if my_id.is_none() {
            log::info!("[TSS] We are not allowed to participate");
            return;
        }

        let my_id = my_id.unwrap();
        log::info!("[TSS] My Id = {:?}", my_id);

        let participant_indices: Vec<String> = (1..participants.len() + 1)
            .into_iter()
            .map(|el| el.to_string())
            .collect();

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
                keygen.process_begin()
            };

            match msg {
                Err(error) => log::error!("[TSS] Error beginning process {:?}", error),
                Ok(msg) => {
                    self.handle_ecdsa_sending_messages(id, msg, &mut handler, ECDSAPhase::Key)
                }
            }
        }
        drop(handler);
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
        (1..=participants.len())
            .map(|el| el.to_string())
            .collect()
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
        let sign_offline = ecdsa_manager.add_sign(
            id,
            index,
            &(1..n+1)
                .into_iter()
                .map(|el| el.to_string())
                .collect::<Vec<String>>(),
            t.into(),
            n.into(),
            &keys,
        );

        if let Some(_) = sign_offline {
            let msg = {
                let sign_offline = ecdsa_manager.get_sign(id);
                if let None = sign_offline {
                    return;
                }
                sign_offline.unwrap().process_begin()
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
            log::info!("[TSS] There was an error generating the signing phase");
        }
    }

    pub fn ecdsa_create_sign_phase(
        &self,
        id: SessionId,
        participants: Vec<TSSParticipant>,
        message: Vec<u8>,
    ) {
        // Use PeerMapper-provided index for this session
        let my_id = match self.get_my_index(id) {
            Some(idx) => idx,
            None => {
                log::info!("[TSS] We are not allowed to participate");
                return;
            }
        };
        let identifier: Identifier = my_id.try_into().unwrap();

        let mut handler = self.ecdsa_manager.lock().unwrap();
        let storage = self.storage_manager.key_storage.lock().unwrap();

        let offline_result =
            storage.read_data(id, StorageType::EcdsaOfflineOutput, Some(&identifier.serialize()));

        if let Err(error) = offline_result {
            log::error!("[TSS] Error fetching keys {:?}", error);
            return;
        }

        drop(storage);

        let sign_online = handler.add_sign_online(
            id,
            &String::from_utf8(offline_result.unwrap()).unwrap(),
            message,
        );

        if let None = sign_online {
            log::error!("[TSS] There was an error generating the signing phase");
        }

        if let Some(_) = sign_online {
            let msg = {
                let mut sign_online_handle = handler.get_sign_online(id).unwrap();
                sign_online_handle.process_begin()
            };

            if let Err(error) = msg {
                log::error!("[TSS] Error beginning process {:?}", error);
                return;
            }

            self.handle_ecdsa_sending_messages(
                id,
                msg.unwrap(),
                &mut handler,
                ECDSAPhase::SignOnline,
            );
        }
        drop(handler);
    }
}