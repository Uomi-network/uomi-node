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

        let my_id = participants
            .iter()
            .position(|&el| el == &self.session_core.validator_key[..]);

        if let None = my_id {
            log::info!("[TSS] We are not allowed to participate");
            return;
        }

        log::info!("[TSS] My Id = {:?}", my_id.unwrap() + 1);

        let participant_indices: Vec<String> = (1..participants.len() + 1)
            .into_iter()
            .map(|el| el.to_string())
            .collect();

        let keygen = handler.add_keygen(
            id,
            (my_id.unwrap() + 1).to_string(),
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
        let mut handler = self.ecdsa_manager.lock().unwrap();


        let my_id = participants
            .iter()
            .position(|&el| el == &self.session_core.validator_key[..]);

        if let None = my_id {
            log::info!("[TSS] We are not allowed to participate");
            return;
        }
        log::info!("[TSS] My Id = {:?}", my_id.unwrap() + 1);

        let identifier: Identifier = u16::try_from(my_id.unwrap() + 1).unwrap().try_into().unwrap();

        let current_keys = self.storage_manager.key_storage.lock().unwrap().read_data(id, StorageType::EcdsaKeys, Some(&identifier.serialize()));

        let current_keys = match current_keys {
            Err(_) => None,
            Ok(keys) => Some(String::from_utf8(keys).unwrap()),
        };



        let reshare = handler.add_reshare(
            id,
            (my_id.unwrap() + 1).to_string(),
            (1..old_participants.len() + 1)
                .into_iter()
                .map(|el| el.to_string())
                .collect::<Vec<String>>(),
            (1..participants.len() + 1)
                .into_iter()
                .map(|el| el.to_string())
                .collect::<Vec<String>>(),
            t.into(),
            n.into(),
            current_keys,
        );

        if let Some(_) = reshare {
            let msg = {
                let mut reshare = handler.get_reshare(id).unwrap();
                reshare.process_begin()
            };

            match msg {
                Err(error) => log::error!("[TSS] Error beginning process {:?}", error),
                Ok(msg) => {
                    self.handle_ecdsa_sending_messages(id, msg, &mut handler, ECDSAPhase::Reshare)
                }
            }
        }
        drop(handler);
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
        let my_id = participants
            .iter()
            .position(|&el| el == &self.session_core.validator_key[..]);

        if let None = my_id {
            log::info!("[TSS] We are not allowed to participate");
            return;
        }

        let my_id = my_id.unwrap() + 1;
        let identifier: Identifier = u16::try_from(my_id).unwrap().try_into().unwrap();

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