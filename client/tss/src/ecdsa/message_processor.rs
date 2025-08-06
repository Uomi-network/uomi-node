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
use sc_network::PeerId;

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
        (
            manager.handle_keygen_message(*session_id, index, &msg),
            ECDSAPhase::Key,
        )
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
        (
            manager.handle_reshare_message(*session_id, index, &msg),
            ECDSAPhase::Reshare,
        )
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
        let index = peer_mapper
            .get_id_from_peer_id(
                session_id,
                &PeerId::from_bytes(&self.session_core.local_peer_id[..]).unwrap(),
            )
            .clone();
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
        } else {
            log::error!("[TSS] Recipient not found {:#?} (id: {:?})", recipient, recipient_id);
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
            return;
        }

        let index = match self.get_local_index(&session_id) {
            Some(idx) => idx,
            None => {
                log::error!("[TSS] Index is not, shouldn't have happened, returning");
                return;
            }
        };

        if let Err(err) = self.client.submit_dkg_result(self.client.best_hash(), session_id, msg.as_bytes().to_vec()) {
            log::error!("[TSS] Error submitting DKG result to chain: {:?}", err);
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
    }

    pub fn get_my_identifier(
        &self,
        session_id: u64,
    ) -> frost_core::Identifier<frost_ed25519::Ed25519Sha512> {
        let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();

        let index = peer_mapper
            .get_id_from_peer_id(
                &session_id,
                &PeerId::from_bytes(&self.session_core.local_peer_id[..]).unwrap(),
            )
            .clone();

        drop(peer_mapper);

        let _id = index.unwrap();
        log::info!("[TSS] My Id is {:?}", _id);
        let _id: frost_ed25519::Identifier = _id.try_into().unwrap();
        _id
    }
}
