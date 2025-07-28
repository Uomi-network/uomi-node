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
                log::info!("[TSS] SendingMessages::P2pMessage");
                let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
                let index = peer_mapper
                    .get_id_from_peer_id(
                        &session_id,
                        &PeerId::from_bytes(&self.session_core.local_peer_id[..]).unwrap(),
                    )
                    .clone();
                drop(peer_mapper);

                if let None = index {
                    log::error!("[TSS] We are not allowed in this session {:?}", session_id);
                    return;
                }

                for (id, data) in msg {
                    if id == index.unwrap().to_string() {
                        let sending_messages_after_handling = match phase {
                            ECDSAPhase::Key => match self
                                .handle_buffer_and_sending_messages_for_keygen(
                                    &session_id,
                                    &data,
                                    ecdsa_manager,
                                    ECDSAIndexWrapper(id),
                                ) {
                                (Err(error), _) => {
                                    log::error!("[TSS] Error sending messages {:?}", error);
                                    None
                                }
                                (Ok(sending_messages), _) => Some(sending_messages),
                            },
                            ECDSAPhase::Reshare => match self
                                .handle_buffer_and_sending_messages_for_reshare(
                                    &session_id,
                                    &data,
                                    ecdsa_manager,
                                    ECDSAIndexWrapper(id),
                                ) {
                                (Err(error), _) => {
                                    log::error!("[TSS] Error sending messages {:?}", error);
                                    None
                                } 
                                (Ok(sending_messages), _) => Some(sending_messages),
                            },
                            ECDSAPhase::Sign => match self
                                .handle_buffer_and_sending_messages_for_sign_offline(
                                    &session_id,
                                    &data,
                                    ecdsa_manager,
                                    ECDSAIndexWrapper(id),
                                ) {
                                (Err(error), _) => {
                                    log::error!("[TSS] Error sending messages {:?}", error);
                                    None
                                }
                                (Ok(sending_messages), _) => Some(sending_messages),
                            },
                            ECDSAPhase::SignOnline => match self
                                .handle_buffer_and_sending_messages_for_sign_online(
                                    &session_id,
                                    &data,
                                    ecdsa_manager,
                                    ECDSAIndexWrapper(id),
                                ) {
                                (Err(error), _) => {
                                    log::error!("[TSS] Error sending messages {:?}", error);
                                    None
                                }
                                (Ok(sending_messages), _) => Some(sending_messages),
                            },
                        };

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

                    log::info!("[TSS] Acquired lock on mapper");
                    let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
                    let recipient = peer_mapper
                        .get_peer_id_from_id(&session_id, id.parse::<u16>().unwrap())
                        .cloned();
                    drop(peer_mapper);
                    log::info!("[TSS] Dropped lock on mapper");

                    if let Some(recipient) = recipient {
                        let ecdsa_message = crate::types::TssMessage::ECDSAMessageP2p(
                            session_id,
                            index.unwrap().to_string(),
                            recipient.to_bytes(),
                            data,
                            phase.clone(),
                        );
                        if let Err(error) = self.send_signed_message(ecdsa_message) {
                            log::error!("[TSS] Error sending signed ECDSA P2P message: {:?}", error);
                        }
                    } else {
                        log::error!("[TSS] Recipient not found {:#?} (id: {:?})", recipient, id);
                    }
                }
            }
            SendingMessages::BroadcastMessage(msg) | SendingMessages::SubsetMessage(msg) => {
                log::info!(
                    "[TSS] SendingMessages::BroadcastMessage, acquiring lock on peer mapper"
                );

                let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
                log::debug!("[TSS] SendingMessages::BroadcastMessage, lock acquired");

                let index = peer_mapper
                    .get_id_from_peer_id(
                        &session_id,
                        &PeerId::from_bytes(&self.session_core.local_peer_id[..]).unwrap(),
                    )
                    .clone();

                                drop(peer_mapper);
                log::debug!("[TSS] SendingMessages::BroadcastMessage, lock dropped");

                if let None = index {
                    log::error!("[TSS] We are not allowed in this session {:?}", session_id);
                    return;
                }

                log::debug!(
                    "[TSS] SendingMessages::BroadcastMessage, phase = {:?}",
                    phase
                );

                let sending_messages = match phase {
                    ECDSAPhase::Key => match self.handle_buffer_and_sending_messages_for_keygen(
                        &session_id,
                        &msg,
                        ecdsa_manager,
                        ECDSAIndexWrapper(index.unwrap().to_string()),
                    ) {
                        (Err(error), _) => {
                            log::error!("[TSS] Error sending messages {:?}", error);
                            None
                        }
                        (Ok(sending_messages), _) => Some(sending_messages),
                    },
                    ECDSAPhase::Reshare => match self
                        .handle_buffer_and_sending_messages_for_reshare(
                            &session_id,
                            &msg,
                            ecdsa_manager,
                            ECDSAIndexWrapper(index.unwrap().to_string()),
                        ) {
                        (Err(error), _) => {
                            log::error!("[TSS] Error sending messages {:?}", error);
                            None
                        }
                        (Ok(sending_messages), _) => Some(sending_messages),
                    },
                    ECDSAPhase::Sign => match self
                        .handle_buffer_and_sending_messages_for_sign_offline(
                            &session_id,
                            &msg,
                            ecdsa_manager,
                            ECDSAIndexWrapper(index.unwrap().to_string()),
                        ) {
                        (Err(error), _) => {
                            log::error!("[TSS] Error sending messages {:?}", error);
                            None
                        }
                        (Ok(sending_messages), _) => Some(sending_messages),
                    },
                    ECDSAPhase::SignOnline => match self
                        .handle_buffer_and_sending_messages_for_sign_online(
                            &session_id,
                            &msg,
                            ecdsa_manager,
                            ECDSAIndexWrapper(index.unwrap().to_string()),
                        ) {
                        (Err(error), _) => {
                            log::error!("[TSS] Error sending messages {:?}", error);
                            None
                        }
                        (Ok(sending_messages), _) => Some(sending_messages),
                    },
                };
                log::debug!(
                    "[TSS] SendingMessages::BroadcastMessage, done, sending message to gossip"
                );

                let broadcast_message = crate::types::TssMessage::ECDSAMessageBroadcast(
                    session_id,
                    index.unwrap().to_string(),
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
            SendingMessages::KeyGenSuccessWithResult(msg) => {
                let _id = self.get_my_identifier(session_id);

                log::info!("[TSS] ECDSA Keygen successful, storing keys {:?}", msg);

                let mut storage: MutexGuard<'_, crate::dkghelpers::FileStorage> = self.storage_manager.key_storage.lock().unwrap();

                if let Err(error) = storage.store_data(
                    session_id,
                    crate::dkghelpers::StorageType::EcdsaKeys,
                    &msg.as_bytes(),
                    Some(&_id.serialize()),
                ) {
                    log::error!("[TSS] There was an error storing keys {:?}", error);
                    return;
                }

                let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();

                let index = peer_mapper
                    .get_id_from_peer_id(
                        &session_id,
                        &PeerId::from_bytes(&self.session_core.local_peer_id[..]).unwrap(),
                    )
                    .clone();

                drop(peer_mapper);
                drop(storage);

                if let None = index {
                    log::error!("[TSS] Index is not, shouldn't have happened, returning");
                    return;
                }

                // Publish to the chain
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
                            index.unwrap().to_string(),
                            ecdsa_manager,
                        );
                    }
                    None => {
                        log::error!("[TSS] Session data not found, returning");
                        return;
                    }
                };
            }
            SendingMessages::ReshareKeySuccessWithResult(msg) =>{
                let _id = self.get_my_identifier(session_id);
                log::info!("[TSS] ECDSA Reshare successful, storing keys {:?}", msg);

                let mut storage: MutexGuard<'_, crate::dkghelpers::FileStorage> = self.storage_manager.key_storage.lock().unwrap();

                if let Err(error) = storage.store_data(
                    session_id,
                    crate::dkghelpers::StorageType::EcdsaKeys,
                    &msg.as_bytes(),
                    Some(&_id.serialize()),
                ) {
                    log::error!("[TSS] There was an error storing keys {:?}", error);
                    return;
                }

                let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();

                let index = peer_mapper
                    .get_id_from_peer_id(
                        &session_id,
                        &PeerId::from_bytes(&self.session_core.local_peer_id[..]).unwrap(),
                    )
                    .clone();
                drop(peer_mapper);
                drop(storage);


                if let None = index {
                    log::error!("[TSS] Index is not, shouldn't have happened, returning");
                    return;
                }

                let session_data = self.get_session_data(&session_id);

                match session_data {
                    Some((t, n, _coordinator, _message)) => {
                        self.ecdsa_create_sign_offline_phase(
                            session_id,
                            t,
                            n,
                            msg,
                            index.unwrap().to_string(),
                            ecdsa_manager,
                        );
                    }
                    None => {
                        log::error!("[TSS] Session data not found, returning");
                        return;
                    }
                };
            }
            SendingMessages::SignOfflineSuccessWithResult(msg) => {
                log::debug!("[TSS] SendingMessages::SignOfflineSuccessWithResult");
                let _id = self.get_my_identifier(session_id);

                let mut storage = self.storage_manager.key_storage.lock().unwrap();

                if let Err(error) = storage.store_data(
                    session_id,
                    crate::dkghelpers::StorageType::EcdsaOfflineOutput,
                    &msg.as_bytes(),
                    Some(&_id.serialize()),
                ) {
                    log::error!("[TSS] There was an error storing keys {:?}", error);
                    return;
                }

                drop(storage);
            }
            SendingMessages::SignOnlineSuccessWithResult(msg) => {
                log::debug!("[TSS] SendingMessages::SignOnlineSuccessWithResult");
                let _id = self.get_my_identifier(session_id);

                let mut storage = self.storage_manager.key_storage.lock().unwrap();

                if let Err(error) = storage.store_data(
                    session_id,
                    crate::dkghelpers::StorageType::EcdsaOnlineOutput,
                    &msg.as_bytes(),
                    Some(&_id.serialize()),
                ) {
                    log::error!("[TSS] There was an error storing keys {:?}", error);
                    return;
                }

                drop(storage);
            }
            msg => log::debug!(
                "[TSS] Other message in handle_ecdsa_sending_messages {:?}",
                msg
            ),
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