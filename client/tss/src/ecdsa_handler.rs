use std::sync::{Arc, Mutex, MutexGuard};
use frost_ed25519::Identifier;
use sc_network::PeerId;
use crate::dkghelpers::{StorageType, FileStorage, Storage};
use crate::{
    SessionId, TSSParticipant, TSSPublic, TSSPeerId, ECDSAManager, ECDSAPhase, ECDSAIndexWrapper,
    PeerMapper, SendingMessages
};

/// Handles ECDSA-specific protocol operations
pub struct ECDSAHandler {
    ecdsa_manager: Arc<Mutex<ECDSAManager>>,
    peer_mapper: Arc<Mutex<PeerMapper>>,
    key_storage: Arc<Mutex<FileStorage>>,
    local_peer_id: TSSPeerId,
    validator_key: TSSPublic,
    session_manager_to_gossip_tx: sc_utils::mpsc::TracingUnboundedSender<(PeerId, crate::TssMessage)>,
}

impl ECDSAHandler {
    pub fn new(
        ecdsa_manager: Arc<Mutex<ECDSAManager>>,
        peer_mapper: Arc<Mutex<PeerMapper>>,
        key_storage: Arc<Mutex<FileStorage>>,
        local_peer_id: TSSPeerId,
        validator_key: TSSPublic,
        session_manager_to_gossip_tx: sc_utils::mpsc::TracingUnboundedSender<(PeerId, crate::TssMessage)>,
    ) -> Self {
        Self {
            ecdsa_manager,
            peer_mapper,
            key_storage,
            local_peer_id,
            validator_key,
            session_manager_to_gossip_tx,
        }
    }

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
            .position(|&el| el == &self.validator_key[..]);

        if let None = my_id {
            log::info!("[TSS] We are not allowed to participate");
            return;
        }

        log::info!("[TSS] My Id = {:?}", my_id.unwrap() + 1);

        let keygen = handler.add_keygen(
            id,
            (my_id.unwrap() + 1).to_string(),
            (1..participants.len() + 1)
                .into_iter()
                .map(|el| el.to_string())
                .collect::<Vec<String>>(),
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
        let session_id = id;

        let my_id = participants
            .iter()
            .position(|&el| el == &self.validator_key[..]);

        let my_old_id = old_participants
            .iter()
            .position(|&el| el == &self.validator_key[..]);

        if let None = my_id {
            if let None = my_old_id {
                log::info!("[TSS] We are not allowed to participate");
                return;
            }
        }

        log::info!("[TSS] My Id = {:?}", my_id);
        log::info!("[TSS] My Old Id = {:?}", my_old_id);

        let identifier: Option<Identifier> = my_old_id.map(|id| u16::try_from(id + 1).unwrap().try_into().unwrap());

        let current_keys = if let Some(id) = identifier {
            let storage = self.key_storage.lock().unwrap();
            let result = storage.read_data(session_id, StorageType::EcdsaKeys, Some(&id.serialize()));
            drop(storage);
            match result {
                Err(_) => None,
                Ok(keys) => Some(String::from_utf8(keys).unwrap()),
            }
        } else {
            None
        };

        let reshare = handler.add_reshare(
            id,
            my_id.map(|id| (id + 1).to_string()).unwrap_or_default(),
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

    fn ecdsa_create_sign_offline_phase(
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

    fn ecdsa_create_sign_phase(
        &self,
        id: SessionId,
        participants: Vec<TSSParticipant>,
        message: Vec<u8>,
    ) {
        let my_id = participants
            .iter()
            .position(|&el| el == &self.validator_key[..]);

        if let None = my_id {
            log::info!("[TSS] We are not allowed to participate");
            return;
        }

        let my_id = my_id.unwrap() + 1;
        let identifier: Identifier = u16::try_from(my_id).unwrap().try_into().unwrap();

        let mut handler = self.ecdsa_manager.lock().unwrap();
        let storage = self.key_storage.lock().unwrap();

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

    pub fn handle_ecdsa_sending_messages(
        &self,
        session_id: SessionId,
        sending_messages: SendingMessages,
        ecdsa_manager: &mut std::sync::MutexGuard<'_, ECDSAManager>,
        phase: ECDSAPhase,
    ) {
        match sending_messages {
            SendingMessages::P2pMessage(msg) => {
                log::info!("[TSS] SendingMessages::P2pMessage");
                let mut peer_mapper = self.peer_mapper.lock().unwrap();
                let index = peer_mapper
                    .get_id_from_peer_id(
                        &session_id,
                        &sc_network::PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
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
                    let mut peer_mapper = self.peer_mapper.lock().unwrap();
                    let recipient = peer_mapper
                        .get_peer_id_from_id(&session_id, id.parse::<u16>().unwrap());
                    drop(peer_mapper);
                    log::info!("[TSS] Dropped lock on mapper");

                    if let Some(recipient) = recipient {
                        if let Err(error) = self.session_manager_to_gossip_tx.unbounded_send((
                            recipient.clone(),
                            crate::TssMessage::ECDSAMessageP2p(
                                session_id,
                                index.unwrap().to_string(),
                                recipient.to_bytes(),
                                data,
                                phase.clone(),
                            ),
                        )) {
                            log::error!("[TSS] Error sending message {:?}", error);
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

                let mut peer_mapper = self.peer_mapper.lock().unwrap();
                log::debug!("[TSS] SendingMessages::BroadcastMessage, lock acquired");

                let index = peer_mapper
                    .get_id_from_peer_id(
                        &session_id,
                        &sc_network::PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
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

                self.session_manager_to_gossip_tx
                    .unbounded_send((
                        sc_network::PeerId::from_bytes(&self.local_peer_id).unwrap(),
                        crate::TssMessage::ECDSAMessageBroadcast(
                            session_id,
                            index.unwrap().to_string(),
                            msg,
                            phase.clone(),
                        ),
                    ))
                    .unwrap();
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

                let mut storage = self.key_storage.lock().unwrap();

                if let Err(error) = storage.store_data(
                    session_id,
                    StorageType::EcdsaKeys,
                    &msg.as_bytes(),
                    Some(&_id.serialize()),
                ) {
                    log::error!("[TSS] There was an error storing keys {:?}", error);
                    return;
                }

                let mut peer_mapper = self.peer_mapper.lock().unwrap();

                let index = peer_mapper
                    .get_id_from_peer_id(
                        &session_id,
                        &sc_network::PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
                    )
                    .clone();

                drop(peer_mapper);
                drop(storage);

                if let None = index {
                    log::error!("[TSS] Index is not, shouldn't have happened, returning");
                    return;
                }

                log::info!("[TSS] Successfully generated ECDSA key for session {}", session_id);
            }
            SendingMessages::ReshareKeySuccessWithResult(msg) =>{
                let _id = self.get_my_identifier(session_id);
                log::info!("[TSS] ECDSA Reshare successful, storing keys {:?}", msg);

                let mut storage = self.key_storage.lock().unwrap();

                if let Err(error) = storage.store_data(
                    session_id,
                    StorageType::EcdsaKeys,
                    &msg.as_bytes(),
                    Some(&_id.serialize()),
                ) {
                    log::error!("[TSS] There was an error storing keys {:?}", error);
                    return;
                }

                let mut peer_mapper = self.peer_mapper.lock().unwrap();

                let index = peer_mapper
                    .get_id_from_peer_id(
                        &session_id,
                        &sc_network::PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
                    )
                    .clone();
                drop(peer_mapper);
                drop(storage);

                if let None = index {
                    log::error!("[TSS] Index is not, shouldn't have happened, returning");
                    return;
                }

                log::info!("[TSS] Successfully completed ECDSA reshare for session {}", session_id);
            }
            SendingMessages::SignOfflineSuccessWithResult(msg) => {
                log::debug!("[TSS] SendingMessages::SignOfflineSuccessWithResult");
                let _id = self.get_my_identifier(session_id);

                let mut storage = self.key_storage.lock().unwrap();

                if let Err(error) = storage.store_data(
                    session_id,
                    StorageType::EcdsaOfflineOutput,
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

                let mut storage = self.key_storage.lock().unwrap();

                if let Err(error) = storage.store_data(
                    session_id,
                    StorageType::EcdsaOnlineOutput,
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

    fn get_my_identifier(
        &self,
        session_id: u64,
    ) -> Identifier {
        let mut peer_mapper = self.peer_mapper.lock().unwrap();

        let index = peer_mapper
            .get_id_from_peer_id(
                &session_id,
                &sc_network::PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
            )
            .clone();

        drop(peer_mapper);

        let _id = index.unwrap();
        log::info!("[TSS] My Id is {:?}", _id);
        let _id: Identifier = _id.try_into().unwrap();
        _id
    }

    pub fn handle_buffer_and_sending_messages_for_keygen(
        &self,
        session_id: &SessionId,
        msg: &Vec<u8>,
        manager: &mut std::sync::MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, crate::ecdsa::ECDSAError>, ECDSAPhase) {
        match manager.handle_keygen_buffer(*session_id) {
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
        session_id: &SessionId,
        msg: &Vec<u8>,
        manager: &mut std::sync::MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, crate::ecdsa::ECDSAError>, ECDSAPhase) {
        match manager.handle_reshare_buffer(*session_id) {
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

    pub fn handle_buffer_and_sending_messages_for_sign_offline(
        &self,
        session_id: &SessionId,
        msg: &Vec<u8>,
        manager: &mut std::sync::MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, crate::ecdsa::ECDSAError>, ECDSAPhase) {
        match manager.handle_sign_buffer(*session_id) {
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

    pub fn handle_buffer_and_sending_messages_for_sign_online(
        &self,
        session_id: &SessionId,
        msg: &Vec<u8>,
        manager: &mut std::sync::MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, crate::ecdsa::ECDSAError>, ECDSAPhase) {
        match manager.handle_sign_online_buffer(*session_id) {
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
}