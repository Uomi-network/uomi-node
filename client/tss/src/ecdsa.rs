use std::{
    collections::BTreeMap,
    sync::{RwLock, RwLockWriteGuard},
};

use multi_party_ecdsa::{
    communication::sending_messages::SendingMessages,
    protocols::multi_party::dmz21::{
        keygen::{KeyGenPhase, Parameters},
        sign::{SignPhase, SignPhaseOnline},
    },
};

use crate::types::SessionId;

pub const GENERIC_ERROR: &str = "Generic error";

#[derive(Debug)]
pub enum ECDSAError {
    KeygenNotFound,
    SignNotFound,
    SignOnlineNotFound,
    ECDSAError(String),
}
pub struct ECDSAManager {
    keygens: BTreeMap<SessionId, RwLock<KeyGenPhase>>,
    signs: BTreeMap<SessionId, RwLock<SignPhase>>,
    signs_online: BTreeMap<SessionId, RwLock<SignPhaseOnline>>,

    buffer_keygen: BTreeMap<SessionId, Vec<(String, Vec<u8>)>>,
    buffer_sign: BTreeMap<SessionId, Vec<(String, Vec<u8>)>>,
    buffer_sign_online: BTreeMap<SessionId, Vec<(String, Vec<u8>)>>,
}

impl ECDSAManager {
    pub fn new() -> Self {
        Self {
            keygens: BTreeMap::new(),
            signs: BTreeMap::new(),
            signs_online: BTreeMap::new(),
            buffer_keygen: BTreeMap::new(),
            buffer_sign: BTreeMap::new(),
            buffer_sign_online: BTreeMap::new(),
        }
    }

    pub fn add_keygen(
        &mut self,
        session_id: SessionId,
        party_id: String,
        party_ids: Vec<String>,
        t: usize,
        n: usize,
    ) -> Option<()> {
        let params = Parameters {
            threshold: t,
            share_count: n,
        };
        let keygen = KeyGenPhase::new(party_id, params, &Some(party_ids));

        if let Err(error) = keygen {
            log::error!("[TSS] Error creating keygen {:?}", error);
            return None;
        }

        let lock = RwLock::new(keygen.unwrap());

        self.keygens.insert(session_id, lock);

        Some(())
    }

    pub fn add_sign(
        &mut self,
        session_id: SessionId,
        party_id: String,
        subset: &Vec<String>,
        t: usize,
        n: usize,
        keys: &String,
    ) -> Option<()> {
        let params = Parameters {
            threshold: t.into(),
            share_count: n.into(),
        };
        let sign = SignPhase::new(party_id, params, subset, keys);

        if let Err(error) = sign {
            log::error!("[TSS] Error creating sign {:?}", error);
            return None;
        }
        let lock = RwLock::new(sign.unwrap());
        self.signs.insert(session_id, lock);
        Some(())
    }

    pub fn add_sign_online(
        &mut self,
        session_id: SessionId,
        offline_result: &String,
        message_bytes: Vec<u8>,
    ) -> Option<()> {
        let sign_online = SignPhaseOnline::new(offline_result, message_bytes);
        if let Err(error) = sign_online {
            log::error!("[TSS] Error creating sign online {:?}", error);
            return None;
        }
        let lock = RwLock::new(sign_online.unwrap());
        self.signs_online.insert(session_id, lock);
        Some(())
    }

    pub fn get_keygen(
        &mut self,
        session_id: SessionId,
    ) -> Option<RwLockWriteGuard<'_, KeyGenPhase>> {
        match self.keygens.get(&session_id) {
            Some(data) => Some(data.write().unwrap()),
            None => None,
        }
    }

    pub fn get_sign(&mut self, session_id: SessionId) -> Option<RwLockWriteGuard<'_, SignPhase>> {
        match self.signs.get(&session_id) {
            Some(data) => Some(data.write().unwrap()),
            None => None,
        }
    }
    pub fn get_sign_online(
        &mut self,
        session_id: SessionId,
    ) -> Option<RwLockWriteGuard<'_, SignPhaseOnline>> {
        match self.signs_online.get(&session_id) {
            Some(data) => Some(data.write().unwrap()),
            None => None,
        }
    }
    pub fn handle_keygen_message(
        &mut self,
        session_id: SessionId,
        index: String,
        message: &Vec<u8>,
    ) -> Result<SendingMessages, ECDSAError> {
        if let Some(mut keygen) = self.get_keygen(session_id) {
            log::info!("[TSS] handling key gen message");
            return keygen
                .msg_handler(index, message)
                .or_else(|e| Err(ECDSAError::ECDSAError(format!("{:?}", e))));
        }
        // buffer the messages and throw an error
        log::info!("[TSS] buffering message to keygen");
        self.buffer_keygen
            .entry(session_id)
            .or_insert(Vec::new())
            .push((index.clone(), message.clone()));
        Err(ECDSAError::KeygenNotFound)
    }

    pub fn handle_sign_message(
        &mut self,
        session_id: SessionId,
        index: String,
        message: &Vec<u8>,
    ) -> Result<SendingMessages, ECDSAError> {
        if let Some(mut sign) = self.get_sign(session_id) {
            log::info!("[TSS] handling Sign offline message");
            return sign
                .msg_handler(index, message)
                .or_else(|e| Err(ECDSAError::ECDSAError(format!("{:?}", e))));
        }

        // buffer the messages and throw an error
        log::info!("[TSS] buffering message to sign");
        self.buffer_sign
            .entry(session_id)
            .or_insert(Vec::new())
            .push((index.clone(), message.clone()));
        Err(ECDSAError::SignNotFound)
    }

    pub fn handle_sign_online_message(
        &mut self,
        session_id: SessionId,
        index: String,
        message: &Vec<u8>,
    ) -> Result<SendingMessages, ECDSAError> {
        if let Some(mut sign) = self.get_sign_online(session_id) {
            log::info!("[TSS] handling Sign online message");
            return sign
                .msg_handler(index, message)
                .or_else(|e| Err(ECDSAError::ECDSAError(format!("{:?}", e))));
        }
        log::info!("[TSS] buffering message to sign online");
        self.buffer_sign_online
            .entry(session_id)
            .or_insert(Vec::new())
            .push((index.clone(), message.clone()));
        Err(ECDSAError::SignOnlineNotFound)
    }

    pub fn handle_keygen_buffer(
        &mut self,
        session_id: SessionId,
    ) -> Result<Vec<SendingMessages>, ECDSAError> {
        if let Some(messages) = self.buffer_keygen.get(&session_id).cloned() {
            let results: Result<Vec<SendingMessages>, ECDSAError> = messages
                .into_iter()
                .map(|(index, message)| self.handle_keygen_message(session_id, index, &message))
                .collect();

            // Only remove the buffer if processing was successful
            if results.is_ok() {
                self.buffer_keygen.remove(&session_id);
            }

            results
        } else {
            Ok(Vec::new())
        }
    }

    pub fn handle_sign_buffer(
        &mut self,
        session_id: SessionId,
    ) -> Result<Vec<SendingMessages>, ECDSAError> {
        if let Some(messages) = self.buffer_sign.get(&session_id).cloned() {
            log::info!(
                "[TSS] handling sign buffer. buffer length is {:?}",
                messages.len()
            );
            let results: Result<Vec<SendingMessages>, ECDSAError> = messages
                .into_iter()
                .map(|(index, message)| self.handle_sign_message(session_id, index, &message))
                .collect();

            log::debug!("[TSS] Buffer completed");
            // Only remove the buffer if processing was successful
            if results.is_ok() {
                self.buffer_sign.remove(&session_id);
            }
            log::debug!("[TSS] Buffer cleared, returning results");

            results
        } else {
            Ok(Vec::new())
        }
    }

    pub fn handle_sign_online_buffer(
        &mut self,
        session_id: SessionId,
    ) -> Result<Vec<SendingMessages>, ECDSAError> {
        if let Some(messages) = self.buffer_sign_online.get(&session_id).cloned() {
            let results: Result<Vec<SendingMessages>, ECDSAError> = messages
                .into_iter()
                .map(|(index, message)| {
                    self.handle_sign_online_message(session_id, index, &message)
                })
                .collect();

            // Only remove the buffer if processing was successful
            if results.is_ok() {
                self.buffer_sign_online.remove(&session_id);
            }

            results
        } else {
            Ok(Vec::new())
        }
    }
}
