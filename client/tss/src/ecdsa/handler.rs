use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use crate::types::SessionId;
use super::{ECDSAManager, ECDSAError, ECDSAIndexWrapper};

impl ECDSAManager {
    pub fn handle_keygen_message(
        &mut self,
        session_id: SessionId,
        index: ECDSAIndexWrapper,
        message: &Vec<u8>,
    ) -> Result<SendingMessages, ECDSAError> {
        println!("TSS: handle_keygen_message from index {:?}", index.get_index());
        log::debug!(
            "[TSS][ECDSA][Keygen] Incoming keygen message session_id={} from index={} message_len={}",
            session_id,
            index.get_index(),
            message.len()
        );

        let keygen = self.get_keygen(session_id);

        if keygen.is_some() {
            log::debug!("[TSS] handling key gen message");
            let mut keygen = keygen.unwrap();
            log::debug!("[TSS] 1");
            let to_ret = keygen
                .msg_handler(index.get_index(), message)
                .or_else(|e| Err(ECDSAError::KeygenMsgHandlerError(format!("{:?}", e), index.clone())));
            log::debug!("[TSS] 2");

            // Debug log the to_ret
            if let Ok(ref sm) = to_ret {
                log::debug!(
                    "[TSS][ECDSA][Keygen] msg_handler returned variant={:?}",
                    std::mem::discriminant(sm)
                );
            } else if let Err(ref e) = to_ret {
                log::error!("[TSS][ECDSA][Keygen] msg_handler error: {:?}", e);
            }

            drop(keygen);
            log::debug!("[TSS] 3");
            self.log_internal_state(session_id, "post-handle_keygen_message");
            return to_ret;
        }
        drop(keygen);
        // buffer the messages and throw an error
        log::debug!("[TSS] buffering message to keygen");
        self.buffer_keygen
            .entry(session_id)
            .or_insert(Vec::new())
            .push((index, message.clone()));
        self.log_internal_state(session_id, "buffered-keygen-message");
        Err(ECDSAError::KeygenNotFound)
    }

    pub fn handle_sign_message(
        &mut self,
        session_id: SessionId,
        index: ECDSAIndexWrapper,
        message: &Vec<u8>,
    ) -> Result<SendingMessages, ECDSAError> {
        log::debug!(
            "[TSS][ECDSA][SignOffline] Incoming sign-offline message session_id={} from index={} len={}",
            session_id,
            index.get_index(),
            message.len()
        );
        if self.get_sign(session_id).is_some() {
            // Inner scope to ensure the write guard is dropped before logging.
            let res = {
                let mut sign = self.get_sign(session_id).expect("sign phase exists");
                log::debug!("[TSS] handling Sign offline message");
                let r = sign
                    .msg_handler(index.get_index(), message)
                    .or_else(|e| Err(ECDSAError::SignMsgHandlerError(format!("{:?}", e), index.clone())));
                match &r {
                    Ok(sm) => log::debug!("[TSS][ECDSA][SignOffline] msg_handler returned variant={:?}", std::mem::discriminant(sm)),
                    Err(e) => log::error!("[TSS][ECDSA][SignOffline] msg_handler error: {:?}", e),
                }
                r
            }; // guard dropped here
            self.log_internal_state(session_id, "post-handle_sign_offline_message");
            return res;
        }
        log::debug!("[TSS] buffering message to sign");
        self.buffer_sign
            .entry(session_id)
            .or_insert(Vec::new())
            .push((index, message.clone()));
        self.log_internal_state(session_id, "buffered-sign-offline-message");
        Err(ECDSAError::SignNotFound)
    }

    pub fn handle_sign_online_message(
        &mut self,
        session_id: SessionId,
        index: ECDSAIndexWrapper,
        message: &Vec<u8>,
    ) -> Result<SendingMessages, ECDSAError> {
        log::debug!(
            "[TSS][ECDSA][SignOnline] Incoming sign-online message session_id={} from index={} len={}",
            session_id,
            index.get_index(),
            message.len()
        );
        if self.get_sign_online(session_id).is_some() {
            let res = {
                let mut sign = self.get_sign_online(session_id).expect("sign online phase exists");
                log::debug!("[TSS] handling Sign online message");
                let r = sign
                    .msg_handler(index.get_index(), message)
                    .or_else(|e| Err(ECDSAError::SignOnlineMsgHandlerError(format!("{:?}", e), index.clone())));
                match &r {
                    Ok(sm) => log::debug!("[TSS][ECDSA][SignOnline] msg_handler returned variant={:?}", std::mem::discriminant(sm)),
                    Err(e) => log::error!("[TSS][ECDSA][SignOnline] msg_handler error: {:?}", e),
                }
                r
            }; // guard dropped
            self.log_internal_state(session_id, "post-handle_sign_online_message");
            return res;
        }
        log::debug!("[TSS] buffering message to sign online");
        self.buffer_sign_online
            .entry(session_id)
            .or_insert(Vec::new())
            .push((index, message.clone()));
        self.log_internal_state(session_id, "buffered-sign-online-message");
        Err(ECDSAError::SignOnlineNotFound)
    }

    pub fn handle_keygen_buffer(
        &mut self,
        session_id: SessionId,
    ) -> Result<Vec<SendingMessages>, ECDSAError> {
        log::debug!("[TSS] 3.1");
        if let Some(messages) = self.buffer_keygen.get(&session_id).cloned() {
            log::info!("4");
            log::debug!(
                "[TSS][ECDSA][Keygen] Processing keygen buffer session_id={} size={}",
                session_id,
                messages.len()
            );
            let results: Result<Vec<SendingMessages>, ECDSAError> = messages
                .into_iter()
                .map(|(index, message)| self.handle_keygen_message(session_id, index, &message))
                .collect();

            // Only remove the buffer if processing was successful
            if results.is_ok() {
                self.buffer_keygen.remove(&session_id);
                log::debug!(
                    "[TSS][ECDSA][Keygen] Cleared keygen buffer session_id={}",
                    session_id
                );
            }

            results
        } else {
            Ok(Vec::new())
        }
    }

    pub fn handle_reshare_buffer(
        &mut self,
        session_id: SessionId,
    ) -> Result<Vec<SendingMessages>, ECDSAError> {
        if let Some(messages) = self.buffer_reshare.get(&session_id).cloned() {
            let results: Result<Vec<SendingMessages>, ECDSAError> = messages
                .into_iter()
                .map(|(index, message)| self.handle_reshare_message(session_id, index, &message))
                .collect();

            // Only remove the buffer if processing was successful
            if results.is_ok() {
                self.buffer_reshare.remove(&session_id);
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

    pub fn handle_reshare_message(
        &mut self,
        session_id: SessionId,
        index: ECDSAIndexWrapper,
        message: &Vec<u8>,
    ) -> Result<SendingMessages, ECDSAError> {
        log::debug!(
            "[TSS][ECDSA][Reshare] Incoming reshare message session_id={} from index={} len={}",
            session_id,
            index.get_index(),
            message.len()
        );
        let res = if let Some(mut reshare) = self.get_reshare(session_id) {
            log::debug!("[TSS] handling reshare message");
            let inner = reshare
                .msg_handler(index.get_index(), message)
                .or_else(|e| Err(ECDSAError::ReshareMsgHandlerError(format!("{:?}", e), index.clone())));
            match &inner {
                Ok(sm) => log::debug!("[TSS][ECDSA][Reshare] msg_handler returned variant={:?}", std::mem::discriminant(sm)),
                Err(e) => log::error!("[TSS][ECDSA][Reshare] msg_handler error: {:?}", e),
            }
            inner
        } else {
            Err(ECDSAError::ReshareNotFound)
        };
        match &res { Ok(_) => self.log_internal_state(session_id, "post-handle_reshare_message"), Err(_) => self.log_internal_state(session_id, "missing-reshare-phase") };
        res
    }

    /// Log concise internal state for a given session to aid debugging stuck flows
    pub fn log_internal_state(&self, session_id: SessionId, context: &str) {
        let keygen_present = self.keygens.contains_key(&session_id);
        let reshare_present = self.reshares.contains_key(&session_id);
        let sign_present = self.signs.contains_key(&session_id);
        let sign_online_present = self.signs_online.contains_key(&session_id);
        let buf_keygen = self.buffer_keygen.get(&session_id).map(|v| v.len()).unwrap_or(0);
        let buf_reshare = self.buffer_reshare.get(&session_id).map(|v| v.len()).unwrap_or(0);
        let buf_sign = self.buffer_sign.get(&session_id).map(|v| v.len()).unwrap_or(0);
        let buf_sign_online = self.buffer_sign_online.get(&session_id).map(|v| v.len()).unwrap_or(0);
        log::debug!(
            "[TSS][ECDSA][State] ctx={} session_id={} keygen={} reshare={} sign={} sign_online={} buffers[keygen={},reshare={},sign={},sign_online={}]",
            context,
            session_id,
            keygen_present,
            reshare_present,
            sign_present,
            sign_online_present,
            buf_keygen,
            buf_reshare,
            buf_sign,
            buf_sign_online
        );
    }
}