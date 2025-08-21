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

        let keygen = self.get_keygen(session_id);

        if keygen.is_some() {
            log::info!("[TSS] handling key gen message");
            let mut keygen = keygen.unwrap();
            log::info!("[tss] 1");
            let to_ret = keygen
                .msg_handler(index.get_index(), message)
                .or_else(|e| Err(ECDSAError::KeygenMsgHandlerError(format!("{:?}", e), index.clone())));
            log::info!("[tss] 2");

            drop(keygen);
            log::info!("[tss] 3");
            return to_ret;
        }
        drop(keygen);
        // buffer the messages and throw an error
        log::info!("[TSS] buffering message to keygen");
        self.buffer_keygen
            .entry(session_id)
            .or_insert(Vec::new())
            .push((index, message.clone()));
        Err(ECDSAError::KeygenNotFound)
    }

    pub fn handle_sign_message(
        &mut self,
        session_id: SessionId,
        index: ECDSAIndexWrapper,
        message: &Vec<u8>,
    ) -> Result<SendingMessages, ECDSAError> {
        if let Some(mut sign) = self.get_sign(session_id) {
            log::info!("[TSS] handling Sign offline message");
            return sign
                .msg_handler(index.get_index(), message)
                .or_else(|e| Err(ECDSAError::SignMsgHandlerError(format!("{:?}", e), index.clone())));
        }

        // buffer the messages and throw an error
        log::info!("[TSS] buffering message to sign");
        self.buffer_sign
            .entry(session_id)
            .or_insert(Vec::new())
            .push((index, message.clone()));
        Err(ECDSAError::SignNotFound)
    }

    pub fn handle_sign_online_message(
        &mut self,
        session_id: SessionId,
        index: ECDSAIndexWrapper,
        message: &Vec<u8>,
    ) -> Result<SendingMessages, ECDSAError> {
        if let Some(mut sign) = self.get_sign_online(session_id) {
            log::info!("[TSS] handling Sign online message");
            return sign
                .msg_handler(index.get_index(), message)
                .or_else(|e| Err(ECDSAError::SignOnlineMsgHandlerError(format!("{:?}", e), index.clone())));
        }
        log::info!("[TSS] buffering message to sign online");
        self.buffer_sign_online
            .entry(session_id)
            .or_insert(Vec::new())
            .push((index, message.clone()));
        Err(ECDSAError::SignOnlineNotFound)
    }

    pub fn handle_keygen_buffer(
        &mut self,
        session_id: SessionId,
    ) -> Result<Vec<SendingMessages>, ECDSAError> {
        log::info!("[tss] 3.1");
        if let Some(messages) = self.buffer_keygen.get(&session_id).cloned() {
            log::info!("4");
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
        if let Some(mut reshare) = self.get_reshare(session_id) {
            log::info!("[TSS] handling reshare message");
            return reshare
                .msg_handler(index.get_index(), message)
                .or_else(|e| Err(ECDSAError::ReshareMsgHandlerError(format!("{:?}", e), index.clone())));
        }
        Err(ECDSAError::ReshareNotFound)
    }
}