use std::sync::RwLockWriteGuard;
use multi_party_ecdsa::protocols::multi_party::dmz21::{keygen::{KeyGenPhase, Parameters}, sign::{SignPhase, SignPhaseOnline}, reshare::ReshareKeyPhase};
use crate::types::SessionId;
use super::{ECDSAManager};

impl ECDSAManager {
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

        let lock = std::sync::RwLock::new(keygen.unwrap());

        self.keygens.insert(session_id, lock);

        Some(())
    }

    pub fn add_reshare(
        &mut self,
        session_id: SessionId,
        party_id: String,
        party_ids: Vec<String>,
        new_party_ids: Vec<String>,
        t: usize,
        _n: usize,
        keys: Option<String>,
    ) -> Option<()> {   
        let reshare = ReshareKeyPhase::new(party_id, party_ids, new_party_ids, t, keys);

        if let Err(error) = reshare {
            log::error!("[TSS] Error creating reshare {:?}", error);
            return None;
        }
        let lock = std::sync::RwLock::new(reshare.unwrap());
        self.reshares.insert(session_id, lock);
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
        let lock = std::sync::RwLock::new(sign.unwrap());
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
        let lock = std::sync::RwLock::new(sign_online.unwrap());
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
    
    pub fn get_reshare(&mut self, session_id: SessionId) -> Option<RwLockWriteGuard<'_, ReshareKeyPhase>> {
        match self.reshares.get(&session_id) {
            Some(data) => Some(data.write().unwrap()),
            None => None,
        }
    }
}