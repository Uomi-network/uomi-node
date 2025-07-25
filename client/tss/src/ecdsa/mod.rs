use std::{
    collections::BTreeMap,
    sync::{RwLock},
};

use multi_party_ecdsa::{
    communication::sending_messages::SendingMessages,
    protocols::multi_party::dmz21::{
        keygen::{KeyGenPhase},
        sign::{SignPhase, SignPhaseOnline},
        reshare::ReshareKeyPhase
    },
};

use crate::types::SessionId;

pub mod handler;
pub mod operations;
pub mod phases;

pub use phases::ECDSAPhase;


pub const GENERIC_ERROR: &str = "Generic error";

#[derive(Debug)]
pub enum ECDSAError {
    KeygenNotFound,
    SignNotFound,
    SignOnlineNotFound,
    KeygenMsgHandlerError(String, ECDSAIndexWrapper),
    SignMsgHandlerError(String, ECDSAIndexWrapper),
    SignOnlineMsgHandlerError(String, ECDSAIndexWrapper),
    ReshareMsgHandlerError(String, ECDSAIndexWrapper),
    ECDSAError(String),
}
pub struct ECDSAManager {
    pub(crate) keygens: BTreeMap<SessionId, RwLock<KeyGenPhase>>,
    pub(crate) signs: BTreeMap<SessionId, RwLock<SignPhase>>,
    pub(crate) signs_online: BTreeMap<SessionId, RwLock<SignPhaseOnline>>,
    pub(crate) reshares: BTreeMap<SessionId, RwLock<ReshareKeyPhase>>,

    pub(crate) buffer_keygen: BTreeMap<SessionId, Vec<(ECDSAIndexWrapper, Vec<u8>)>>,
    pub(crate) buffer_reshare: BTreeMap<SessionId, Vec<(ECDSAIndexWrapper, Vec<u8>)>>,
    pub(crate) buffer_sign: BTreeMap<SessionId, Vec<(ECDSAIndexWrapper, Vec<u8>)>>,
    pub(crate) buffer_sign_online: BTreeMap<SessionId, Vec<(ECDSAIndexWrapper, Vec<u8>)>>,
}

impl ECDSAManager {
    pub fn new() -> Self {
        Self {
            keygens: BTreeMap::new(),
            reshares: BTreeMap::new(),
            signs: BTreeMap::new(),
            signs_online: BTreeMap::new(),
            buffer_keygen: BTreeMap::new(),
            buffer_reshare: BTreeMap::new(),
            buffer_sign: BTreeMap::new(),
            buffer_sign_online: BTreeMap::new(),
        }
    }
}


#[derive(Clone, Debug)]
pub struct ECDSAIndexWrapper(pub String);

impl ECDSAIndexWrapper {
    pub fn get_index(&self) -> String {
        self.0.clone()
    }
}
