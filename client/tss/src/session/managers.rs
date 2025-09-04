use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender};
use sp_keystore::KeystorePtr;
use crate::{
    dkghelpers::{FileStorage, MemoryStorage},
    ecdsa::ECDSAManager,
    network::PeerMapper,
    retry::mechanism::RetryMechanism,
    types::{SessionId, SignedTssMessage, TSSPeerId, TSSRuntimeEvent},
    session::{
        dkg_state_manager::DKGStateManager,
        signing_state_manager::SigningStateManager,
        SessionCore,
    },
};
use sc_network::PeerId;
use frost_ed25519::Identifier;
use crate::types::{TSSPublic, TssMessage};

/// Groups storage-related components
pub struct StorageManager {
    pub storage: Arc<Mutex<MemoryStorage>>,
    pub key_storage: Arc<Mutex<FileStorage>>,
}

impl StorageManager {
    pub fn new(
        storage: Arc<Mutex<MemoryStorage>>,
        key_storage: Arc<Mutex<FileStorage>>,
    ) -> Self {
        Self {
            storage,
            key_storage,
        }
    }
}

/// Groups communication channels
pub struct CommunicationManager {
    pub gossip_to_session_manager_rx: TracingUnboundedReceiver<(SignedTssMessage, Option<PeerId>)>,
    pub runtime_to_session_manager_rx: TracingUnboundedReceiver<TSSRuntimeEvent>,
    pub session_manager_to_gossip_tx: TracingUnboundedSender<SignedTssMessage>,
}

impl CommunicationManager {
    pub fn new(
    gossip_to_session_manager_rx: TracingUnboundedReceiver<(SignedTssMessage, Option<PeerId>)>,
        runtime_to_session_manager_rx: TracingUnboundedReceiver<TSSRuntimeEvent>,
        session_manager_to_gossip_tx: TracingUnboundedSender<SignedTssMessage>,
    ) -> Self {
        Self {
            gossip_to_session_manager_rx,
            runtime_to_session_manager_rx,
            session_manager_to_gossip_tx,
        }
    }
}

/// Groups session state managers
pub struct StateManagerGroup {
    pub dkg_state_manager: DKGStateManager,
    pub signing_state_manager: SigningStateManager,
}

impl StateManagerGroup {
    pub fn new(
        dkg_state_manager: DKGStateManager,
        signing_state_manager: SigningStateManager,
    ) -> Self {
        Self {
            dkg_state_manager,
            signing_state_manager,
        }
    }
}

/// Groups participant and peer management
pub struct ParticipantManager {
    pub sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    pub active_participants: Arc<Mutex<HashMap<SessionId, Vec<TSSPeerId>>>>,
    // Buffer of messages received from a peer before we could authenticate / map it.
    // Store full SignedTssMessage so original signature & timestamp are preserved for later verification.
    pub unknown_peer_queue: Arc<Mutex<HashMap<PeerId, Vec<SignedTssMessage>>>>,
}

impl ParticipantManager {
    pub fn new(
        sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
        active_participants: Arc<Mutex<HashMap<SessionId, Vec<TSSPeerId>>>>,
        unknown_peer_queue: Arc<Mutex<HashMap<PeerId, Vec<SignedTssMessage>>>>,
    ) -> Self {
        Self {
            sessions_participants,
            active_participants,
            unknown_peer_queue,
        }
    }

    pub fn empty() -> Self {
        Self {
            sessions_participants: Arc::new(Mutex::new(HashMap::new())),
            active_participants: Arc::new(Mutex::new(HashMap::new())),
            unknown_peer_queue: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Groups authentication and signing components
pub struct AuthenticationManager {
    pub validator_public_key: [u8; 32],
    pub keystore: KeystorePtr,
}

impl AuthenticationManager {
    pub fn new(validator_public_key: [u8; 32], keystore: KeystorePtr) -> Self {
        Self {
            validator_public_key,
            keystore,
        }
    }
}