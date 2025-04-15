use codec::{Compact, Decode, Encode, EncodeLike, Error};
use ecdsa::{ECDSAError, ECDSAIndexWrapper, ECDSAManager};
use frame_system::EventRecord;
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use rand::prelude::*;
use sc_transaction_pool_api::{LocalTransactionPool, OffchainTransactionPoolFactory};
use substrate_prometheus_endpoint::Registry;
use sp_keystore::{KeystoreExt, KeystorePtr};
use std::{
    collections::{btree_map::Keys, BTreeMap, HashMap},
    fmt::Debug,
    future::Future,
    marker::PhantomData,
    num::TryFromIntError,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll}, thread::sleep, time::Duration, time::Instant, u16
};

use dkghelpers::{FileStorage, MemoryStorage, Storage, StorageType};
use frame_support::Parameter;
use frost_ed25519::{
    aggregate,
    keys::dkg::{
        self,
        round1::{Package, SecretPackage},
        round2,
    },
    round1::SigningCommitments,
    round2::{sign as frost_round2_sign, SignatureShare},
    Identifier, Signature, SigningPackage,
};
use futures::{channel::mpsc::Receiver, prelude::*, select, stream::FusedStream};
use log::info;
use sc_service::{KeystoreContainer, TransactionPool};
use sp_core::{sr25519, ByteArray};
use sc_client_api::{BlockchainEvents, HeaderBackend};
use sc_network::{
    config::{self, NonDefaultSetConfig, SetConfig}, utils::interval, NetworkSigner, NetworkStateInfo, NotificationService, PeerId, ProtocolName
};
use sc_network_gossip::{
    GossipEngine, Network, Syncing, TopicNotification, ValidationResult, Validator,
    ValidatorContext,
};
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender, TrySendError};
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_io::crypto::sr25519_verify;
use sp_runtime::app_crypto::Ss58Codec;
use uomi_runtime::pallet_uomi_engine::crypto::CRYPTO_KEY_TYPE as UOMI;

use sp_core::crypto::Ss58AddressFormat;
use sp_runtime::traits::Member;
use sp_runtime::{
    codec,
    traits::{Block as BlockT, Hash as HashT, Header as HeaderT},
};

use uomi_runtime::{
    pallet_tss::{types::SessionId, Event as TssEvent, TssApi},
    AccountId
};

use uomi_runtime::RuntimeEvent;

mod dkghelpers;
mod dkground1;
mod dkground2;
mod dkground3;
mod ecdsa;
mod signlib;
mod types;
#[cfg(test)]
mod test_framework;
#[cfg(test)]
mod test_framework_multi_node;


const TSS_PROTOCOL: &str = "/tss/1";

type TSSPublic = Vec<u8>;
type TSSParticipant = [u8; 32];
type TSSSignature = Vec<u8>;
pub type TSSPeerId = Vec<u8>;
pub type SessionData = (u16, u16, Vec<u8>, Vec<u8>); // t, n, coordinator, message

#[derive(Encode, Decode, Debug, Clone)]
pub enum TssMessage {
    /// Utilities
    Announce(u16, TSSPeerId, TSSPublic, TSSSignature),
    GetInfo(TSSPublic),
    Ping,

    /// FROST
    DKGRound1(SessionId, Vec<u8>),
    DKGRound2(SessionId, Vec<u8>, TSSPeerId),
    SigningCommitment(SessionId, Vec<u8>),
    SigningPackage(SessionId, Vec<u8>),
    SigningShare(SessionId, Vec<u8>),

    /// ECDSA OPEN TSS
    /// Utils
    ECDSAMessageBroadcast(SessionId, String, Vec<u8>, ECDSAPhase),
    ECDSAMessageSubset(SessionId, String, Vec<u8>, ECDSAPhase),
    ECDSAMessageP2p(SessionId, String, TSSPeerId, Vec<u8>, ECDSAPhase),

    /// Utils Keygen
    ECDSAMessageKeygen(SessionId, String, Vec<u8>),
    /// Utils Reshare
    ECDSAMessageReshare(SessionId, String, Vec<u8>),
    /// Utils Sign Offline
    ECDSAMessageSign(SessionId, String, Vec<u8>),
    /// Utils Sign Online
    ECDSAMessageSignOnline(SessionId, String, Vec<u8>),
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum ECDSAPhase {
    Key,
    Reshare,
    Sign,
    SignOnline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum DKGSessionState {
    Idle,            // Session created, but not started locally
    Round1Initiated, // Round 1 secret package generated and potentially broadcasted
    Round1Completed, // Received enough Round 1 packages to proceed to Round 2
    Round2Initiated, // Round 2 verification and package generation initiated
    Round2Completed, // Received enough Round 2 packages to proceed to Round 3 (or finalize DKG)
    Round3Initiated, // Round 3 initiated (if needed in Frost - check if round 3 is necessary for keygen)
    Round3Completed, // Round 3 completed
    KeyGenerated,    // Final TSS key generated
    Failed,          // Session failed for some reason
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum SigningSessionState {
    Idle,               // Session created, but not started locally
    Round1Initiated,    // Round 1 secret package generated and potentially broadcasted
    Round1Completed,    // Received enough Round 1 packages to proceed to Round 2
    Round2Initiated,    // Round 2 verification and package generation initiated
    Round2Completed,    // Received enough Round 2 packages to proceed to Round 3 (or finalize DKG)
    Round3Initiated, // Round 3 initiated (if needed in Frost - check if round 3 is necessary for keygen)
    Round3Completed, // Round 3 completed
    SignatureGenerated, // Final Signature key generated
    Failed,          // Session failed for some reason
}

#[derive(Encode, Decode, Debug)]
pub enum SessionManagerMessage {
    NewDKGMessage(SessionId, TssMessage, TSSPeerId), // Message received from gossip before session info
    SessionInfoReady(SessionId),                     // Session info from runtime is now available
    RuntimeEvent(RuntimeEvent),                      // Events from the runtime
}
#[derive(Encode, Decode, Debug)]
pub enum TSSRuntimeEvent {
    DKGSessionInfoReady(SessionId, u16, u16, Vec<TSSParticipant>), // Session info from runtime is now available
    DKGReshareSessionInfoReady(SessionId, u16, u16, Vec<TSSParticipant>, Vec<TSSParticipant>), // Session info from runtime is now available
    SigningSessionInfoReady(
        SessionId,
        u16,
        u16,
        Vec<TSSParticipant>,
        TSSParticipant,
        Vec<u8>,
    ), // Session info from runtime is now available
    ValidatorIdAssigned(TSSParticipant, u32)
}

struct TssValidator {
    announcement: Option<TssMessage>,
    // Track processed messages with their timestamps
    processed_messages: Arc<Mutex<HashMap<Vec<u8>, Instant>>>,
    // How long to keep messages in the cache before expiring them
    message_expiry: Duration,
}

#[derive(Encode, Decode, Debug)]
pub enum SessionManagerError {
    IdentifierNotFound,
    SessionNotYetInitiated,
    Round2SecretPackageNotYetAvailable,
    DeserializationError,
    SignatureAggregationError,
    SignatureNotReadyYet,
}
// ===== TssValidator =====

impl TssValidator {
    fn new(message_expiry: Duration, announcement: Option<TssMessage>) -> Self {
        Self {
            announcement,
            processed_messages: Arc::new(Mutex::new(HashMap::new())),
            message_expiry,
        }
    }
}


impl<B: BlockT> Validator<B> for TssValidator {
    fn new_peer(
        &self,
        context: &mut dyn ValidatorContext<B>,
        who: &PeerId,
        _role: sc_network::ObservedRole,
    ) {
        info!("[TSS]: New Peer Connected: {}", who.to_base58());
        
        if false {
            if let Some(announcement) = &self.announcement {
                match announcement {
                    TssMessage::Announce(_nonce, peer_id, pubkey, sig) => {
                        let mut rng = rand::thread_rng();
                        context.send_message(
                            who,
                            TssMessage::Announce(
                                rng.gen::<u16>(),
                                peer_id.clone(),
                                pubkey.clone(),
                                sig.clone(),
                            )
                            .encode(),
                        );
                    }
                    _ => (),
                }
            }
        }
    }

    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<B>,
        sender: &PeerId,
        data: &[u8],
    ) -> ValidationResult<B::Hash> {
        info!("[TSS]: Received message from {}", sender.to_base58());

        // Safely modify the processed messages
        let mut processed_messages = self.processed_messages.lock().unwrap();
        
        // Check if we've already processed this message
        if processed_messages.contains_key(data) {
            return ValidationResult::Discard;
        }
        
        // Mark the message as processed
        processed_messages.insert(data.to_vec(), Instant::now());
        
        // Cleanup can happen here or in a background task
        let now = Instant::now();
        processed_messages.retain(|_, timestamp| {
            now.duration_since(*timestamp) < self.message_expiry
        });
        
        let topic = <<B::Header as HeaderT>::Hashing as HashT>::hash("tss_topic".as_bytes());
        
        ValidationResult::ProcessAndKeep(topic)
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(<B as BlockT>::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_topic, data| {
            let processed_messages = self.processed_messages.lock().unwrap();
            if let Some(_timestamp) = processed_messages.get(data) {
                return true;
            }
            false
        })
    }
    fn message_allowed<'a>(
            &'a self,
        ) -> Box<dyn FnMut(&PeerId, sc_network_gossip::MessageIntent, &<B as BlockT>::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_peer_id, _intent, _topic, data| {
            // The messages are always allowed, but we need to store what data we send out
            // to avoid sending the same message multiple times

            let mut processed_messages = self.processed_messages.lock().unwrap();
            processed_messages.insert(data.to_vec(), Instant::now());

            return true;
        })  
    }
}

// ===== PeerMapper =====
struct PeerMapper {
    peers: HashMap<PeerId, TSSPublic>,
    sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    sessions_participants_u16: Arc<Mutex<HashMap<SessionId, HashMap<u16, TSSPublic>>>>,
    validator_ids: Arc<Mutex<HashMap<TSSPublic, u32>>>,
}

impl PeerMapper {
    fn new(
        sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    ) -> Self {
        PeerMapper {
            peers: HashMap::new(),
            sessions_participants,
            sessions_participants_u16: Arc::new(Mutex::new(HashMap::new())),
            validator_ids: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    pub fn _get_account_id_from_peer_id(&mut self, peer_id: &PeerId) -> Option<&TSSPublic> {
        self.peers.get(peer_id)
    }

    pub fn get_peer_id_from_account_id(&mut self, account_id: &TSSPublic) -> Option<&PeerId> {
        self.peers
            .iter()
            .find_map(|(key, val)| if val == account_id { Some(key) } else { None })
    }

    // Modified to use validator ID as identifier where possible
    pub fn get_peer_id_from_identifier(
        &mut self,
        session_id: &SessionId,
        identifier: &Identifier,
    ) -> Option<&PeerId> {
        let sessions_participants = self.sessions_participants.lock().unwrap();
        let session = sessions_participants.get(session_id);

        if let Some(session) = session {
            let account_id = session.get(identifier).cloned();

            drop(sessions_participants);
            if let Some(account_id) = account_id {
                return self.get_peer_id_from_account_id(&account_id);
            }
        }

        None
    }

    pub fn get_peer_id_from_id(&mut self, session_id: &SessionId, id: u16) -> Option<&PeerId> {
        let sessions_participants = self.sessions_participants_u16.lock().unwrap();
        let session = sessions_participants.get(session_id);

        if let Some(session) = session {
            log::info!("Session found");
            let account_id = session.get(&id).cloned();

            drop(sessions_participants);
            if let Some(account_id) = account_id {
                log::info!("Account found {:?}", account_id);

                return self.get_peer_id_from_account_id(&account_id);
            } else {
                log::info!("Account not found");
            }
        } else {
            log::info!("Session not found");
        }

        None
    }

    pub fn get_identifier_from_peer_id(
        &mut self,
        session_id: &SessionId,
        peer_id: &PeerId,
    ) -> Option<Identifier> {
        let account_id = self.peers.get(peer_id).cloned();
        if let Some(account_id) = account_id {
            self.get_identifier_from_account_id(session_id, &account_id)
        } else {
            None
        }
    }

    pub fn get_id_from_peer_id(&mut self, session_id: &SessionId, peer_id: &PeerId) -> Option<u16> {
        let account_id = self.peers.get(peer_id).cloned();

        if let Some(account_id) = account_id {
            self.get_id_from_account_id(session_id, &account_id)
        } else {
            None
        }
    }

    pub fn get_id_from_account_id(
        &mut self,
        session_id: &SessionId,
        account_id: &TSSPublic,
    ) -> Option<u16> {
        let handle = self.sessions_participants_u16.lock().unwrap();
        let session = handle.get(session_id);

        if let None = session {
            return None;
        }

        for (_, (key, val)) in session.unwrap().iter().enumerate() {
            if val == account_id {
                return Some(*key);
            }
        }
        drop(handle);

        return None;
    }

    // Modified to use validator ID if available
    pub fn get_identifier_from_account_id(
        &mut self,
        session_id: &SessionId,
        account_id: &TSSPublic,
    ) -> Option<Identifier> {
        // First try to get the validator ID
        let validator_id = self.get_validator_id(account_id);
        
        if let Some(id) = validator_id {
            // If we have a validator ID, convert it to Identifier
            let identifier: Identifier = u16::try_from(id).unwrap_or(u16::MAX).try_into().unwrap();
            return Some(identifier);
        }
        
        // If no validator ID is found, fall back to the original method
        let handle = self.sessions_participants.lock().unwrap();
        let session = handle.get(session_id);

        if let None = session {
            return None;
        }

        log::debug!(
            "[TSS] get_identifier_from_account_id({:?}, {:?}) from session = {:?}",
            session_id,
            account_id,
            session
        );

        for (_, (key, val)) in session.unwrap().iter().enumerate() {
            if val == account_id {
                return Some(key.clone());
            }
        }
        drop(handle);

        return None;
    }

    // Modified to use validator IDs
    pub fn create_session(&mut self, session_id: SessionId, participants: Vec<TSSParticipant>) {
        let mut sessions_participants = self.sessions_participants.lock().unwrap();
        let mut sessions_participants_u16 = self.sessions_participants_u16.lock().unwrap();

        let entry_sessions_participants = sessions_participants
            .entry(session_id)
            .or_insert(empty_hash_map());
        let entry_sessions_participants_u16 = sessions_participants_u16
            .entry(session_id)
            .or_insert(empty_hash_map());

        for (index, val) in participants.iter().enumerate() {
            // Try to get validator ID for this participant
            let validator_id = self.get_validator_id(&val.to_vec())
                .unwrap_or_else(|| (index + 1) as u32); // Fall back to index+1 if no validator ID
            
            // Convert validator_id to Identifier
            
            let identifier: Identifier = u16::try_from(validator_id).unwrap_or_default().try_into().unwrap();
 
            
            entry_sessions_participants.insert(identifier, val.to_vec());
            entry_sessions_participants_u16.insert(u16::try_from(index + 1).unwrap(), val.to_vec());
            
            log::info!("[TSS] Added participant with validator ID {} to session {}", validator_id, session_id);
        }

        drop(sessions_participants_u16);
        drop(sessions_participants);
    }

    pub fn add_peer(&mut self, peer_id: PeerId, public_key_data: TSSPublic) {
        log::info!("Adding Peer {:?} with public key {:?}", peer_id, public_key_data);
        self.peers.insert(peer_id, public_key_data);
    }

    pub fn get_validator_id(&self, public_key: &TSSPublic) -> Option<u32> {
        let validator_ids = self.validator_ids.lock().unwrap();
        let id = validator_ids.get(public_key).cloned();
        drop(validator_ids);
        id
    }

    pub fn _get_validator_account_from_id(&mut self, id: u32) -> Option<TSSPublic> {
        let validator_ids = self.validator_ids.lock().unwrap();
        let account = validator_ids.iter().find_map(|(key, val)| {
            if *val == id {
                Some(key.clone())
            } else {
                None
            }
        });
        drop(validator_ids);
        account
    }

    pub fn set_validator_id(&mut self, public_key: TSSPublic, id: u32) {
        let mut validator_ids = self.validator_ids.lock().unwrap();
        validator_ids.insert(public_key, id);
        drop(validator_ids);
    }
}

// ===== SessionManager =====
/// Error type for session operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Session with this ID already exists
    SessionAlreadyExists,
    /// Session with this ID doesn't exist
    SessionDoesNotExist,
    /// Session is in an invalid state for the requested operation
    InvalidSessionState,
    /// Participant is not allowed in this session
    NotAuthorized,
    /// Message couldn't be deserialized
    DeserializationError,
    /// Session timed out
    SessionTimeout,
    /// Generic error
    GenericError(String),
}



struct SessionManager<B: BlockT, C: ClientManager<B>>
{
    storage: Arc<Mutex<MemoryStorage>>,
    key_storage: Arc<Mutex<FileStorage>>,
    sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    sessions_data: Arc<Mutex<HashMap<SessionId, SessionData>>>, // t, n, coordinator, message
    dkg_session_states: Arc<Mutex<HashMap<SessionId, DKGSessionState>>>,
    signing_session_states: Arc<Mutex<HashMap<SessionId, SigningSessionState>>>,
    validator_key: TSSPublic,
    peer_mapper: Arc<Mutex<PeerMapper>>,
    _phantom: PhantomData<B>,
    ecdsa_manager: Arc<Mutex<ECDSAManager>>,
    gossip_to_session_manager_rx: TracingUnboundedReceiver<(PeerId, TssMessage)>,
    runtime_to_session_manager_rx: TracingUnboundedReceiver<TSSRuntimeEvent>,
    session_manager_to_gossip_tx: TracingUnboundedSender<(PeerId, TssMessage)>,
    buffer: Arc<Mutex<HashMap<SessionId, Vec<(TSSPeerId, TssMessage)>>>>,
    local_peer_id: TSSPeerId,
    client: C,
    // Track session creation timestamps for timeout enforcement
    session_timestamps: Arc<Mutex<HashMap<SessionId, std::time::Instant>>>,
    // Maximum session lifetime (in seconds)
    session_timeout: u64,
    // A list of participants that have actively participated so far
    active_participants: Arc<Mutex<HashMap<SessionId, Vec<TSSPeerId>>>>,
}

impl<B: BlockT, C: ClientManager<B>> SessionManager<B, C>
{
    fn new(
        storage: Arc<Mutex<MemoryStorage>>,
        key_storage: Arc<Mutex<FileStorage>>,
        sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
        sessions_data: Arc<Mutex<HashMap<SessionId, SessionData>>>, // t, n, message
        dkg_session_states: Arc<Mutex<HashMap<SessionId, DKGSessionState>>>,
        signing_session_states: Arc<Mutex<HashMap<SessionId, SigningSessionState>>>,
        validator_key: TSSPublic,
        peer_mapper: Arc<Mutex<PeerMapper>>,
        gossip_to_session_manager_rx: TracingUnboundedReceiver<(PeerId, TssMessage)>,
        runtime_to_session_manager_rx: TracingUnboundedReceiver<TSSRuntimeEvent>,
        session_manager_to_gossip_tx: TracingUnboundedSender<(PeerId, TssMessage)>,
        local_peer_id: TSSPeerId,
        client: C,
    ) -> Self {
        Self {
            storage,
            key_storage,
            sessions_participants,
            sessions_data,
            dkg_session_states,
            signing_session_states,
            validator_key,
            peer_mapper,
            gossip_to_session_manager_rx,
            runtime_to_session_manager_rx,
            session_manager_to_gossip_tx,
            _phantom: PhantomData,
            buffer: Arc::new(Mutex::new(empty_hash_map())),
            local_peer_id,
            client,
            ecdsa_manager: Arc::new(Mutex::new(ECDSAManager::new())),
            // Default session timeout to 1 hour (3600 seconds)
            session_timeout: 3600,
            session_timestamps: Arc::new(Mutex::new(empty_hash_map())),
            active_participants: Arc::new(Mutex::new(empty_hash_map())),
        }
    }
    
    /// Check if a session exists
    fn session_exists(&self, session_id: &SessionId) -> bool {
        self.sessions_data.lock().unwrap().contains_key(session_id)
    }
    
    /// Check if a session has timed out
    fn is_session_timed_out(&self, session_id: &SessionId) -> bool {
        let timestamps = self.session_timestamps.lock().unwrap();
        if let Some(timestamp) = timestamps.get(session_id) {
            let elapsed = timestamp.elapsed().as_secs();
            return elapsed > self.session_timeout;
        }
        false
    }
    
    /// Check if node is authorized to participate in a session
    fn is_authorized_for_session(&self, session_id: &SessionId) -> bool {
        let mut peer_mapper = self.peer_mapper.lock().unwrap();
        let id = peer_mapper.get_id_from_peer_id(
            session_id,
            &PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
        );
        drop(peer_mapper);
        id.is_some()
    }

    // Add the participant as active, so that it doesn't get reported as bad actor
    fn add_active_participant(&self, session_id: &SessionId, peer_id: &PeerId) {
        log::info!("[TSS] Adding Active Participant {:?}", peer_id);
        let mut active_participants = self.active_participants.lock().unwrap();
        let participants = active_participants.entry(*session_id).or_insert_with(Vec::new);
        participants.push(peer_id.to_bytes());
        drop(active_participants);
    }

    /// Checks what participants have not participated actively
    fn get_inactive_participants(&self, session_id: &SessionId) -> Vec<[u8; 32]> {

        if !self.is_authorized_for_session(session_id) {
            return Vec::new();
        }
        let mut inactive_participants = Vec::new();

        let sessions_data = self.sessions_data.lock().unwrap();
        let session_data = sessions_data.get(session_id).cloned();
        drop(sessions_data);
        
        if let Some((_, _, _, _)) = session_data {
            let peer_mapper = self.peer_mapper.lock().unwrap();
            let participants = peer_mapper.sessions_participants.lock().unwrap().clone();
            drop(peer_mapper);
            let mut peer_mapper = self.peer_mapper.lock().unwrap();
            let active_participants = self.active_participants.lock().unwrap();
            let empty_vec = Vec::new();
            let active_participants_in_session = active_participants.get(session_id).unwrap_or(&empty_vec);
            log::info!("[TSS] Active Participants In Session: {:?}", active_participants_in_session);
            if let Some(session_participants) = participants.get(session_id) {
                for (_identifier, account_id) in session_participants.iter() {
                    let peer_id = peer_mapper.get_peer_id_from_account_id(account_id);
                    if let Some(peer_id) = peer_id {
                        if peer_id.to_bytes() != self.local_peer_id && !active_participants_in_session.contains(&peer_id.to_bytes()) {
                            inactive_participants.push(account_id.clone().try_into().unwrap());
                        }
                    } else {
                        // If the peer_id is not found, we assume it's inactive
                        inactive_participants.push(account_id.clone().try_into().unwrap());
                    }
                }
            }
            drop(active_participants);
            drop(participants);
            drop(peer_mapper);
        }
        inactive_participants

    }

    /// Add session data with validation
    fn add_session_data(
        &mut self,
        session_id: SessionId,
        t: u16,
        n: u16,
        coordinator: TSSParticipant,
        participants: Vec<TSSParticipant>,
        message: Vec<u8>,
    ) -> Result<(), SessionError> {
        // Check if session already exists
        if self.session_exists(&session_id) {
            log::warn!("[TSS] Session {} already exists, refusing to create again", session_id);
        //    return Err(SessionError::SessionAlreadyExists);
        }
        
        // Validate threshold requirements
        if t == 0 || n == 0 || t > n {
            log::error!("[TSS] Invalid threshold parameters t={}, n={}", t, n);
            return Err(SessionError::GenericError(format!("Invalid threshold parameters: t={}, n={}", t, n)));
        }
        
        // Validate participants list
        if participants.len() != n as usize {
            log::error!(
                "[TSS] Mismatch between participant count and n parameter: {} vs {}",
                participants.len(),
                n
            );
            return Err(SessionError::GenericError(format!(
                "Participant count ({}) doesn't match n parameter ({})",
                participants.len(), n
            )));
        }

        // Add the session data
        let mut sessions_data = self.sessions_data.lock().unwrap();
        sessions_data.insert(session_id, (t, n, coordinator.to_vec(), message));
        drop(sessions_data);

        let mut peer_mapper = self.peer_mapper.lock().unwrap();
        peer_mapper.create_session(session_id, participants.clone());
        drop(peer_mapper);
        
        // Record session creation time for timeout tracking
        let mut timestamps = self.session_timestamps.lock().unwrap();
        timestamps.insert(session_id, std::time::Instant::now());
        drop(timestamps);
        
        log::info!("[TSS] Successfully created session {}", session_id);
        Ok(())
    }

    /// Get session data with timeout check
    fn get_session_data(&self, session_id: &SessionId) -> Option<(u16, u16, Vec<u8>, Vec<u8>)> {
        // Check for session timeout
        if self.is_session_timed_out(session_id) {
            log::warn!("[TSS] Session {} has timed out", session_id);
            return None;
        }
        
        self.sessions_data.lock().unwrap().get(session_id).cloned()
    }

    fn is_coordinator(&self, session_id: &SessionId) -> bool {
        if let None = self.get_session_data(session_id) {
            return false;
        }

        let (_, _, coordinator, _) = self.get_session_data(session_id).unwrap();

        coordinator == self.validator_key[..]
    }

    fn handle_gossip_message(&mut self, message: TssMessage, sender: TSSPeerId) {
        // First, try to convert the sender to a PeerId
        let sender_peer_id = match PeerId::from_bytes(&sender) {
            Ok(peer_id) => peer_id,
            Err(e) => {
                log::error!("[TSS] Invalid sender peer ID: {:?}", e);
                return;
            }
        };

        match &message {
            TssMessage::DKGRound1(session_id, ref bytes) => {
                // Check if this session exists or is timed out
                if !self.session_exists(session_id) {
                    log::warn!("[TSS] Received DKGRound1 message for non-existent session {}", session_id);
                    // Buffer the message in case session is created later
                    self.buffer
                        .lock()
                        .unwrap()
                        .entry(*session_id)
                        .or_insert(Vec::new())
                        .push((sender, TssMessage::DKGRound1(*session_id, bytes.clone())));
                    return;
                }
                
                if self.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received DKGRound1 message for timed out session {}", session_id);
                    return;
                }

                // Check if the node is authorized for this session
                if !self.is_authorized_for_session(session_id) {
                    log::warn!("[TSS] Node not authorized for session {}", session_id);
                    return;
                }

                if let Err(error) = self.dkg_handle_round1_message(
                    *session_id,
                    bytes,
                    sender_peer_id,
                ) {
                    match error {
                        SessionManagerError::IdentifierNotFound => {
                            log::debug!("[TSS] Buffering DKGRound1 message for session {} (identifier not found yet)", session_id);
                            self.buffer
                                .lock()
                                .unwrap()
                                .entry(*session_id)
                                .or_insert(Vec::new())
                                .push((sender, TssMessage::DKGRound1(*session_id, bytes.clone())));
                        },
                        _ => {
                            log::error!("[TSS] Error handling DKGRound1 for session {}: {:?}", session_id, error);
                        },
                    }
                } else {
                    self.add_active_participant(session_id, &sender_peer_id);
                }
            }
            TssMessage::DKGRound2(session_id, ref bytes, ref recipient) => {
                // Check if this session exists or is timed out
                if !self.session_exists(session_id) {
                    log::warn!("[TSS] Received DKGRound2 message for non-existent session {}", session_id);
                    return;
                }
                
                if self.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received DKGRound2 message for timed out session {}", session_id);
                    return;
                }

                // Check if the node is authorized for this session
                if !self.is_authorized_for_session(session_id) {
                    log::warn!("[TSS] Node not authorized for session {}", session_id);
                    return;
                }

                log::debug!(
                    "[TSS] TssMessage::DKGRound2({:?}, {:?}, {:?})",
                    session_id,
                    bytes,
                    recipient
                );
                if let Err(error) = self.dkg_handle_round2_message(
                    *session_id,
                    bytes,
                    recipient,
                    sender_peer_id,
                ) {
                    match error {
                        SessionManagerError::Round2SecretPackageNotYetAvailable => {
                            log::debug!("[TSS] Buffering DKGRound2 message for session {} (round 2 not ready yet)", session_id);
                            self.buffer
                                .lock()
                                .unwrap()
                                .entry(*session_id)
                                .or_insert(Vec::new())
                                .push((
                                    sender,
                                    TssMessage::DKGRound2(
                                        *session_id,
                                        bytes.clone(),
                                        recipient.clone(),
                                    ),
                                ));
                        },
                        _ => {
                            log::error!("[TSS] Error handling DKGRound2 for session {}: {:?}", session_id, error);
                        },
                    }
                } else {
                    self.add_active_participant(session_id, &sender_peer_id);
                }
            }
            TssMessage::SigningCommitment(session_id, ref bytes) => {
                // Check if this session exists or is timed out
                if !self.session_exists(session_id) {
                    log::warn!("[TSS] Received SigningCommitment message for non-existent session {}", session_id);
                    return;
                }
                
                if self.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received SigningCommitment message for timed out session {}", session_id);
                    return;
                }

                if let Err(error) = self.signing_handle_commitment(
                    *session_id,
                    bytes,
                    sender_peer_id,
                ) {
                    // only the coordinator is supposed to receive this
                    log::error!("[TSS] Error Handling Signing Commitment for session {}: {:?}", session_id, error);
                } else {
                    self.add_active_participant(session_id, &sender_peer_id);
                }
            }
            TssMessage::SigningShare(session_id, ref bytes) => {
                // Check if this session exists or is timed out
                if !self.session_exists(session_id) {
                    log::warn!("[TSS] Received SigningShare message for non-existent session {}", session_id);
                    return;
                }
                
                if self.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received SigningShare message for timed out session {}", session_id);
                    return;
                }

                // only the coordinator is supposed to receive this
                match self.signing_handle_signature_share(
                    *session_id,
                    bytes,
                    sender_peer_id,
                ) {
                    Err(error) => log::error!("[TSS] Error Handling Signing Share for session {}: {:?}", session_id, error),
                    Ok(_signature) => {
                        self.add_active_participant(session_id, &sender_peer_id);
                    }
                } 
            }

            TssMessage::SigningPackage(session_id, bytes) => {
                // Check if this session exists or is timed out
                if !self.session_exists(session_id) {
                    log::warn!("[TSS] Received SigningPackage message for non-existent session {}", session_id);
                    return;
                }
                
                if self.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received SigningPackage message for timed out session {}", session_id);
                    return;
                }

                // this should be for the participants
                // be careful, if participant is also the coordinator they should not send
                // stuff to themselves.
                if let Err(error) = self.signing_handle_signing_package(
                    *session_id,
                    &bytes,
                    sender_peer_id,
                ) {
                    log::error!("[TSS] Error Handling Signing Package for session {}: {:?}", session_id, error);
                } else {
                    self.add_active_participant(session_id, &sender_peer_id);
                }
            }

            TssMessage::Announce(_, _, _, _) => {
                // Announcements are handled by the gossip layer directly.  The SessionManager
                // only needs to know about them to add peers to its mapping.  The GossipHandler
                // already does this, so nothing to do here *within* the SessionManager.
            }
            TssMessage::GetInfo(_) | TssMessage::Ping => {
                //  Handle these if needed.  They are likely more relevant to the GossipHandler.
                //  Maybe in the future we might want to implement some explicit request for information to another Peer
            }
            TssMessage::ECDSAMessageBroadcast(_, _, _, _)
            | TssMessage::ECDSAMessageP2p(_, _, _, _, _)
            | TssMessage::ECDSAMessageSubset(_, _, _, _) => {
                //  We use this as utils enum values only in for inner communication. They are handled in the GossipHandler
            }

            TssMessage::ECDSAMessageKeygen(session_id, _index, msg)
            | TssMessage::ECDSAMessageReshare(session_id, _index, msg)
            | TssMessage::ECDSAMessageSign(session_id, _index, msg)
            | TssMessage::ECDSAMessageSignOnline(session_id, _index, msg) => {
                // Check if this session exists or is timed out
                if !self.session_exists(session_id) {
                    log::warn!("[TSS] Received ECDSA message for non-existent session {}", session_id);
                    return;
                }
                
                if self.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received ECDSA message for timed out session {}", session_id);
                    return;
                }
                
                // Check if the node is authorized for this session
                if !self.is_authorized_for_session(session_id) {
                    log::warn!("[TSS] Node not authorized for session {}", session_id);
                    return;
                }

                // This means we received a message through gossip. This can be handled in multiple ways depending on multiple possibilities
                // 1. We know who we are
                // 2. We know who sent this message (sender)
                // 3. We can handle all the messages in the same loop for the key gen
                let mut manager = self.ecdsa_manager.lock().unwrap();

                // Use message_type to determine which function to call instead of matching on message again
                let (sending_messages, phase) = match message.clone() {
                    TssMessage::ECDSAMessageKeygen(_, index, _) => self
                        .handle_buffer_and_sending_messages_for_keygen(
                            session_id,
                            msg,
                            &mut manager,
                            ECDSAIndexWrapper(index),
                        ),
                    TssMessage::ECDSAMessageSign(_, index, _) => {
                        log::debug!("[TSS] Starting consuming buffer");
                        self.handle_buffer_and_sending_messages_for_sign_offline(
                            session_id,
                            msg,
                            &mut manager,
                            ECDSAIndexWrapper(index),
                        )
                    }
                    TssMessage::ECDSAMessageSignOnline(_, index, _) => self
                        .handle_buffer_and_sending_messages_for_sign_online(
                            session_id,
                            msg,
                            &mut manager,
                            ECDSAIndexWrapper(index),
                        ),
                    _ => (
                        Err(ecdsa::ECDSAError::ECDSAError(
                            ecdsa::GENERIC_ERROR.to_string(), // if this happens there's a bug in the code.
                        )),
                        ECDSAPhase::Key,
                    ),
                };

                log::debug!(
                    "[TSS] Sending messages = {:?}, phase = {:?}",
                    sending_messages,
                    phase
                );

                if let Err(error) = &sending_messages {
                    log::error!("[TSS] Error sending messages for session {}: {:?}", session_id, error);
                    return;
                } else{
                    self.add_active_participant(session_id, &sender_peer_id);
                }
                log::debug!("[TSS] calling handle_ecdsa_sending_messages()");

                self.handle_ecdsa_sending_messages(
                    *session_id,
                    sending_messages.unwrap(),
                    &mut manager,
                    phase,
                );
            }
        }
    }

    fn handle_buffer_and_sending_messages_for_sign_online(
        &self,
        session_id: &u64,
        msg: &Vec<u8>,
        manager: &mut MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, ECDSAError>, ECDSAPhase) {
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

    fn handle_buffer_and_sending_messages_for_sign_offline(
        &self,
        session_id: &u64,
        msg: &Vec<u8>,
        manager: &mut MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, ECDSAError>, ECDSAPhase) {
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

    fn handle_buffer_and_sending_messages_for_keygen(
        &self,
        session_id: &u64,
        msg: &Vec<u8>,
        manager: &mut MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, ECDSAError>, ECDSAPhase) {
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

    fn handle_buffer_and_sending_messages_for_reshare(
        &self,
        session_id: &u64,
        msg: &Vec<u8>,
        manager: &mut MutexGuard<'_, ECDSAManager>,
        index: ECDSAIndexWrapper,
    ) -> (Result<SendingMessages, ECDSAError>, ECDSAPhase) {
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

    fn handle_ecdsa_sending_messages(
        &self,
        session_id: SessionId,
        sending_messages: SendingMessages,
        ecdsa_manager: &mut MutexGuard<'_, ECDSAManager>,
        phase: ECDSAPhase,
    ) {
        match sending_messages {
            SendingMessages::P2pMessage(msg) => {
                log::info!("[TSS] SendingMessages::P2pMessage");
                let mut peer_mapper = self.peer_mapper.lock().unwrap();
                let index = peer_mapper
                    .get_id_from_peer_id(
                        &session_id,
                        &PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
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
                        .get_peer_id_from_id(&session_id, id.parse::<u16>().unwrap())
                        .cloned();
                    drop(peer_mapper);
                    log::info!("[TSS] Dropped lock on mapper");

                    if let Some(recipient) = recipient {
                        if let Err(error) = self.session_manager_to_gossip_tx.unbounded_send((
                            recipient.clone(),
                            TssMessage::ECDSAMessageP2p(
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
                        &PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
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
                        PeerId::from_bytes(&self.local_peer_id).unwrap(),
                        TssMessage::ECDSAMessageBroadcast(
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

                let mut storage: MutexGuard<'_, FileStorage> = self.key_storage.lock().unwrap();

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
                        &PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
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

                let mut storage: MutexGuard<'_, FileStorage> = self.key_storage.lock().unwrap();

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
                        &PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
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
    ) -> frost_core::Identifier<frost_ed25519::Ed25519Sha512> {
        let mut peer_mapper = self.peer_mapper.lock().unwrap();

        let index = peer_mapper
            .get_id_from_peer_id(
                &session_id,
                &PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
            )
            .clone();

        drop(peer_mapper);

        let _id = index.unwrap();
        log::info!("[TSS] My Id is {:?}", _id);
        let _id: Identifier = _id.try_into().unwrap();
        _id
    }

    fn dkg_handle_round1_message(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        sender: PeerId,
    ) -> Result<(), SessionManagerError> {
        let session_state_lock = self.dkg_session_states.lock().unwrap();
        let current_state = session_state_lock
            .get(&session_id)
            .copied()
            .unwrap_or(DKGSessionState::Idle);
        drop(session_state_lock); // Release lock

        // STEP 1: For sure, we need to store the message for later use.
        let mut storage = self.storage.lock().unwrap();

        let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();

        let identifier = peer_mapper_handle.get_identifier_from_peer_id(&session_id, &sender);

        log::info!(
            "[TSS] Apparently peer_id = {:?} is associated with identifier = {:?}",
            sender,
            identifier
        );

        if let None = identifier {
            log::warn!(
                "[TSS]: Couldn't find identifier fo Session {} and peer_id {:?}. Ignoring message.",
                session_id,
                sender
            );

            return Err(SessionManagerError::IdentifierNotFound);
        }

        let identifier = identifier.unwrap();
        log::info!(
            "[TSS] Stored received message from identifier {:?}",
            identifier.clone()
        );
        storage.store_round1_packages(session_id, identifier, &bytes[..]);
        drop(peer_mapper_handle);

        // STEP 2: If we haven't started yet, wait for our time to come
        // This can happen for example if someone received the event from the pallet before us and has
        // already started. Should be handled gracefulyl
        if current_state < DKGSessionState::Round1Initiated {
            // Only process if we've initiated Round 1
            log::warn!(
                "[TSS]: Received DKGRound1 for session {} but local state is {:?}. Ignoring message.",
                session_id,
                current_state
            );
            return Err(SessionManagerError::SessionNotYetInitiated);
        }

        drop(storage);

        log::info!("[TSS] calling handle_verification_to_complete_round1()");
        self.dkg_handle_verification_to_complete_round1(session_id);

        Ok(())
    }

    fn dkg_handle_verification_to_complete_round1(&self, session_id: SessionId) {
        let storage = self.storage.lock().unwrap();

        // This should not actually happen since the state is updated when we store the secret package from round 1
        // but you never know...
        let data = storage.read_secret_package_round1(session_id);

        if let Err(_e) = data {
            log::warn!(
                "[TSS]: Received DKGRound1 for session {} but local round 1 data not ready yet. Ignoring message.",
                session_id
            );
            return; // Ignore if local data not ready (should not happen with state check)
        }

        let data = data.unwrap();
        let n = data.max_signers();

        let round1_packages = storage.fetch_round1_packages(session_id).unwrap();
        drop(storage); // Release lock

        log::info!("[TSS] debug round1_packages = {:?}", round1_packages);

        if round1_packages.keys().len() >= (n - 1).into() {
            self.dkg_verify_and_start_round2(session_id, data, round1_packages)
        }
    }

    fn dkg_verify_and_start_round2(
        &self,
        session_id: SessionId,
        round1_secret_package: SecretPackage, // Pass the secret package directly
        round1_packages: BTreeMap<Identifier, Package>,
    ) {
        match dkground2::round2_verify_round1_participants(
            session_id,
            round1_secret_package,
            &round1_packages,
        ) {
            Err(e) => {
                log::error!(
                    "[TSS]: Error in round2_verify_round1_participants for session {}: {:?}",
                    session_id,
                    e
                );
                // Optionally handle failure state here, e.g., update session state to Failed
                let mut session_state_lock = self.dkg_session_states.lock().unwrap();
                session_state_lock.insert(session_id, DKGSessionState::Failed);
                drop(session_state_lock);
            }
            Ok((secret, round2_packages)) => {
                log::info!("[TSS] Round 1 Verification completed. Continuing now with Round 2");
                // Update session state to Round1Completed
                let mut session_state_lock = self.dkg_session_states.lock().unwrap();
                session_state_lock.insert(session_id, DKGSessionState::Round1Completed);
                drop(session_state_lock);
                log::info!("[TSS] 1");

                let empty = empty_hash_map();
                let handle_participants = self.sessions_participants.lock().unwrap();
                let participants = handle_participants.get(&session_id).unwrap_or(&empty); // Use HashMap::new() directly
                log::info!("[TSS] 2");

                for (identifier, package) in round2_packages {
                    let account_id = participants.get(&identifier);

                    if let None = account_id {
                        log::error!(
                            "[TSS]: Account ID not found for identifier {:?} in session {}",
                            identifier,
                            session_id
                        );
                        continue; // Handle error???
                    }

                    if *(account_id.unwrap()) == self.validator_key {
                        // don't send stuff to yourself
                        log::info!(
                            "[TSS] Skipping message to myself for session {}",
                            session_id
                        );
                        continue;
                    }
                    log::info!("[TSS] 3");

                    let mut peer_mapper = self.peer_mapper.lock().unwrap();
                    if let Some(peer_id) =
                        peer_mapper.get_peer_id_from_account_id(account_id.unwrap())
                    {
                        log::info!("[TSS] 4");
                        let _ = self
                            .session_manager_to_gossip_tx
                            .unbounded_send((
                                peer_id.clone(),
                                TssMessage::DKGRound2(
                                    session_id,
                                    package.serialize().unwrap(),
                                    peer_id.to_bytes(),
                                ),
                            ))
                            .unwrap();
                    } else {
                        log::error!("[TSS] PeerID not found, cannot send message")
                    }
                    log::info!("[TSS] 5");

                    drop(peer_mapper);
                }
                drop(handle_participants);
                log::info!("[TSS] 6");
                let mut storage = self.storage.lock().unwrap();
                storage
                    .store_data(
                        session_id,
                        dkghelpers::StorageType::DKGRound2SecretPackage,
                        &(secret.serialize().unwrap()),
                        None,
                    )
                    .unwrap();
                drop(storage);
                log::info!("[TSS] 7");

                // Update session state to Round2Initiated after sending Round2 messages
                let mut session_state_lock = self.dkg_session_states.lock().unwrap();
                session_state_lock.insert(session_id, DKGSessionState::Round2Initiated);
                drop(session_state_lock);
                log::info!("[TSS] 8");

                // This is not gonna happen but just in case
                if let Err(e) = self.dkg_verify_and_complete(session_id) {
                    log::error!(
                        "[TSS] There was an error verifying Round2 to complete DKG {:?}",
                        e
                    )
                }
            }
        };
    }

    fn dkg_handle_round2_message(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        recipient: &TSSPeerId,
        sender: PeerId,
    ) -> Result<(), SessionManagerError> {
        let session_state_lock = self.dkg_session_states.lock().unwrap();
        let current_state = session_state_lock
            .get(&session_id)
            .copied()
            .unwrap_or(DKGSessionState::Idle);
        drop(session_state_lock); // Release lock

        if current_state < DKGSessionState::Round2Initiated {
            // Only process if we've initiated Round 2
            log::warn!(
                "[TSS]: Received DKGRound2 for session {} but local state is {:?}. Ignoring message.",
                session_id,
                current_state
            );

            return Err(SessionManagerError::Round2SecretPackageNotYetAvailable);
        }

        if self.local_peer_id != *recipient {
            log::warn!(
                "[TSS]: Received DKGRound2 for session {} for peer {:?} but it's not for us ({:?}). Ignoring message.",
                session_id, PeerId::from_bytes(&recipient), self.local_peer_id
            );
            return Ok(());
        }

        let mut storage = self.storage.lock().unwrap();

        let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();

        let identifier = peer_mapper_handle.get_identifier_from_peer_id(&session_id, &sender);

        if let None = identifier {
            // this can never happen, but we handle it anyway.
            log::warn!(
                "[TSS]: Couldn't find identifier fo Session {} and peer_id {:?}. Ignoring message.",
                session_id,
                sender
            );

            return Err(SessionManagerError::IdentifierNotFound);
        }

        let identifier = identifier.unwrap();

        if let Err(e) = round2::Package::deserialize(&bytes[..]) {
            log::error!(
                "[TSS] Error {:?} Invalid data received as DKGRound2 = {:?}",
                e,
                bytes
            );
            return Err(SessionManagerError::DeserializationError);
        }
        storage.store_round2_packages(session_id, identifier, &bytes[..]);

        drop(peer_mapper_handle);
        drop(storage);

        if let Err(e) = self.dkg_verify_and_complete(session_id) {
            log::error!(
                "[TSS] There was an error verifying Round2 to complete DKG {:?}",
                e
            )
        }

        return Ok(());
    }

    fn dkg_verify_and_complete(&self, session_id: SessionId) -> Result<(), SessionManagerError> {
        // Process the buffered messages before checking anything else
        self.dkg_process_buffer_for_round2(session_id);

        let storage = self.storage.lock().unwrap();

        let round2_secret_package = storage.read_secret_package_round2(session_id);
        if let Err(_e) = round2_secret_package {
            log::warn!(
                "[TSS]: Received DKGRound2 for session {} but local round 2 secret package not ready yet.",
                session_id
            );
            return Err(SessionManagerError::Round2SecretPackageNotYetAvailable);
        }
        let round2_secret_package = round2_secret_package.unwrap();

        let n = round2_secret_package.max_signers();

        let round1_packages = storage.fetch_round1_packages(session_id).unwrap();
        let round2_packages = storage.fetch_round2_packages(session_id).unwrap();
        drop(storage); // Release lock

        if round2_packages.keys().len() >= (n - 1).into() {
            match dkg::part3(&round2_secret_package, &round1_packages, &round2_packages) {
                Ok((private_key, public_key)) => {


                    let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();
                    let whoami_identifier = peer_mapper_handle.get_identifier_from_account_id(&session_id, &self.validator_key);

                    if let None = whoami_identifier {
                        log::error!("[TSS] We are not allowed to participate in the signing phase");
                        return Err(SessionManagerError::IdentifierNotFound);
                    }

                    drop(peer_mapper_handle);



                    let mut storage = self.key_storage.lock().unwrap();
                    let _ = storage.store_data(
                        session_id,
                        dkghelpers::StorageType::PubKey,
                        &public_key.serialize().unwrap()[..],
                        Some(&whoami_identifier.unwrap().serialize()),
                    );
                    if let Err(error) = storage.store_data(
                        session_id,
                        dkghelpers::StorageType::Key,
                        &private_key.serialize().unwrap()[..],
                        Some(&whoami_identifier.unwrap().serialize()),
                    ) {
                        log::error!("[TSS] There was an error storing key {:?}", error);
                    }
                    drop(storage);
                    log::info!(
                        "[TSS]: DKG Part 3 successful for session {}. Public Key: {:?}",
                        session_id,
                        public_key
                    );
                    // Update session state to KeyGenerated
                    let mut session_state_lock = self.dkg_session_states.lock().unwrap();
                    session_state_lock.insert(session_id, DKGSessionState::KeyGenerated);
                    drop(session_state_lock); // Release lock
                }
                Err(e) => {
                    log::error!(
                        "[TSS]: DKG Part 3 failed for session {}: {:?}",
                        session_id,
                        e
                    );
                    // Update session state to Failed
                    let mut session_state_lock = self.dkg_session_states.lock().unwrap();
                    session_state_lock.insert(session_id, DKGSessionState::Failed);
                    drop(session_state_lock); // Release lock
                }
            }
        }

        Ok(())
    }

    /// Process a new DKG session creation
    fn dkg_handle_session_created(
        &self,
        session_id: SessionId,
        n: u64,
        t: u64,
        participants: Vec<TSSParticipant>,
    ) -> Result<(), SessionError>
    where
        B: BlockT,
    {
        
        // Validate threshold and participant count
        if t == 0 || n == 0 || t > n {
            log::error!("[TSS] Invalid threshold parameters for DKG session {}: t={}, n={}", session_id, t, n);
            return Err(SessionError::GenericError(format!("Invalid threshold parameters: t={}, n={}", t, n)));
        }
        
        if participants.len() != n as usize {
            log::error!(
                "[TSS] Mismatch between participant count and n parameter for DKG session {}: {} vs {}",
                session_id, participants.len(), n
            );
            return Err(SessionError::GenericError(format!(
                "Participant count ({}) doesn't match n parameter ({})",
                participants.len(), n
            )));
        }
        
        let mut index = None;
        log::debug!("[TSS] participants={:?}", participants);

        // Check if we're part of the participants
        for (i, el) in participants.iter().enumerate() {
            if *el == self.validator_key[..] {
                index = Some(i);
                break;
            }
        }

        if index.is_none() {
            log::error!("[TSS] Not authorized to participate in DKG session {}", session_id);
            return Err(SessionError::NotAuthorized);
        }
        
        let index: Result<u16, TryFromIntError> = index.unwrap().try_into();
        if let Err(e) = index {
            log::error!("[TSS] Error converting index to u16: {:?}", e);
            return Err(SessionError::GenericError("Error converting index to u16".into()));
        }
        
        let index = index.unwrap();
        info!("[TSS] Our index in DKG session {}: {}", session_id, index);

        let participant_identifier: Identifier = (index + 1).try_into().unwrap();

        log::info!("[TSS] Event received from DKG, starting round 1 for session {}", session_id);

        // Generate round 1 package
        let (r1, secret) = match dkground1::generate_round1_secret_package(
            t.try_into().unwrap_or(u16::MAX),
            n.try_into().unwrap(),
            participant_identifier,
            session_id,
        ) {
            Ok(result) => result,
            Err(e) => {
                log::error!("[TSS] Failed to generate round 1 package for session {}: {:?}", session_id, e);
                return Err(SessionError::GenericError(format!("Failed to generate round 1 package: {:?}", e)));
            }
        };

        // Store secret package
        let mut storage = self.storage.lock().unwrap();
        if let Err(e) = storage.store_data(
            session_id,
            dkghelpers::StorageType::DKGRound1SecretPackage,
            &secret.serialize().unwrap()[..],
            None,
        ) {
            log::error!("[TSS] Failed to store secret package for session {}: {:?}", session_id, e);
            return Err(SessionError::GenericError(format!("Failed to store secret package: {:?}", e)));
        }

        // Update session state
        let mut handle_state = self.dkg_session_states.lock().unwrap();
        handle_state.insert(session_id, DKGSessionState::Round1Initiated);
        drop(handle_state);
        drop(storage);

        // Send round 1 message
        match self.session_manager_to_gossip_tx.unbounded_send((
            PeerId::from_bytes(&self.local_peer_id[..]).unwrap(),
            TssMessage::DKGRound1(session_id, r1.serialize().unwrap()),
        )) {
            Ok(_) => log::info!("[TSS] Round 1 message broadcasted for session {}", session_id),
            Err(e) => {
                log::error!("[TSS] Failed to send round 1 message for session {}: {:?}", session_id, e);
                return Err(SessionError::GenericError(format!("Failed to send round 1 message: {:?}", e)));
            }
        }

        // Process any buffered messages for this session
        let mut handle = self.buffer.lock().unwrap();
        let entries = handle.entry(session_id).or_default().clone();
        drop(handle);

        for (peer_id, message) in entries {
            match message {
                TssMessage::DKGRound1(_, bytes) => {
                    log::info!(
                        "[TSS] Processing buffered DKGRound1 message for session {} from peer_id {:?}",
                        session_id,
                        PeerId::from_bytes(&peer_id[..]).unwrap().to_base58()
                    );
                    if let Err(e) = self.dkg_handle_round1_message(
                        session_id,
                        &bytes,
                        PeerId::from_bytes(&peer_id[..]).unwrap(),
                    ) {
                        log::error!(
                            "[TSS] Error processing buffered DKGRound1 message for session {}: {:?}",
                            session_id,
                            e
                        );
                    }
                }
                _ => (), // ignore other message types for now
            }
        }

        // Try to complete round 1 if we have enough messages already
        self.dkg_handle_verification_to_complete_round1(session_id);
        
        Ok(())
    }

    fn signing_handle_session_created(
        &self,
        session_id: SessionId,
        participants: Vec<TSSParticipant>,
        coordinator: TSSParticipant,
    ) where
        B: BlockT,
    {
        // Store the participants
        let mut handle = self.sessions_participants.lock().unwrap();
        let mut tmp = HashMap::<Identifier, TSSPublic>::new();

        let mut index = None;

        log::debug!("[TSS] participants={:?}", participants);

        for (i, el) in participants.into_iter().enumerate() {
            tmp.insert(u16::try_from(i + 1).unwrap().try_into().unwrap(), el.into());

            if el == self.validator_key[..] {
                index = Some(i);
            }
        }

        // Check if we are part of this

        if let None = index {
            log::error!("[TSS] Not allowed to participate in Signing");
            return;
        }
        let index: Result<u16, TryFromIntError> = index.unwrap().try_into();

        info!("[TSS] Index: {:?}", index);

        if let Err(_) = index {
            log::error!("[TSS] Not allowed to participate in Signing");
            return;
        }

        handle.insert(session_id, tmp);
        drop(handle);

        log::debug!("[TSS]: Event received from Signing, starting round 1");

        let key_storage = self.key_storage.lock().unwrap();

        let key_package = key_storage.get_key_package(session_id, &(u16::try_from(index.unwrap()+1).unwrap().try_into().unwrap()));

        if let Err(error) = key_package {
            log::error!("[TSS] Error fetching Key Package {:?}", error);
            return;
        }
        // Generate commitments and nonces from the key_package.signing_share()
        let (nonces, commitments) =
            signlib::generate_signing_commitments_and_nonces(key_package.unwrap());

        drop(key_storage);

        let mut storage = self.storage.lock().unwrap();
        // Store the nonces
        if let Err(error) = storage.store_data(
            session_id,
            StorageType::SigningNonces,
            &(nonces.serialize().unwrap()[..]),
            None,
        ) {
            log::error!("[TSS] Error storing nonces {:?}", error);
        }

        drop(storage);

        let mut handle_state = self.signing_session_states.lock().unwrap();
        handle_state.insert(session_id, SigningSessionState::Round1Initiated);
        drop(handle_state);

        // And send the commitment to our coordinator
        let mut peer_handle = self.peer_mapper.lock().unwrap();
        let peer_id = peer_handle.get_peer_id_from_account_id(&coordinator.to_vec());
        if let Some(peer_id) = peer_id {
            match self.session_manager_to_gossip_tx.unbounded_send((
                peer_id.clone(),
                TssMessage::SigningCommitment(session_id, commitments.serialize().unwrap()),
            )) {
                Err(error) => log::error!(
                    "[TSS] There was an error sending commitments to the coordinator {:?}",
                    error
                ),
                Ok(_) => {
                    // Update session state to Round1Completed
                    let mut session_state_lock = self.signing_session_states.lock().unwrap();
                    session_state_lock.insert(session_id, SigningSessionState::Round1Completed);
                    drop(session_state_lock);
                    log::info!("[TSS] Setting Round1Completed");
                }
            }
        }
        drop(peer_handle);
    }

    pub fn dkg_process_buffer_for_round2(&self, session_id: SessionId) {
        let messages = {
            let mut buffer = self.buffer.lock().unwrap();
            buffer.entry(session_id).or_default().clone()
        };

        for (peer_id, message) in messages {
            // Process the (peer_id, message) pair without holding the lock
            match message {
                TssMessage::DKGRound2(_, bytes, recipient) => {
                    log::info!(
                        "[TSS] Handling buffered message from peer_id {:?}",
                        PeerId::from_bytes(&peer_id[..]).unwrap().to_base58()
                    );
                    if let Err(e) = self.dkg_handle_round2_message(
                        session_id,
                        &bytes,
                        &recipient,
                        PeerId::from_bytes(&peer_id[..]).unwrap(),
                    ) {
                        log::error!(
                            "[TSS] There was an error while handling buffered message {:?}",
                            e
                        );
                    }
                }
                _ => (), // ignore the rest
            }
        }
    }

    fn signing_handle_commitment(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        sender: PeerId,
    ) -> Result<(), SessionManagerError> {
        // STEP 1: For sure, we need to store the message for later use.
        let mut storage = self.storage.lock().unwrap();

        let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();

        let identifier = peer_mapper_handle.get_identifier_from_peer_id(&session_id, &sender);

        log::info!(
            "[TSS] Apparently peer_id = {:?} is associated with identifier = {:?}",
            sender,
            identifier
        );

        if let None = identifier {
            log::warn!(
                "[TSS]: Couldn't find identifier fo Session {} and peer_id {:?}. Ignoring message.",
                session_id,
                sender
            );

            return Err(SessionManagerError::IdentifierNotFound);
        }

        let identifier = identifier.unwrap();
        log::info!(
            "[TSS] Stored received commitment message from identifier {:?}",
            identifier.clone()
        );
        storage.store_commitment(session_id, identifier, &bytes[..]);
        drop(peer_mapper_handle);
        drop(storage);


        let handle_state = self.signing_session_states.lock().unwrap();
        let current_state = handle_state.get(&session_id);

        if current_state.is_some() && current_state.unwrap() >= &SigningSessionState::Round2Completed {
            return Ok(());
        }
        drop(handle_state);


        if self.is_coordinator(&session_id) {
            log::info!("[TSS] calling signing_handle_verification_to_complete_round1()");
            self.signing_handle_verification_to_complete_round1(session_id);
        }
        Ok(())
    }

    fn signing_handle_verification_to_complete_round1(&self, session_id: SessionId) {
        let storage = self.storage.lock().unwrap();

        let commitments = storage.fetch_commitments(session_id).unwrap();
        drop(storage); // Release lock

        log::debug!("[TSS] debug commitments = {:?}", commitments);

        let keys = commitments.keys();

        let session_data = self.sessions_data.lock().unwrap();

        let session_data = session_data.get(&session_id);

        if let None = session_data {
            log::error!("[TSS] Session doesn't exist");
            return;
        }
        let (t,_,_,message) = session_data.unwrap();

        if u16::try_from(keys.len()).unwrap() < *t {
            return;
        }
        
        let message = &message[..];

        let signing_package = signlib::get_signing_package(message, commitments.clone());

        let mut handle_state = self.signing_session_states.lock().unwrap();
        handle_state.insert(session_id, SigningSessionState::Round2Initiated);
        drop(handle_state);


        if let Err(error) = signing_package.serialize() {
            log::error!(
                "[TSS] There was an error serializing signing package {:?}",
                error
            );
        }

        let mut storage = self.storage.lock().unwrap();
        if let Err(error) = storage.store_data(
            session_id,
            StorageType::SigningPackage,
            &(signing_package.serialize().unwrap())[..],
            None,
        ) {
            log::error!(
                "[TSS] There was an error storing signing package {:?}",
                error
            );
        }


        self.signing_send_signing_package_to_committed_participants(
            session_id,
            signing_package,
            keys,
        );
    }

    fn signing_send_signing_package_to_committed_participants(
        &self,
        session_id: SessionId,
        signing_package: SigningPackage,
        committed: Keys<'_, Identifier, SigningCommitments>,
    ) {
        let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();

        let signing_package = signing_package.serialize().unwrap();

        for identifier in committed {
            let peer_id = peer_mapper_handle.get_peer_id_from_identifier(&session_id, identifier);

            if let None = peer_id {
                // this shouldn't have happened
                log::error!(
                    "[TSS] PeerId Not Found In Session {:?} for Identifier {:?}",
                    session_id,
                    identifier
                );
                continue;
            }

            if let Err(error) = self.session_manager_to_gossip_tx.unbounded_send((
                peer_id.unwrap().clone(),
                TssMessage::SigningPackage(session_id.clone(), signing_package.clone()),
            )) {
                log::error!(
                    "[TSS] There was an error sending data to the outgoing channel {:?}",
                    error
                );
                return;
                // what do we do? start over?
            }
        }
        let mut handle_state = self.signing_session_states.lock().unwrap();
        handle_state.insert(session_id, SigningSessionState::Round2Completed);
        drop(handle_state);
        log::info!("[TSS] Setting Round2Completed");

        drop(peer_mapper_handle);
    }

    fn signing_handle_signing_package(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        _sender: PeerId,
    ) -> Result<(), SessionManagerError> {
        let signing_package = SigningPackage::deserialize(bytes);

        log::info!("[TSS] Handling signing package from coordinator");

        // Update session state to Round1Completed
        let mut session_state_lock = self.signing_session_states.lock().unwrap();
        session_state_lock.insert(session_id, SigningSessionState::Round2Initiated);
        drop(session_state_lock);

        if let Err(error) = signing_package {
            log::error!(
                "[TSS] There was an error deserializing the Signing Package {:?}",
                error
            );
            return Err(SessionManagerError::DeserializationError);
        }

        // STEP 1: For sure, we need to store the message for later use.
        let storage = self.storage.lock().unwrap();
        let nonces = storage.read_nonces(session_id);

        if let Err(error) = nonces {
            log::error!(
                "[TSS] There was an error fetching nonces from the storage {:?}",
                error
            );
        }


        let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();
        let whoami_identifier = peer_mapper_handle.get_identifier_from_account_id(&session_id, &self.validator_key);

        if let None = whoami_identifier {
            log::error!("[TSS] We are not allowed to participate in the signing phase");
            return Err(SessionManagerError::IdentifierNotFound);
        }
        let key_storage = self.key_storage.lock().unwrap();
        let key_package = key_storage.get_key_package(session_id, &whoami_identifier.unwrap());
        drop(key_storage);
        drop(peer_mapper_handle);
        if let Err(error) = key_package {
            log::error!("[TSS] Error fetching the key package {:?}", error);
        }

        if (&signing_package.as_ref()).unwrap().signing_commitments().len() < (*(&key_package.as_ref()).unwrap().min_signers()).into() {
            log::info!("[TSS] FROST round 2 signing requires at least {:?} signers, for now only {:?} provided", key_package.unwrap().min_signers(), signing_package.unwrap().signing_commitments().len());
            return Ok(());
        }

        let signature_share = frost_round2_sign(
            &signing_package.unwrap(),
            &nonces.unwrap(),
            &key_package.unwrap(),
        )
        .unwrap();

        log::info!("[TSS] Signature share generated, ready to send");

        drop(storage);

        // log::info!("[TSS] calling signing_handle_verification_to_complete_round1()");
        // self.signing_handle_verification_to_complete_round1(session_id);



        let data = self.get_session_data(&session_id);
        
        if let None = data {
            log::error!("[TSS] No data found in Storage");
        }

        let (_, _, coordinator, _) = data.unwrap();

        log::debug!("Coordinator = {:?}", coordinator.clone());

        let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();

        let coordinator = peer_mapper_handle.get_peer_id_from_account_id(&coordinator);

        if let Some(coordinator) = coordinator {
            log::debug!("I found that coordinator is associated with peer_id = {:?}", coordinator);
            match self.session_manager_to_gossip_tx.unbounded_send((
                coordinator.clone(),
                TssMessage::SigningShare(session_id, signature_share.serialize()),
            )) {
                Err(error) =>log::error!(
                    "[TSS] There was an error sending Signature Share to the coordinator {:?}",
                    error
                ),
                Ok(_) => {
                    log::info!("[TSS] Signing Share sent to coordinator {:?}", coordinator);
                    // Update session state to Round1Completed
                    let mut session_state_lock = self.signing_session_states.lock().unwrap();
                    session_state_lock.insert(session_id, SigningSessionState::Round2Completed);
                    drop(session_state_lock);
                    log::info!("[TSS] Signin State updated to SigningSessionState::Round2Completed");
                }
            }
        } else {
            log::error!("[TSS] Missing coordinator information, for peer {:?}", coordinator);
        }
        

        Ok(())
    }

    fn signing_handle_signature_share(
        &self,
        session_id: SessionId,
        bytes: &Vec<u8>,
        sender: PeerId,
    ) -> Result<Signature, SessionManagerError> {
        let signature_share = SignatureShare::deserialize(bytes);
        // Update session state to Round1Completed
        let mut session_state_lock = self.signing_session_states.lock().unwrap();
        session_state_lock.insert(session_id, SigningSessionState::Round3Initiated);
        drop(session_state_lock);
        

        if let Err(error) = signature_share {
            log::error!(
                "[TSS] There was an error deserializing the Signature Share {:?}",
                error
            );
            return Err(SessionManagerError::DeserializationError);
        }
        let mut storage = self.storage.lock().unwrap();
        let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();

        let identifier = peer_mapper_handle.get_identifier_from_peer_id(&session_id, &sender);

        log::info!(
            "[TSS] Apparently peer_id = {:?} is associated with identifier = {:?}",
            sender,
            identifier
        );

        if let None = identifier {
            log::warn!(
                "[TSS]: Couldn't find identifier fo Session {} and peer_id {:?}. Ignoring message.",
                session_id,
                sender
            );

            return Err(SessionManagerError::IdentifierNotFound);
        }

        let identifier = identifier.unwrap();
        log::info!(
            "[TSS] Stored received signature share message from identifier {:?}",
            identifier.clone()
        );
        storage.store_signature_share(session_id, identifier, &bytes[..]);
        drop(peer_mapper_handle);
        drop(storage);

        let storage = self.storage.lock().unwrap();

        let signature_shares = storage.fetch_signature_shares(session_id);

        if let Err(error) = signature_shares {
            log::error!(
                "[TSS] Error fetching Signature Shares for SesssionId {:?} {:?}",
                session_id,
                error
            );
            return Err(SessionManagerError::DeserializationError);
        }

        let data = self.get_session_data(&session_id);
        if let None = data {
            log::error!("[TSS] No data found in Storage");
        }

        let (t, _, _, _) = data.unwrap();

        let signature_shares = signature_shares.unwrap();
        log::info!("signature_shares = {:?}", signature_shares);

        if signature_shares.len() >= t.into() {
            let signing_package = storage.read_signing_package(session_id);

            if let Err(error) = signing_package {
                log::error!(
                    "[TSS] Error fetching Signing Package for SesssionId {:?} {:?}",
                    session_id,
                    error
                );
            }

            let key_storage = self.key_storage.lock().unwrap();
            let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();
            let whoami_identifier = peer_mapper_handle.get_identifier_from_account_id(&session_id, &self.validator_key);

            if let None = whoami_identifier {
                log::error!("[TSS] We are not allowed to participate in the signing phase");
                return Err(SessionManagerError::IdentifierNotFound);
            }
            let pubkeys = key_storage.get_pubkey(session_id, &whoami_identifier.unwrap());
            drop(peer_mapper_handle);

            if let Err(error) = signing_package {
                log::error!(
                    "[TSS] Error fetching Signing Package for SesssionId {:?} {:?}",
                    session_id,
                    error
                );
            }

            let signature = aggregate(
                &signing_package.unwrap(),
                &signature_shares,
                &pubkeys.unwrap(),
            );

            if let Err(error) = signature {
                log::error!("[TSS] Error aggregating Signature {:?}", error);

                 // Update session state to Round1Completed
                let mut session_state_lock = self.signing_session_states.lock().unwrap();
                session_state_lock.insert(session_id, SigningSessionState::Failed);
                drop(session_state_lock);
                return Err(SessionManagerError::SignatureAggregationError);
            }

            let mut handle_state = self.signing_session_states.lock().unwrap();
            handle_state.insert(session_id, SigningSessionState::SignatureGenerated);
            drop(handle_state);


            
            drop(storage);
            drop(key_storage);

            return Ok(signature.unwrap());
        }
        log::error!("[TSS] Only {:?} signature shares received. Needing {:?} to proceed", signature_shares.len(), t);
        return Err(SessionManagerError::SignatureNotReadyYet);
    }

    fn ecdsa_create_keygen_phase(
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

    fn ecdsa_create_reshare_phase(
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
            .position(|&el| el == &self.validator_key[..]);

        if let None = my_id {
            log::info!("[TSS] We are not allowed to participate");
            return;
        }
        log::info!("[TSS] My Id = {:?}", my_id.unwrap() + 1);

        let identifier: Identifier = u16::try_from(my_id.unwrap() + 1).unwrap().try_into().unwrap();

        let current_keys = self.key_storage.lock().unwrap().read_data(id, StorageType::EcdsaKeys, Some(&identifier.serialize()));

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

    /// Cleanup expired sessions
    fn cleanup_expired_sessions(&mut self) {
        let now = std::time::Instant::now();
        let mut expired_sessions = Vec::new();
        
        // Identify expired sessions
        {
            let timestamps = self.session_timestamps.lock().unwrap();
            for (session_id, timestamp) in timestamps.iter() {
                if now.duration_since(*timestamp).as_secs() > self.session_timeout {
                    expired_sessions.push(*session_id);
                }
            }
        }
        
        // Clean up expired sessions
        for session_id in expired_sessions {
            log::info!("[TSS] Cleaning up expired session {}", session_id);

            // Get the inactive participants for reporting them
            let inactive_participants = self.get_inactive_participants(&session_id);
            if inactive_participants.len() > 0 { 
                let best_hash = self.client.best_hash();
                let _ = self.client.report_participants(best_hash, session_id, inactive_participants.clone());
            }

            // Remove from all session data structures
            {
                let mut session_data = self.sessions_data.lock().unwrap();
                session_data.remove(&session_id);
            }
            
            {
                let mut sessions_participants = self.sessions_participants.lock().unwrap();
                sessions_participants.remove(&session_id);
            }
            
            {
                let mut dkg_states = self.dkg_session_states.lock().unwrap();
                dkg_states.remove(&session_id);
            }
            
            {
                let mut signing_states = self.signing_session_states.lock().unwrap();
                signing_states.remove(&session_id);
            }
            
            {
                let mut timestamps = self.session_timestamps.lock().unwrap();
                timestamps.remove(&session_id);
            }
            
            {
                let mut buffer = self.buffer.lock().unwrap();
                buffer.remove(&session_id);
            }
        }
    }

    async fn run(mut self) {
        log::info!("[TSS] Listening for messages inside Session Manager from Gossip and Runtime");
        
        // Set up a timer for periodic session cleanup
        let mut cleanup_interval = interval(Duration::from_secs(60));
        
        loop {
            select! {
                // Run periodic cleanup of expired sessions
                _ = cleanup_interval.next().fuse() => {
                    self.cleanup_expired_sessions();
                },
                
                // Process messages from the gossip network
                gossip_notification = self.gossip_to_session_manager_rx.next().fuse() => {
                    if let Some((peer_id, message)) = gossip_notification {
                        self.process_gossip_message(peer_id, message);
                    }
                },

                // Process messages from the runtime
                runtime_message = self.runtime_to_session_manager_rx.next().fuse() => {
                    if let Some(runtime_message) = runtime_message {
                        self.process_runtime_message(runtime_message);
                    }
                },
            }
        }
    }

    fn process_gossip_message(&mut self, peer_id: PeerId, message: TssMessage) {
        self.handle_gossip_message(message, peer_id.to_bytes());
    }

    fn process_runtime_message(&mut self, runtime_message: TSSRuntimeEvent) {
        match runtime_message {
            TSSRuntimeEvent::DKGSessionInfoReady(id, t, n, participants) => {
                if let Err(e) = self.add_and_initialize_dkg_session(id, t, n, participants) {
                    log::error!("[TSS] Failed to process DKG session {}: {:?}", id, e);
                }
            }
            TSSRuntimeEvent::DKGReshareSessionInfoReady(id, t, n, participants, old_participants) => {
                if let Err(e) = self.add_and_initialize_dkg_reshare_session(id, t, n, participants, old_participants) {
                    log::error!("[TSS] Failed to process DKG session {}: {:?}", id, e);
                }
            }
            TSSRuntimeEvent::SigningSessionInfoReady(id, t, n, participants, coordinator, message) => {
                if let Err(e) = self.add_and_initialize_signing_session(id, t, n, participants, coordinator, message) {
                    log::error!("[TSS] Failed to process signing session {}: {:?}", id, e);
                }
            }
            TSSRuntimeEvent::ValidatorIdAssigned(account_id, id) => {
                self.on_new_validator_id_assigned(account_id.to_vec(), id);
            }
        }
    }

    fn add_and_initialize_dkg_session(&mut self, id: SessionId, t: u16, n: u16, participants: Vec<TSSParticipant>) -> Result<(), String> {
        self.add_session_data(id, t, n, [0; 32], participants.clone(), Vec::new())
            .map_err(|e| format!("Failed to add data: {:?}", e))?;
        
        log::info!("[TSS] Successfully added data for DKG session {}", id);
        
        // Check if the node is authorized for this session
        if !self.is_authorized_for_session(&id) {
            log::warn!("[TSS] Node not authorized for session {}", id);
            return Err(format!("Node not authorized for session {}", id));
        }
        

        self.dkg_handle_session_created(id, n.into(), t.into(), participants.clone())
            .map_err(|e| format!("Failed to initialize DKG session: {:?}", e))?;
        
        log::info!("[TSS] Successfully initialized DKG session {}", id);
        
        self.ecdsa_create_keygen_phase(id, n.into(), t.into(), participants);
        
        Ok(())
    }

    fn add_and_initialize_dkg_reshare_session(&mut self, id: SessionId, t: u16, n: u16, participants: Vec<TSSParticipant>, old_participants: Vec<TSSParticipant>) -> Result<(), String> {
        self.add_session_data(id, t, n, [0; 32], participants.clone(), Vec::new())
            .map_err(|e| format!("Failed to add data: {:?}", e))?;
        
        // log::info!("[TSS] Successfully added data for DKG session {}", id);
        
        // self.dkg_handle_session_created(id, n.into(), t.into(), participants.clone())
        //     .map_err(|e| format!("Failed to initialize DKG session: {:?}", e))?;
        
        log::info!("[TSS] Successfully initialized DKG session {}", id);
        
        self.ecdsa_create_reshare_phase(id, n.into(), t.into(), participants, old_participants);
        
        Ok(())
    }

    fn add_and_initialize_signing_session(&mut self, id: SessionId, t: u16, n: u16, participants: Vec<TSSParticipant>, coordinator: [u8; 32], message: Vec<u8>) -> Result<(), String> {
        self.add_session_data(id, t, n, coordinator, participants.clone(), message.clone())
            .map_err(|e| format!("Failed to add data: {:?}", e))?;
        
        log::info!("[TSS] Successfully added data for signing session {}", id);

        self.signing_handle_session_created(id, participants.clone(), coordinator.clone());
    
        log::info!("[TSS] Successfully initialized FROST Signing session {}", id);

        
        self.ecdsa_create_sign_phase(id, participants, message);
        
        Ok(())
    }

    fn on_new_validator_id_assigned(&mut self, account_id: TSSPublic, id: u32) {
        let mut peer_mapper_handle = self.peer_mapper.lock().unwrap();
        peer_mapper_handle.set_validator_id(account_id, id);
    }
}

// ===== RuntimeEventHandler =====
struct RuntimeEventHandler<B: BlockT, C>
where
    C: BlockchainEvents<B> + ProvideRuntimeApi<B> + Send + Sync + 'static,
    C::Api: uomi_runtime::pallet_tss::TssApi<B>,
{
    client: Arc<C>,
    sender: TracingUnboundedSender<TSSRuntimeEvent>,
    _phantom: PhantomData<B>,
}

impl<B: BlockT, C> RuntimeEventHandler<B, C>
where
    C: BlockchainEvents<B> + ProvideRuntimeApi<B> + Send + Sync + 'static,
    C::Api: uomi_runtime::pallet_tss::TssApi<B>,
{
    fn new(client: Arc<C>, sender: TracingUnboundedSender<TSSRuntimeEvent>) -> Self {
        Self {
            client,
            sender,
            _phantom: PhantomData,
        }
    }

    async fn run(self) {
        log::info!("[TSS] Listening for messages from Runtime");
        let notification_stream = self.client.storage_changes_notification_stream(None, None);

        if let Err(error) = notification_stream {
            log::error!("[TSS] Error acquiring notifiaction stream {:?}", error);
            return;
        }

        let mut notification_stream = notification_stream.unwrap();

        while let Some(event) = notification_stream.next().await {
            let hash = event.block;
            let events_key = sp_core::twox_128("System".as_bytes()).to_vec();
            let events_storage_key =
                [events_key, sp_core::twox_128("Events".as_bytes()).to_vec()].concat();

            for (_parent_key, key, value) in event.changes.iter() {
                if key.as_ref().starts_with(&events_storage_key[..]) {
                    if let Some(data) = value {
                        let raw_bytes = data.0.as_slice();
                        let mut cursor = &raw_bytes[..];
                        let num_events_compact =
                            Compact::<u32>::decode(&mut cursor).unwrap_or(Compact(0)); // Error handling!
                        let num_events = num_events_compact.0;

                        for _i in 0..num_events {
                            match EventRecord::<RuntimeEvent, B::Hash>::decode(&mut cursor) {
                                Ok(event_record) => match event_record.event {
                                    RuntimeEvent::Tss(TssEvent::DKGSessionCreated(id)) => {
                                        let n = self
                                            .client
                                            .runtime_api()
                                            .get_dkg_session_participants_count(hash, id)
                                            .unwrap();
                                        let t = self
                                            .client
                                            .runtime_api()
                                            .get_dkg_session_threshold(hash, id)
                                            .unwrap();

                                        // t is a percentage value, convert it to the actual threshold value
                                        let t = (t as f64 * n as f64 / 100.0) as u16;

                                        let participants = self
                                            .client
                                            .runtime_api()
                                            .get_dkg_session_participants(hash, id)
                                            .unwrap_or(Vec::new());

                                        // let the session manager now about the new DKG Session started
                                        if let Err(e) = self.sender.unbounded_send(
                                            TSSRuntimeEvent::DKGSessionInfoReady(
                                                id,
                                                u16::try_from(t).unwrap_or(u16::MAX),
                                                n,
                                                participants,
                                            ),
                                        ) {
                                            log::error!("[TSS] There was a problem communicating with the TSS Session Manager {:?}", e);
                                        }
                                    }

                                    RuntimeEvent::Tss(TssEvent::DKGReshareSessionCreated(id)) => {
                                        let n = self
                                            .client
                                            .runtime_api()
                                            .get_dkg_session_participants_count(hash, id)
                                            .unwrap();
                                        let t = self
                                            .client
                                            .runtime_api()
                                            .get_dkg_session_threshold(hash, id)
                                            .unwrap();

                                        // t is a percentage value, convert it to the actual threshold value
                                        let t = (t as f64 * n as f64 / 100.0) as u16;

                                        let participants = self
                                            .client
                                            .runtime_api()
                                            .get_dkg_session_participants(hash, id)
                                            .unwrap_or(Vec::new());

                                        let old_participants = self
                                            .client
                                            .runtime_api()
                                            .get_dkg_session_old_participants(hash, id)
                                            .unwrap_or(Vec::new());

                                        // let the session manager now about the new DKG Session started
                                        if let Err(e) = self.sender.unbounded_send(
                                            TSSRuntimeEvent::DKGReshareSessionInfoReady(
                                                id,
                                                u16::try_from(t).unwrap_or(u16::MAX),
                                                n,
                                                participants,
                                                old_participants,
                                            ),
                                        ) {
                                            log::error!("[TSS] There was a problem communicating with the TSS Session Manager {:?}", e);
                                        }
                                    }

                                    RuntimeEvent::Tss(TssEvent::SigningSessionCreated(signing_session_id, dkg_session_id)) => {
                                        log::debug!("[TSS] Starting signing session {:?} using DKG session {:?}",signing_session_id, dkg_session_id);
                                        let n = self
                                            .client
                                            .runtime_api()
                                            .get_dkg_session_participants_count(hash, dkg_session_id)
                                            .unwrap();
                                        let t = self
                                            .client
                                            .runtime_api()
                                            .get_dkg_session_threshold(hash, dkg_session_id)
                                            .unwrap();

                                        
                                        // t is a percentage value, convert it to the actual threshold value
                                        let t = (t as f64 * n as f64 / 100.0) as u16;

                                        let participants = self
                                            .client
                                            .runtime_api()
                                            .get_dkg_session_participants(hash, dkg_session_id)
                                            .unwrap_or(Vec::new());

                                        let message = self
                                            .client
                                            .runtime_api()
                                            .get_signing_session_message(hash, dkg_session_id)
                                            .unwrap_or(Vec::new());

                                        // TODO: add the function in the pallet for these three:
                                        let coordinator = participants[0];
                                        let id = dkg_session_id;

                                        // let the session manager now about the new Signing Session
                                        if let Err(e) = self.sender.unbounded_send(
                                            TSSRuntimeEvent::SigningSessionInfoReady(
                                                id,
                                                u16::try_from(t).unwrap_or(u16::MAX),
                                                n,
                                                participants,
                                                coordinator,
                                                message
                                            ),
                                        ) {
                                            log::error!("[TSS] There was a problem communicating with the TSS Session Manager {:?}", e);
                                        }
                                    }

                                    RuntimeEvent::Tss(TssEvent::ValidatorIdAssigned(account_id, id)) => {
                                        if let Err(e) = self.sender.unbounded_send(
                                            TSSRuntimeEvent::ValidatorIdAssigned(account_id.into(), id),
                                        ) {
                                            log::error!("[TSS] There was a problem communicating with the TSS Session Manager {:?}", e);
                                        }
                                    }
                                    _ => (),
                                },
                                Err(e) => {
                                    log::error!("Error decoding event: {:?}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
// ===== GossipHandler =====
// Define a trait for message handling to make testing easier
pub trait TssMessageHandler {
    fn send_message(&mut self, message: TssMessage, recipient: PeerId) -> Result<(), String>;
    fn broadcast_message(&mut self, message: TssMessage) -> Result<(), String>;
    fn handle_announcment(&mut self, sender: PeerId, message: TssMessage);
    fn forward_to_session_manager(&self, sender: PeerId, message: TssMessage) -> Result<(), TrySendError<(PeerId, TssMessage)>>;
}
struct GossipHandler<B: BlockT> {
    gossip_engine: GossipEngine<B>,

    peer_mapper: Arc<Mutex<PeerMapper>>,

    gossip_to_session_manager_tx: TracingUnboundedSender<(PeerId, TssMessage)>,
    session_manager_to_gossip_rx: TracingUnboundedReceiver<(PeerId, TssMessage)>,
    gossip_handler_message_receiver: Receiver<TopicNotification>,
}

impl<B: BlockT> GossipHandler<B> {
    fn new(
        gossip_engine: GossipEngine<B>,
        gossip_to_session_manager_tx: TracingUnboundedSender<(PeerId, TssMessage)>,
        session_manager_to_gossip_rx: TracingUnboundedReceiver<(PeerId, TssMessage)>,
        peer_mapper: Arc<Mutex<PeerMapper>>,
        gossip_handler_message_receiver: Receiver<TopicNotification>,
    ) -> Self {
        Self {
            gossip_engine,
            peer_mapper,
            gossip_to_session_manager_tx,
            session_manager_to_gossip_rx,
            gossip_handler_message_receiver,
        }
    }
}
impl<B:BlockT> TssMessageHandler for GossipHandler<B> {
    fn broadcast_message(&mut self, message: TssMessage) -> Result<(), String> {
        let topic = <<B::Header as HeaderT>::Hashing as HashT>::hash("tss_topic".as_bytes());
        Ok(self
            .gossip_engine
            .gossip_message(topic, message.encode(), false))
    }

    fn send_message(&mut self, message: TssMessage, peer_id: PeerId) -> Result<(), String> {
        log::info!("[TSS] Sending Direct Message {:?}", message.encode());
        Ok(self
            .gossip_engine
            .send_message(vec![peer_id], message.encode()))
    }

    fn handle_announcment(&mut self, _peer_id: PeerId, data: TssMessage) {
        if let TssMessage::Announce(_nonce, peer_id, public_key_data, signature) = data {
            info!(
                "[TSS] Handling peer_id {:?} with pubkey {:?}",
                peer_id, public_key_data
            );
            let public_key = &sr25519::Public::from_slice(&&public_key_data[..]).unwrap();
            if sr25519_verify(
                &signature[..].try_into().unwrap(),
                &[&public_key_data[..], &peer_id[..]].concat(),
                public_key,
            ) {
                self.peer_mapper
                    .lock()
                    .unwrap()
                    .add_peer(PeerId::from_bytes(&peer_id[..]).unwrap(), public_key_data);
                // info!(
                //     "[TSS] Handling peer_id {:?} with pubkey {:?} SIGN CHECK OK",
                //     peer_id, public_key_data
                // );
            } else {
                // info!(
                //     "[TSS] Handling peer_id {:?} with pubkey {:?} SIGN CHECK KO",
                //     peer_id, public_key_data
                // );
            }
        }
    }
    fn forward_to_session_manager(&self, sender: PeerId, message: TssMessage) -> Result<(), TrySendError<(PeerId, TssMessage)>> {
        self.gossip_to_session_manager_tx.unbounded_send((sender, message))
    }
}

// Define a trait for routing ECDSA messages
trait ECDSAMessageRouter {
    fn route_ecdsa_message(
        &mut self,
        session_id: SessionId,
        index: String,
        bytes: Vec<u8>,
        phase: ECDSAPhase,
        recipient: Option<PeerId>
    ) -> Result<(), String>;
}

impl<T: TssMessageHandler> ECDSAMessageRouter for T {
    fn route_ecdsa_message(
        &mut self,
        session_id: SessionId,
        index: String,
        bytes: Vec<u8>,
        phase: ECDSAPhase,
        recipient: Option<PeerId>
    ) -> Result<(), String> {
        let message = match phase {
            ECDSAPhase::Key => TssMessage::ECDSAMessageKeygen(session_id, index, bytes),
            ECDSAPhase::Reshare => TssMessage::ECDSAMessageReshare(session_id, index, bytes),
            ECDSAPhase::Sign => TssMessage::ECDSAMessageSign(session_id, index, bytes),
            ECDSAPhase::SignOnline => TssMessage::ECDSAMessageSignOnline(session_id, index, bytes),
        };

        match recipient {
            Some(peer) => {
                log::debug!(
                    "[TSS] Sending message to peer_id {:?} for session_id {:?}, phase is {:?}",
                    peer,
                    session_id,
                    phase
                );
                self.send_message(message, peer)
            },
            None => {
                log::debug!(
                    "[TSS] Sending message to all peers for session_id {:?} with phase {:?}",
                    session_id,
                    phase
                );
                self.broadcast_message(message)
            }
        }.map_err(|error| {
            log::error!(
                "[TSS] Error sending ECDSA message for session_id {:?}, phase {:?} with error {:?}",
                session_id,
                phase,
                error
            );
            error
        })
    }
}

// Helper method to process gossip engine notifications
fn process_gossip_notification<T: TssMessageHandler>(
    handler: &mut T, 
    notification: TopicNotification
) -> Option<()> {
    let sender = notification.sender?;
    
    let message = match TssMessage::decode(&mut &notification.message[..]) {
        Ok(msg) => msg,
        Err(_) => {
            log::warn!("[TSS] Failed to decode message from {:?}", sender);
            return Some(());
        }
    };
    
    match message {
        TssMessage::Announce(_, _, _, _) => {
            handler.handle_announcment(sender, message);
        }
        _ => {
            if let Err(e) = handler.forward_to_session_manager(sender, message) {
                log::error!("[TSS] Failed to forward message to session manager: {:?}", e);
            }
        }
    }
    
    Some(())
}

// Helper method to process session manager messages
fn process_session_manager_message<T: TssMessageHandler + ECDSAMessageRouter>(
    handler: &mut T,
    msg: (PeerId, TssMessage)
) -> Result<(), String> {
    let (recipient, message) = msg;
    
    match message {
        TssMessage::DKGRound1(id, bytes) => {
            handler.broadcast_message(TssMessage::DKGRound1(id, bytes))
                .map_err(|e| {
                    log::error!("[TSS] Error broadcasting TssMessage::DKGRound1 for session_id {:?} with error {:?}", id, e);
                    e
                })
        }
        
        TssMessage::DKGRound2(id, bytes, recipient_bytes) => {
            match PeerId::from_bytes(&recipient_bytes[..]) {
                Ok(peer_id) => {
                    handler.send_message(TssMessage::DKGRound2(id, bytes, recipient_bytes.clone()), peer_id)
                        .map_err(|e| {
                            log::error!("[TSS] Error sending TssMessage::DKGRound2 for session_id {:?}, peer_id {:?} with error {:?}", 
                                id, recipient_bytes, e);
                            e
                        })
                }
                Err(e) => {
                    log::error!("[TSS] Invalid peer ID in DKGRound2 message: {:?}", e);
                    Err("Invalit Peer Id".to_string())
                }
            }
        }
        
        TssMessage::SigningPackage(id, bytes) => {
            handler.send_message(TssMessage::SigningPackage(id, bytes), recipient)
                .map_err(|e| {
                    log::error!("[TSS] Error sending TssMessage::SigningPackage for session_id {:?}, peer_id {:?} with error {:?}", 
                        id, recipient, e);
                    e
                })
        }
        
        TssMessage::SigningCommitment(id, bytes) => {
            handler.send_message(TssMessage::SigningCommitment(id, bytes), recipient)
                .map_err(|e| {
                    log::error!("[TSS] Error sending TssMessage::SigningCommitment for session_id {:?}, peer_id {:?} with error {:?}", 
                        id, recipient, e);
                    e
                })
        }
        
        TssMessage::SigningShare(id, bytes) => {
            handler.send_message(TssMessage::SigningShare(id, bytes), recipient)
                .map_err(|e| {
                    log::error!("[TSS] Error sending TssMessage::SigningShare for session_id {:?}, peer_id {:?} with error {:?}", 
                        id, recipient, e);
                    e
                })
        }
        
        TssMessage::ECDSAMessageBroadcast(session_id, index, bytes, phase) |
        TssMessage::ECDSAMessageSubset(session_id, index, bytes, phase) => {
            handler.route_ecdsa_message(session_id, index, bytes, phase, None)
        }
        
        TssMessage::ECDSAMessageP2p(session_id, index, _peer_id, bytes, phase) => {
            handler.route_ecdsa_message(session_id, index, bytes, phase, Some(recipient))
        }
        
        _ => Ok(())
    }
}


impl<B: BlockT> Future for GossipHandler<B> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Poll the gossip engine
        while let Poll::Ready(e) = Pin::new(&mut self.gossip_engine).poll(cx) {
            e // Process the result if needed
        }

        // Process gossip notifications
        while let Poll::Ready(Some(notification)) = self.gossip_handler_message_receiver.poll_next_unpin(cx) {
            if notification.sender.is_none() {
                log::info!("[TSS] Received notification without sender: {:?}", notification.message);
                continue;
            }

            // Correct and concise solution: Use get_mut()
            process_gossip_notification(self.as_mut().get_mut(), notification);
        }

        // Process session manager messages
        while let Poll::Ready(Some(msg)) = self.session_manager_to_gossip_rx.poll_next_unpin(cx) {
            if let Err(e) = process_session_manager_message(&mut *self, msg) {  // &mut *self is CORRECT here
                log::warn!("[TSS] Error processing session manager message: {:?}", e);
            }
        }

        // Check if any channel has closed
        if self.gossip_handler_message_receiver.is_terminated() ||
            self.session_manager_to_gossip_rx.is_terminated() {
            return Poll::Ready(());
        }

        Poll::Pending
    }
}

// impl<B: BlockT> Future for GossipHandler<B> {
   // type Output = ();

    // fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    //     loop {
    //         match Pin::new(&mut self.gossip_engine).poll(cx) {
    //             Poll::Ready(e) => e,
    //             Poll::Pending => break,
    //         }
    //     }

    //     loop {
    //         match self.gossip_handler_message_receiver.poll_next_unpin(cx) {
    //             Poll::Ready(Some(notification)) => {
    //                 if let Some(sender) = notification.sender {
    //                     if let Ok(message) = TssMessage::decode(&mut &notification.message[..]) {
    //                         match message {
    //                             TssMessage::Announce(_, _, _, _) => {
    //                                 self.handle_announcment(sender, message);
    //                             }
    //                             _ => {
    //                                 let _ = self
    //                                     .gossip_to_session_manager_tx
    //                                     .unbounded_send((sender, message));
    //                             }
    //                         }
    //                     }
    //                 } else {
    //                     log::info!("[TSS] This is weird {:?}", notification.message);
    //                 }
    //             }
    //             Poll::Ready(None) => return Poll::Ready(()),
    //             Poll::Pending => break,
    //         }
    //     }

    //     loop {
    //         match self.session_manager_to_gossip_rx.poll_next_unpin(cx) {
    //             Poll::Ready(Some((recipient, message))) => match message {
    //                 TssMessage::DKGRound1(id, bytes) => {
    //                     if let Err(e) = self.broadcast_message(TssMessage::DKGRound1(id, bytes)) {
    //                         log::error!("[TSS] Error broadcasting TssMessage::DKGRound1 for session_id {:?} with error {:?}", id, e);
    //                     }
    //                 }
    //                 TssMessage::DKGRound2(id, bytes, recipient) => {
    //                     if let Err(e) = self.send_message(
    //                         TssMessage::DKGRound2(id, bytes, recipient.clone()),
    //                         PeerId::from_bytes(&recipient[..]).unwrap(),
    //                     ) {
    //                         log::error!("[TSS] Error sending TssMessage::DKGRound2 for session_id {:?}, peer_id {:?} with error {:?}", id, recipient, e);
    //                     }
    //                 }

    //                 TssMessage::SigningPackage(id, bytes) => {
    //                     if let Err(e) =
    //                         self.send_message(TssMessage::SigningPackage(id, bytes), recipient)
    //                     {
    //                         log::error!("[TSS] Error sending TssMessage::SigningPackage for session_id {:?}, peer_id {:?} with error {:?}", id, recipient, e);
    //                     }
    //                 }
    //                 TssMessage::SigningCommitment(id, bytes) => {
    //                     if let Err(e) =
    //                         self.send_message(TssMessage::SigningCommitment(id, bytes), recipient)
    //                     {
    //                         log::error!("[TSS] Error sending TssMessage::SigningCommitment for session_id {:?}, peer_id {:?} with error {:?}", id, recipient, e);
    //                     }
    //                 }
    //                 TssMessage::SigningShare(id, bytes) => {
    //                     if let Err(e) =
    //                         self.send_message(TssMessage::SigningShare(id, bytes), recipient)
    //                     {
    //                         log::error!("[TSS] Error sending TssMessage::SigningShare for session_id {:?}, peer_id {:?} with error {:?}", id, recipient, e);
    //                     }
    //                 }

    //                 TssMessage::ECDSAMessageBroadcast(session_id, index, bytes, phase)
    //                 | TssMessage::ECDSAMessageSubset(session_id, index, bytes, phase) => {
    //                     log::debug!(
    //                         "[TSS] Sending message to all peers for session_id {:?} with phase {:?}",
    //                         session_id,
    //                         phase
    //                     );

    //                     match phase {
    //                         ECDSAPhase::Key => match self.broadcast_message(TssMessage::ECDSAMessageKeygen(
    //                             session_id, index, bytes,
    //                         )) {
    //                             Err(error) => log::error!("[TSS] Error broadcasting TssMessage::ECDSAMessageKeygen for session_id {:?} with error {:?}", session_id, error),
    //                             _ => ()
    //                         },
    //                         ECDSAPhase::Sign => match self.broadcast_message(TssMessage::ECDSAMessageSign(
    //                             session_id, index, bytes,
    //                         )) {
    //                             Err(error) => log::error!("[TSS] Error broadcasting TssMessage::ECDSAMessageSign for session_id {:?} with error {:?}", session_id, error),
    //                             _ => ()
    //                         },
    //                         ECDSAPhase::SignOnline => match self.broadcast_message(TssMessage::ECDSAMessageSignOnline(
    //                             session_id, index, bytes,
    //                         )) {
    //                             Err(error) => log::error!("[TSS] Error broadcasting TssMessage::ECDSAMessageSignOnline for session_id {:?} with error {:?}", session_id, error),
    //                             _ => ()
    //                         },
    //                     }
    //                 }
    //                 TssMessage::ECDSAMessageP2p(session_id, index, _peer_id, bytes, phase) => {
    //                     log::debug!(
    //                         "[TSS] Sending message to peer_id {:?} for session_id {:?}, phase is {:?}",
    //                         recipient,
    //                         session_id,
    //                         phase
    //                     );

    //                     match phase {
    //                         ECDSAPhase::Key => match self.send_message(
    //                             TssMessage::ECDSAMessageKeygen(session_id, index, bytes),
    //                             recipient,
    //                         ) {
    //                             Err(error) => log::error!("[TSS] Error sending message to TssMessage::ECDSAMessageKeygen for session_id {:?} with error {:?}", session_id, error),
    //                             _ => ()
    //                         },
    //                         ECDSAPhase::Sign => match self.send_message(
    //                             TssMessage::ECDSAMessageSign(session_id, index, bytes),
    //                             recipient,
    //                         ) {
    //                             Err(error) => log::error!("[TSS] Error sending message to TssMessage::ECDSAMessageSign for session_id {:?} with error {:?}", session_id, error),
    //                             _ => ()
    //                         },
    //                         ECDSAPhase::SignOnline => match self.send_message(
    //                             TssMessage::ECDSAMessageSignOnline(session_id, index, bytes),
    //                             recipient,
    //                         ) {
    //                             Err(error) => log::error!("[TSS] Error sending message to TssMessage::ECDSAMessageSignOnline for session_id {:?} with error {:?}", session_id, error),
    //                             _ => ()
    //                         },
    //                     }
    //                 }
    //                 _ => (),
    //             },
    //             Poll::Ready(None) => return Poll::Ready(()),
    //             Poll::Pending => break,
    //         }
    //     }

    //     Poll::Pending
    // }
    // Main poll method
// }


// ===== Client Manager =====

struct ClientWrapper<B: BlockT, C: BlockchainEvents<B> + ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static, TP> where 
TP: TransactionPool + LocalTransactionPool<Block = B> + Send + Sync + 'static,
{
    client: Arc<C>,
    phantom: PhantomData<B>,
    keystore: KeystorePtr,
    transaction_pool: Arc<TP>,
}   
impl <B: BlockT, C: BlockchainEvents<B> + ProvideRuntimeApi<B, Api=T> + HeaderBackend<B> + Send + Sync + 'static, T:TssApi<B>, TP> ClientWrapper<B, C, TP> where 
TP: TransactionPool + LocalTransactionPool<Block = B> + Send + Sync + 'static
 {
    fn new(client: Arc<C>, keystore: KeystorePtr, transaction_pool: Arc<TP> ) -> Self {
        Self {
            client,
            phantom: Default::default(),
            keystore,
            transaction_pool
        }
    }
}

trait ClientManager<B: BlockT> {
    fn best_hash(&self) -> <<B as BlockT>::Header as HeaderT>::Hash;
    fn report_participants(
        &self,
        hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        inactive_participants: Vec<[u8; 32]>,
    ) -> Result<(), String>;
    fn submit_dkg_result(
        &self,
        hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        aggregated_key: Vec<u8>,
    ) -> Result<(), String>;
}

impl<B: BlockT, C, TP> ClientManager<B> for ClientWrapper<B, C, TP>
where
    C: BlockchainEvents<B> + ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    C::Api: uomi_runtime::pallet_tss::TssApi<B>,
    TP: TransactionPool + LocalTransactionPool<Block = B> + Send + Sync + 'static,
{
    fn best_hash(&self) -> <<B as BlockT>::Header as HeaderT>::Hash {
        self.client.info().best_hash
    }

    fn report_participants(
        &self,
        hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        inactive_participants: Vec<[u8; 32]>,
    ) -> Result<(), String> {

        let mut runtime = self.client.runtime_api();
        runtime.register_extension(KeystoreExt(self.keystore.clone()));
    
        let otpf = OffchainTransactionPoolFactory::new(self.transaction_pool.clone());
        runtime.register_extension(otpf.offchain_transaction_pool(self.client.info().best_hash));

        runtime
            .report_participants(hash, session_id, inactive_participants)
            .map_err(|e| format!("Failed to report participants: {:?}", e))
    }

    fn submit_dkg_result(
            &self,
            hash: <<B as BlockT>::Header as HeaderT>::Hash,
            session_id: SessionId,
            aggregated_key: Vec<u8>,
        ) -> Result<(), String> {
            let mut runtime = self.client.runtime_api();
            runtime.register_extension(KeystoreExt(self.keystore.clone()));
        
            let otpf = OffchainTransactionPoolFactory::new(self.transaction_pool.clone());
            runtime.register_extension(otpf.offchain_transaction_pool(self.client.info().best_hash));
    
            runtime
                .submit_dkg_result(hash, session_id, aggregated_key)
                .map_err(|e| format!("Failed to submit DKG result: {:?}", e))
    }
}


// ===== Main Setup Function =====

pub fn setup_gossip<C, N, B, S, TP, RE>(
    client: Arc<C>,
    network: N,
    sync: S,
    notification_service: Box<dyn NotificationService>,
    protocol_name: ProtocolName,
    keystore_container: KeystoreContainer,
    transaction_pool: Arc<TP>,
    registry: Option<Registry>,
    _: PhantomData<B>,
    __: PhantomData<RE>,
) -> Result<Pin<Box<dyn Future<Output = ()> + Send>>, Error>
where
    B: BlockT,
    C: BlockchainEvents<B> + ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    C::Api: uomi_runtime::pallet_tss::TssApi<B>,
    N: Network<B> + Clone + Send + Sync + 'static + NetworkStateInfo + NetworkSigner,
    S: Syncing<B> + Clone + Send + 'static,
    TP: TransactionPool + LocalTransactionPool<Block = B> + Send + Sync + 'static,
    RE: EncodeLike + Eq + Debug + Parameter + Sync + Send + Member,
{
    let mut rng = rand::thread_rng();


    let setup_gossip_pin = move || {
        // Create Arc clone of client that will be moved into the future
        let client = Arc::clone(&client);
        
        // Wait until the key is available. This might not be right away, so check every 30s
        while get_validator_key_from_keystore(&keystore_container).is_none() {
            log::warn!("[TSS] No validator key found in keystore. Waiting for key");
            sleep(Duration::from_secs(30));
        }
    

        // As soon as the key is ready we can break the loop and we can start the actual thing

        let validator_key = get_validator_key_from_keystore(&keystore_container);
    
        let validator_key = validator_key.unwrap().0.to_vec();
        let validator_key_clone = validator_key.clone();
        let local_peer_id = network.local_peer_id();

        info!(
            "[TSS] My Validator key is {:}",
            AccountId::from_slice(&validator_key_clone)
                .unwrap()
                .to_ss58check_with_version(Ss58AddressFormat::custom(87))
        );
        
        // Create announcement message
        let announcement = if let Some(signature) = sign_announcment(
            &keystore_container,
            &validator_key[..],
            &local_peer_id.to_bytes()[..],
        ) {
            let announcement = TssMessage::Announce(
                rng.gen::<u16>(),
                local_peer_id.to_bytes(),
                validator_key.clone(),
                signature,
            );
            Some(announcement)
        } else {
            log::warn!("[TSS] Failed to sign announcement message");
            None
        };

        let gossip_validator = Arc::new(TssValidator::new(Duration::from_secs(120), announcement.clone()));

        // Set up communication channels
        let (gossip_to_session_manager_tx, gossip_to_session_manager_rx) =
            sc_utils::mpsc::tracing_unbounded::<(PeerId, TssMessage)>(
                "gossip_to_session_manager",
                1024,
            );
        let (session_manager_to_gossip_tx, session_manager_to_gossip_rx) =
            sc_utils::mpsc::tracing_unbounded::<(PeerId, TssMessage)>(
                "session_manager_to_gossip",
                1024,
            );
        let (runtime_to_session_manager_tx, runtime_to_session_manager_rx) =
            sc_utils::mpsc::tracing_unbounded::<TSSRuntimeEvent>("runtime_to_session_manager", 1024);

        // Create shared state
        let sessions_participants = Arc::new(Mutex::new(HashMap::<
            SessionId,
            HashMap<Identifier, TSSPublic>,
        >::new()));
        let sessions_data = Arc::new(Mutex::new(HashMap::<SessionId, SessionData>::new()));
        let dkg_session_states = Arc::new(Mutex::new(HashMap::<SessionId, DKGSessionState>::new()));
        let signing_session_states =
            Arc::new(Mutex::new(HashMap::<SessionId, SigningSessionState>::new()));
        let storage = Arc::new(Mutex::new(MemoryStorage::new()));
        let key_storage = Arc::new(Mutex::new(FileStorage::new()));

        // Try to load from file if it exists
        let mut storage_lock = storage.lock().unwrap();
        storage_lock.load_from_file();
        drop(storage_lock);

        // Set up peer mapping
        let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants.clone())));
        {
            let mut handle = peer_mapper.lock().unwrap();
            handle.add_peer(local_peer_id.clone(), validator_key.clone());
        }

        log::info!(
            "[TSS] Local peer ID: {:?}",
            local_peer_id.to_base58()
        ); 

        // ===== GossipHandler Setup =====
        let mut gossip_engine = GossipEngine::new(
            network.clone(),
            sync,
            notification_service,
            protocol_name.clone(),
            gossip_validator,
            registry.as_ref(),
        );

        let topic = <<B::Header as HeaderT>::Hashing as HashT>::hash("tss_topic".as_bytes());
        let gossip_handler_message_receiver: Receiver<TopicNotification> =
            gossip_engine.messages_for(topic);

        let mut gossip_handler = GossipHandler::new(
            gossip_engine,
            gossip_to_session_manager_tx,
            session_manager_to_gossip_rx,
            peer_mapper.clone(),
            gossip_handler_message_receiver,
        );

        // Broadcast initial announcement if available
        if let Some(a) = announcement {
            if let Err(e) = gossip_handler.broadcast_message(a) {
                log::error!("[TSS] Failed to broadcast announcement: {:?}", e);
            } else {
                log::info!("[TSS] Announcement broadcasted successfully");
            }
        }
        
        // ===== RuntimeEventHandler Setup =====
        let runtime_event_handler =
            RuntimeEventHandler::<B, C>::new(client.clone(), runtime_to_session_manager_tx);

        // ===== SessionManager Setup =====
        let mut session_manager = SessionManager::<B, _>::new(
            storage.clone(),
            key_storage.clone(),
            sessions_participants.clone(),
            sessions_data.clone(),
            dkg_session_states.clone(),
            signing_session_states.clone(),
            validator_key.clone(),
            peer_mapper.clone(),
            gossip_to_session_manager_rx,
            runtime_to_session_manager_rx,
            session_manager_to_gossip_tx,
            local_peer_id.to_bytes(),
            ClientWrapper::new(Arc::clone(&client), keystore_container.keystore().clone(), transaction_pool.clone()),
        );
        
        // Configure session timeout (default is 1 hour, make it 2 hours for production)
        session_manager.session_timeout = 15; // 2 hours in seconds

        // ===== Start the components =====
        let runtime_event_handler_future = runtime_event_handler.run();
        let session_manager_future = session_manager.run();

        let combined_future = futures::future::join3(
            runtime_event_handler_future,
            session_manager_future,
            gossip_handler,
        )
        .map(|_| ());

        combined_future
    };
    Ok(Box::pin(setup_gossip_pin()))
}

pub fn get_active_validators() {}

pub fn get_validator_key_from_keystore(keystore: &KeystoreContainer) -> Option<sp_core::sr25519::Public>{
    keystore
        .keystore()
        .sr25519_public_keys(UOMI)
        .first()
        .cloned()
}

pub fn sign_announcment(
    keystore_container: &KeystoreContainer,
    validator_key: &[u8],
    peer_id: &[u8],
) -> Option<Vec<u8>> {
    let result = keystore_container.keystore().sign_with(
        UOMI,
        sr25519::CRYPTO_ID,
        validator_key,
        &[validator_key, peer_id].concat(),
    );
    match result {
        Ok(signature) => match signature {
            Some(signature) => Some(signature),
            None => {
                log::error!("[TSS] There was an error signing: None");
                None
            }
        },
        Err(err) => {
            log::error!("[TSS] There was an error signing {:?}", err);
            None
        }
    }
}

pub fn get_config() -> (
    NonDefaultSetConfig,
    Box<dyn NotificationService>,
    ProtocolName,
) {
    let protocol: ProtocolName = TSS_PROTOCOL.into();
    let (config, notification_service) = config::NonDefaultSetConfig::new(
        protocol.clone(),
        Vec::new(),
        1024 * 1024,
        None,
        SetConfig {
            in_peers: 5000,
            out_peers: 5000,
            ..Default::default()
        },
    );

    (config, notification_service, protocol)
}

// Helper function to avoid creating a new empty HashMap every time.
fn empty_hash_map<K, V>() -> HashMap<K, V> {
    HashMap::new()
}
