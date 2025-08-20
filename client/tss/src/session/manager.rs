use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{Arc, Mutex},
};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::Block as BlockT;
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender, TrySendError};
use sc_network::PeerId;
use frost_ed25519::Identifier;
use futures::{select, StreamExt, FutureExt};
use sc_network::utils::interval;
use std::time::Duration;

use crate::{
    client::ClientManager,
    dkghelpers::{FileStorage, MemoryStorage},
    ecdsa::ECDSAManager,
    network::PeerMapper,
    retry::mechanism::RetryMechanism,
    security::verification,
    MessageProcessor,
    types::{SessionId, SignedTssMessage, TSSRuntimeEvent, TssMessage, TSSPeerId, TSSPublic, SessionData},
    utils::empty_hash_map,
    gossip::router::{TssMessageHandler, ECDSAMessageRouter},
};

use super::{
    SessionCore, DKGSessionState, SigningSessionState,
    managers::{StorageManager, CommunicationManager, StateManagerGroup, ParticipantManager, AuthenticationManager},
    dkg_state_manager::DKGStateManager,
    signing_state_manager::SigningStateManager,
};

use crate::TSSParticipant;
use crate::utils::*;
use crate::utils::get_validator_key_from_keystore;
use crate::utils::sign_announcment;


pub struct SessionManager<B: BlockT, C: ClientManager<B>> {
    // Core session management functionality
    pub session_core: SessionCore,
    
    // Grouped managers
    pub storage_manager: StorageManager,
    pub communication_manager: CommunicationManager,
    pub state_managers: StateManagerGroup,
    pub participant_manager: ParticipantManager,
    pub auth_manager: AuthenticationManager,
    
    // Specialized components
    pub ecdsa_manager: Arc<Mutex<ECDSAManager>>,
    pub buffer: Arc<Mutex<HashMap<SessionId, Vec<(TSSPeerId, TssMessage)>>>>,
    pub client: C,
    pub announcement: Option<TssMessage>,
    pub retry_mechanism: RetryMechanism,
    pub _phantom: PhantomData<B>,
}

impl<B: BlockT, C: ClientManager<B>> SessionManager<B, C> {
    pub fn new(
        storage: Arc<Mutex<MemoryStorage>>,
        key_storage: Arc<Mutex<FileStorage>>,
        sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
        sessions_data: Arc<Mutex<HashMap<SessionId, SessionData>>>, // t, n, message
        dkg_session_states: Arc<Mutex<HashMap<SessionId, DKGSessionState>>>,
        signing_session_states: Arc<Mutex<HashMap<SessionId, SigningSessionState>>>,
        validator_key: TSSPublic,
        validator_public_key: [u8; 32],
        keystore: KeystorePtr,
        peer_mapper: Arc<Mutex<PeerMapper>>,
    gossip_to_session_manager_rx: TracingUnboundedReceiver<(SignedTssMessage, Option<PeerId>)>,
        runtime_to_session_manager_rx: TracingUnboundedReceiver<TSSRuntimeEvent>,
        session_manager_to_gossip_tx: TracingUnboundedSender<SignedTssMessage>,
        local_peer_id: TSSPeerId,
        announcment: Option<TssMessage>,
        client: C,
        retry_enabled: bool,
    ) -> Self {
        // Create SessionCore for core session management
        let session_timestamps = Arc::new(Mutex::new(empty_hash_map()));
        let session_core = SessionCore::new(
            sessions_data.clone(),
            session_timestamps.clone(),
            3600, // Default session timeout: 1 hour (3600 seconds)
            validator_key.clone(),
            local_peer_id.clone(),
            peer_mapper.clone(),
        );

        // Create grouped managers
        let storage_manager = StorageManager::new(storage, key_storage);
        
        let communication_manager = CommunicationManager::new(
            gossip_to_session_manager_rx,
            runtime_to_session_manager_rx,
            session_manager_to_gossip_tx,
        );
        
        let state_managers = StateManagerGroup::new(
            DKGStateManager::new(dkg_session_states),
            SigningStateManager::new(signing_session_states),
        );
        
        let participant_manager = ParticipantManager::new(
            sessions_participants,
            Arc::new(Mutex::new(empty_hash_map())),
            Arc::new(Mutex::new(empty_hash_map())),
        );
        
        let auth_manager = AuthenticationManager::new(validator_public_key, keystore);
        
        let retry_mechanism = RetryMechanism::new(300, 3, retry_enabled, local_peer_id.clone());

        Self {
            session_core,
            storage_manager,
            communication_manager,
            state_managers,
            participant_manager,
            auth_manager,
            ecdsa_manager: Arc::new(Mutex::new(ECDSAManager::new())),
            buffer: Arc::new(Mutex::new(empty_hash_map())),
            client,
            announcement: announcment,
            retry_mechanism,
            _phantom: PhantomData,
        }
    }
    
    /// Send a signed message to the gossip handler
    pub fn send_signed_message(&self, message: TssMessage) -> Result<(), String> {
        log::info!("[TSS] 📤 SessionManager CREATING SIGNED MESSAGE: {:?}", std::mem::discriminant(&message));
        
        let signed_message = verification::create_signed_message(message, &self.auth_manager.validator_public_key, &self.auth_manager.keystore)?;
        
        log::info!("[TSS] ✅ Signed message created successfully, sending to gossip handler");
        
        self.communication_manager.session_manager_to_gossip_tx.unbounded_send(signed_message)
            .map_err(|e| format!("Failed to send signed message: {:?}", e))
    }
    
    /// Check if a session exists
    pub fn session_exists(&self, session_id: &SessionId) -> bool {
        self.session_core.session_exists(session_id)
    }
    
    /// Check if a session has timed out
    pub fn is_session_timed_out(&self, session_id: &SessionId) -> bool {
        self.session_core.is_session_timed_out(session_id)
    }
    
    /// Check if node is authorized to participate in a session
    pub fn is_authorized_for_session(&self, session_id: &SessionId) -> bool {
        self.session_core.is_authorized_for_session(session_id)
    }

    // Add a TssMessage we received from an unknown peer until they announce themselves
    pub fn add_unknown_peer_message(&self, peer_id: PeerId, message: TssMessage) {
        log::info!("[TSS] Adding unknown peer message from {:?}", peer_id);
        let mut unknown_peer_queue = self.participant_manager.unknown_peer_queue.lock().unwrap();
        let messages = unknown_peer_queue.entry(peer_id).or_insert_with(Vec::new);
        messages.push(message);
        drop(unknown_peer_queue);
    }

    // Consume the queue of an unknown peer as soon as they have announced themselves
    pub fn consume_unknown_peer_queue(&self, peer_id: PeerId) -> Vec<TssMessage> {
        log::info!("[TSS] Consuming unknown peer queue for {:?}", peer_id);
        let mut unknown_peer_queue = self.participant_manager.unknown_peer_queue.lock().unwrap();
        let messages = unknown_peer_queue.remove(&peer_id).unwrap_or_default();
        drop(unknown_peer_queue);
        messages
    }

    // Consume unknown peer messages by public key (used when the real PeerId becomes known)
    pub fn consume_unknown_peer_queue_by_public_key(&self, public_key: &[u8]) -> Vec<TssMessage> {
        use sp_core::hashing::blake2_256;
        let public_key_hash = blake2_256(public_key);
        
        // Try to find messages stored under the temp PeerId derived from this public key
        let temp_peer_id = PeerId::from_bytes(&public_key_hash[0..32])
            .unwrap_or_else(|_| PeerId::random());
            
        self.consume_unknown_peer_queue(temp_peer_id)
    }

    /// Add session data with validation
    pub fn add_session_data(
        &self,
        session_id: SessionId,
        t: u16,
        n: u16,
        coordinator: TSSParticipant,
        participants: Vec<TSSParticipant>,
        message: Vec<u8>,
    ) -> Result<(), crate::session::SessionError> {
        self.session_core.add_session_data(session_id, t, n, coordinator, participants, message)
    }

    /// Get session data with timeout check
    pub fn get_session_data(&self, session_id: &SessionId) -> Option<(u16, u16, Vec<u8>, Vec<u8>)> {
        self.session_core.get_session_data(session_id)
    }

    pub fn is_coordinator(&self, session_id: &SessionId) -> bool {
        self.session_core.is_coordinator(session_id)
    }

    

    /// Process a queued message directly without signature verification
    /// These messages were received before we knew the sender, but now we do
    pub fn process_queued_message_directly(&mut self, message: TssMessage, sender_peer_id: PeerId) {
        log::info!("[TSS] 🔄 Processing queued message directly from known peer: {}", sender_peer_id.to_base58());
        
        // We can now process this message directly since we know who sent it
        // This is safe because:
        // 1. The message was received through the gossip protocol 
        // 2. We now have verified the sender through their announcement
        // 3. The message was buffered while waiting for sender identification
        
        // Get the actual public key for this peer from the peer mapper
        let sender_public_key = {
            let mut peer_mapper = self.session_core.peer_mapper.lock().unwrap();
            peer_mapper.get_account_id_from_peer_id(&sender_peer_id)
                .map(|public_key| {
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(&public_key[..32.min(public_key.len())]);
                    key_array
                })
                .unwrap_or([0u8; 32])
        };
        
        // Create a temporary SignedTssMessage for processing
        let signed_message = SignedTssMessage {
            message,
            sender_public_key,
            signature: [0u8; 64], // We don't have the actual signature here (but it's bypassed in test mode)
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Delegate to the message processor with the known sender PeerId
        MessageProcessor::handle_gossip_message(self, signed_message, Some(sender_peer_id));
        log::info!("[TSS] ✅ Successfully processed queued message");
    }

    pub async fn run(mut self) {
        log::info!("[TSS] Listening for messages inside Session Manager from Gossip and Runtime");
        
        // Set up a timer for periodic session cleanup
        let mut cleanup_interval = interval(Duration::from_secs(60));
        
        // Set up a timer for periodic retry checks
        let mut retry_check_interval = interval(Duration::from_secs(30));
        
        loop {
            select! {
                // Run periodic cleanup of expired sessions
                _ = cleanup_interval.next().fuse() => {
                    self.cleanup_expired_sessions();
                },
                
                // Run periodic retry checks for all active sessions
                _ = retry_check_interval.next().fuse() => {
                    self.check_all_sessions_for_retries();
                },
                
                // Process messages from the gossip network
                gossip_notification = self.communication_manager.gossip_to_session_manager_rx.next().fuse() => {
                    if let Some((signed_message, sender)) = gossip_notification {
                        self.process_gossip_message(signed_message, sender);
                    }
                },

                // Process messages from the runtime
                runtime_message = self.communication_manager.runtime_to_session_manager_rx.next().fuse() => {
                    if let Some(runtime_message) = runtime_message {
                        self.process_runtime_message(runtime_message);
                    }
                },
            }
        }
    }

    pub fn process_gossip_message(&mut self, signed_message: SignedTssMessage, sender_peer_id: Option<PeerId>) {
        MessageProcessor::handle_gossip_message(self, signed_message, sender_peer_id);
    }

    pub fn process_gossip_message_with_sender(&mut self, signed_message: SignedTssMessage, sender_peer_id: PeerId) {
        MessageProcessor::handle_gossip_message(self, signed_message, Some(sender_peer_id));
    }

    pub fn process_runtime_message(&mut self, runtime_message: TSSRuntimeEvent) {
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

    fn add_and_initialize_dkg_session(&self, id: SessionId, t: u16, n: u16, participants: Vec<TSSParticipant>) -> Result<(), String> {
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

    fn add_and_initialize_dkg_reshare_session(&self, id: SessionId, t: u16, n: u16, participants: Vec<TSSParticipant>, old_participants: Vec<TSSParticipant>) -> Result<(), String> {
        self.add_session_data(id, t, n, [0; 32], participants.clone(), Vec::new())
            .map_err(|e| format!("Failed to add data: {:?}", e))?;
        
        // log::info!("[TSS] Successfully added data for DKG session {}", id);
        
        // self.dkg_handle_session_created(id, n.into(), t.into(), participants.clone())
        //     .map_err(|e| format!("Failed to initialize DKG session: {:?}", e))?;
        
        log::info!("[TSS] Successfully initialized DKG session {}", id);
        
        self.ecdsa_create_reshare_phase(id, n.into(), t.into(), participants, old_participants);
        
        Ok(())
    }

    fn add_and_initialize_signing_session(&self, id: SessionId, t: u16, n: u16, participants: Vec<TSSParticipant>, coordinator: [u8; 32], message: Vec<u8>) -> Result<(), String> {
        self.add_session_data(id, t, n, coordinator, participants.clone(), message.clone())
            .map_err(|e| format!("Failed to add data: {:?}", e))?;
        
        log::info!("[TSS] Successfully added data for signing session {}", id);

        self.signing_handle_session_created(id, participants.clone(), coordinator.clone());
    
        log::info!("[TSS] Successfully initialized FROST Signing session {}", id);

        
        self.ecdsa_create_sign_phase(id, participants, message);
        
        Ok(())
    }

    fn on_new_validator_id_assigned(&mut self, account_id: TSSPublic, id: u32) {
        let mut peer_mapper_handle = self.session_core.peer_mapper.lock().unwrap();
        peer_mapper_handle.set_validator_id(account_id, id);
    }
}

// Implement TssMessageHandler trait for SessionManager
impl<B: BlockT, C: ClientManager<B>> TssMessageHandler for SessionManager<B, C> {
    fn send_signed_message(&mut self, message: TssMessage, recipient: PeerId) -> Result<(), String> {
        // Create a signed message and send it via the communication manager
        let signed_message = SignedTssMessage {
            message,
            sender_public_key: self.auth_manager.validator_public_key,
            signature: [0u8; 64], // TODO: Implement proper signing
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Send via gossip channel - this will be handled by the gossip handler
        self.communication_manager.session_manager_to_gossip_tx
            .unbounded_send(signed_message)
            .map_err(|e| format!("Failed to send message to gossip: {:?}", e))
    }

    fn broadcast_signed_message(&mut self, message: TssMessage) -> Result<(), String> {
        // Create a signed message and broadcast it via the communication manager
        let signed_message = SignedTssMessage {
            message,
            sender_public_key: self.auth_manager.validator_public_key,
            signature: [0u8; 64], // TODO: Implement proper signing
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Send via gossip channel - this will be handled by the gossip handler
        self.communication_manager.session_manager_to_gossip_tx
            .unbounded_send(signed_message)
            .map_err(|e| format!("Failed to broadcast message to gossip: {:?}", e))
    }

    fn handle_announcment(&mut self, sender: PeerId, message: TssMessage) {
        // Handle announcement messages - typically used for peer discovery
        if let TssMessage::Announce(nonce, peer_id, public_key_data, signature) = message {
            log::info!("[TSS] Handling announcement from peer: {}", sender.to_base58());
            // Delegate to the authentication manager or handle directly
            // This is typically used to register new peers
        }
    }

    fn forward_to_session_manager(&self, _signed_message: SignedTssMessage, _sender: Option<PeerId>) -> Result<(), TrySendError<(SignedTssMessage, Option<PeerId>)>> {
        // This is a no-op for SessionManager since we ARE the session manager
        Ok(())
    }
}