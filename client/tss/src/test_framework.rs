// test_framework.rs
use crate::*;
use crate::{
    dkghelpers::{FileStorage, MemoryStorage},
    ecdsa::ECDSAManager,
    gossip::router::ECDSAMessageRouter,
    PeerMapper, SessionId, SessionManager,
    TSSPublic, TSSRuntimeEvent, TssMessage, SignedTssMessage,
};
use sc_network_types::PeerId;
use sp_runtime::{
    traits::{Block as BlockT, Hash as HashT, Header as HeaderT},
};

use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender, TrySendError};
use std::cell::RefCell;
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    sync::{Arc, Mutex},
};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;
use uomi_runtime::Block;
use uomi_runtime::pallet_tss::TssOffenceType;
use sp_keystore::{testing::MemoryKeystore, Keystore};
use std::sync::Once;

// Initialize logging for tests once per test binary. Works with `RUST_LOG=...` and `-- --nocapture`.
#[cfg(test)]
static INIT_LOG: Once = Once::new();
#[cfg(test)]
fn init_test_logging() {
    INIT_LOG.call_once(|| {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("debug"),
        )
        .is_test(true)
        .try_init();
    });
}

/// Create a fresh temporary directory, set TSS_STORAGE_DIR to it, and ensure it's empty.
pub fn reset_tss_storage_dir() -> std::path::PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("tss-tests-{}", now));
    // Best-effort cleanup if it exists
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("failed to create fresh TSS storage dir");
    std::env::set_var("TSS_STORAGE_DIR", &base);
    base
}


/// Simulates the network environment with configurable message passing
pub struct TestNetwork {
    /// All nodes in the network
    nodes: HashMap<PeerId, TestNode>,
    /// Queue of messages to be delivered (sender, recipient, message)
    message_queue: VecDeque<(PeerId, Vec<u8>, TssMessage)>,
    /// Network configuration parameters
    config: TestConfig,
}

/// Configuration for network behavior
pub struct TestConfig {
    pub message_delay: usize,
    pub reliability: f32,
    pub fail_specific_peers: Vec<PeerId>,
}

impl Default for TestConfig {
    fn default() -> Self {
        TestConfig {
            message_delay: 0,
            reliability: 1.0,
            fail_specific_peers: Vec::new(),
        }
    }
}


pub struct TestClientManager {
    // spy on calls to ClientManager functions
    submit_dkg_result_calls: RefCell<Vec<(SessionId, Vec<u8>)>>,
    report_participants_calls: RefCell<Vec<(SessionId, Vec<[u8; 32]>)>>,
}

impl TestClientManager {
    pub fn new() -> Self {
        TestClientManager {
            submit_dkg_result_calls: RefCell::new(Vec::new()),
            report_participants_calls: RefCell::new(Vec::new()),
        }
    }

    pub fn submit_dkg_result_calls(&self) -> Vec<(SessionId, Vec<u8>)> {
        self.submit_dkg_result_calls.borrow().clone()
    }
    pub fn report_participants_calls(&self) -> Vec<(SessionId, Vec<[u8; 32]>)> {
        self.report_participants_calls.borrow().clone()
    }

    pub fn clear_calls(&self) {
        self.submit_dkg_result_calls.borrow_mut().clear();
        self.report_participants_calls.borrow_mut().clear();
    }

    pub fn add_submit_dkg_result_call(&self, session_id: SessionId, aggregated_key: Vec<u8>) {
        self.submit_dkg_result_calls
            .borrow_mut()
            .push((session_id, aggregated_key));
    }
    pub fn add_report_participants_call(&self, session_id: SessionId, inactive_participants: Vec<[u8; 32]>) {
        self.report_participants_calls
            .borrow_mut()
            .push((session_id, inactive_participants));
    }
}

impl<B: BlockT> ClientManager<B> for TestClientManager {
    fn best_hash(&self) -> <<B as BlockT>::Header as HeaderT>::Hash {
        Default::default()
    }

    fn best_number(&self) -> <<B as BlockT>::Header as HeaderT>::Number {
        Default::default()
    }

    fn report_participants(
        &self,
        _hash: <<B as BlockT>::Header as HeaderT>::Hash, 
        session_id: SessionId,
        inactive_participants: Vec<[u8; 32]>,
    ) -> Result<(), String> {
        // Test implementation just returns Ok
        self.add_report_participants_call(session_id, inactive_participants);
        Ok(())
    }
    fn submit_dkg_result(
            &self,
            _hash: <<B as BlockT>::Header as HeaderT>::Hash,
            session_id: SessionId,
            aggregated_key: Vec<u8>,
        ) -> Result<(), String> {
        // Test implementation just returns Ok
        self.add_submit_dkg_result_call(session_id, aggregated_key);
        Ok(())
    }

    fn complete_reshare_session(
        &self,
        _hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
    ) -> Result<(), String> {
        // For tests we can just record or noop; here we noop.
        let _ = session_id;
        Ok(())
    }
    
    fn report_tss_offence(
        &self,
        _hash: <<B as BlockT>::Header as HeaderT>::Hash,
        _session_id: SessionId,
        _offence_type: TssOffenceType,
        _offenders: Vec<[u8; 32]>,
    ) -> Result<(), String> {
        // Test implementation just returns Ok
        Ok(())
    }
}
/// Represents a single node in the test network
pub struct TestNode {
    /// The core component under test
    pub session_manager: SessionManager<Block, TestClientManager>,
    /// Transmitter for runtime events
    pub runtime_tx: TracingUnboundedSender<TSSRuntimeEvent>,
    /// Receiver for outgoing gossip messages
    pub gossip_rx: TracingUnboundedReceiver<SignedTssMessage>,
    /// Sender for outgoing gossip messages
    pub gossip_tx: TracingUnboundedSender<(SignedTssMessage, Option<PeerId>)>,
    /// Spy on storage state
    pub storage: Arc<Mutex<MemoryStorage>>,
    /// Spy on key storage
    pub key_storage: Arc<Mutex<FileStorage>>,
}

impl TestNetwork {
    /// Create a new test network with the given number of nodes
    pub fn new(node_count: usize, config: TestConfig) -> Self {
    // Ensure a clean TSS storage dir for every test network
    reset_tss_storage_dir();
        let mut nodes = HashMap::with_capacity(node_count);
        // Keep track of (validator_key, assigned_id) for all nodes
        let mut validator_map: Vec<(TSSPublic, u32)> = Vec::with_capacity(node_count);

        for i in 0..node_count {
            let (peer_id, validator_key) = generate_peer_data(i);
            // Deterministic validator id: index + 1
            validator_map.push((validator_key.clone(), (i as u32) + 1));
            let node = TestNode::new(peer_id, validator_key);
            nodes.insert(peer_id, node);
        }

        let node_keys = nodes.keys().cloned().collect::<Vec<_>>();
        let node_keys_inner = nodes.keys().cloned().collect::<Vec<_>>();


        assert_eq!(node_keys.len(), node_count);

        for peer_id in node_keys {
            let node = nodes.get(&peer_id).unwrap();

            for other_peer_id in node_keys_inner.iter() {
                if peer_id != *other_peer_id {
                    node.session_manager.session_core.peer_mapper.lock().unwrap().add_peer(
                        other_peer_id.clone(),
                        nodes.get(other_peer_id).unwrap().session_manager.session_core.validator_key.clone(),
                    );
            
                }
            
            }
            // Populate validator_id assignments for all known validators in this node's PeerMapper
            {
                let mut mapper = node.session_manager.session_core.peer_mapper.lock().unwrap();
                for (account, id) in validator_map.iter() {
                    mapper.set_validator_id(account.clone(), *id);
                }
            }
            // verify that each peer_mapper contains the elements it should
            assert_eq!(
                node_count,
                node.session_manager.session_core.peer_mapper.lock().unwrap().peers().lock().unwrap().len()
            );
        }

        TestNetwork {
            nodes,
            message_queue: VecDeque::new(),
            config,
        }
    }

    /// Get mutable access to a specific node
    pub fn node_mut(&mut self, peer_id: &PeerId) -> &mut TestNode {
        self.nodes.get_mut(peer_id).expect("Node should exist")
    }

    /// Get access to all nodes (for testing)
    pub fn nodes(&self) -> &HashMap<PeerId, TestNode> {
        &self.nodes
    }

    /// Get access to all nodes (for testing)
    pub fn nodes_mut(&mut self) -> &mut HashMap<PeerId, TestNode> {
        &mut self.nodes
    }
    /// Process all pending messages in the network
    pub fn deliver_messages(&mut self) -> Vec<(PeerId, Vec<u8>, TssMessage)> {
        let mut delivered = Vec::new();

        while let Some((sender_id, recipient_bytes, msg)) = self.message_queue.pop_front() {
            // Handle message loss
            if rand::random::<f32>() > self.config.reliability {
                continue;
            }

            // Get the sender's validator key before we start borrowing nodes mutably
            let sender_validator_key = if let Some(sender_node) = self.nodes.get(&sender_id) {
                let mut key = [0u8; 32];
                key.copy_from_slice(&sender_node.session_manager.session_core.validator_key[..32]);
                key
            } else {
                [0u8; 32] // fallback to dummy if sender not found
            };

            // Handle broadcast (empty recipient) or direct message
            let mut recipients: Vec<PeerId> = if recipient_bytes.is_empty() {
                // if it's broadcast it means we send to everyone BUT the sender_id
                self
                    .nodes
                    .keys()
                    .filter(|key| **key != sender_id)
                    .cloned()
                    .collect()
            } else {
                vec![PeerId::from_bytes(&recipient_bytes).unwrap()]
            };

            // Ensure deterministic recipient order
            recipients.sort_by(|a, b| a.to_bytes().cmp(&b.to_bytes()));

            for recipient_id in recipients {
                // Skip failed peers
                if self.config.fail_specific_peers.contains(&recipient_id) {
                    continue;
                }

                if let Some(node) = self.nodes.get_mut(&recipient_id) {
                    // Create a SignedTssMessage for testing
                    let signed_message = SignedTssMessage {
                        message: msg.clone(),
                        sender_public_key: sender_validator_key,
                        signature: [0u8; 64], // dummy for tests
                        block_number: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    };
                    node.session_manager.process_gossip_message_with_sender(signed_message, sender_id.clone());
                }
            }

            delivered.push((sender_id, recipient_bytes, msg));
        }

        let delivered_clone = delivered.clone();
        // Requeue messages if delay > 0
        if self.config.message_delay > 0 {
            self.message_queue.extend(delivered_clone);
        }
        delivered
    }

    /// Process one complete network round (send + receive)
    pub fn process_round(&mut self) -> Vec<(PeerId, Vec<u8>, TssMessage)> {
        // Collect all outgoing messages from nodes in a deterministic order
        let mut peer_ids: Vec<PeerId> = self.nodes.keys().cloned().collect();
        peer_ids.sort_by(|a, b| a.to_bytes().cmp(&b.to_bytes()));

        for peer_id in peer_ids {
            let node = self.nodes.get_mut(&peer_id).expect("Node should exist");
            let (broadcast_msgs, direct_msgs) = node.outgoing_messages();

            for msg in broadcast_msgs {
                self.message_queue
                    .push_back((peer_id.clone(), vec![], msg.clone()));
            }

            for (msg, recipient_peer_id) in direct_msgs {
                self.message_queue
                    .push_back((peer_id.clone(), recipient_peer_id.to_bytes(), msg.clone()));
            }
        }

        self.deliver_messages()
    }

    pub fn process_all_rounds(&mut self) {
        let max_iterations = 15;
        for _i in 0..max_iterations {
            let messages = self.process_round();
            println!("process_round.len {:?}", messages.len());
            if messages.len() == 0 {
                break;
            }
        }
    }
}




impl TestNode {
    /// Create a new test node with mocked channels
    fn new(peer_id: PeerId, validator_key: TSSPublic) -> Self {
        // Create mock channels that match production setup
        let (gossip_to_sm_tx, gossip_to_sm_rx) = tracing_unbounded("test_gossip_to_sm", 1024);
        let (sm_to_gossip_tx, sm_to_gossip_rx) = tracing_unbounded("test_sm_to_gossip", 1024);
        let (runtime_to_sm_tx, runtime_to_sm_rx) = tracing_unbounded("test_runtime_to_sm", 1024);

        // Initialize dependencies
        let storage = Arc::new(Mutex::new(MemoryStorage::new()));
        let key_storage = Arc::new(Mutex::new(FileStorage::new()));
        let sessions_participants = Arc::new(Mutex::new(HashMap::new()));
        let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants.clone())));

        {
            let mut handle = peer_mapper.lock().unwrap();
            handle.add_peer(peer_id.clone(), validator_key.clone());
        }

        // Create a keystore and generate a key for the validator to sign messages.
        let keystore = Arc::new(MemoryKeystore::new());
        const UOMI: sp_core::crypto::KeyTypeId = sp_core::crypto::KeyTypeId(*b"uomi");
        let validator_public_key = keystore
            .sr25519_generate_new(UOMI, None)
            .expect("failed to generate sr25519 key");


        let session_manager = SessionManager::new(
            storage.clone(),
            key_storage.clone(),
            sessions_participants,
            Arc::new(Mutex::new(HashMap::new())), // sessions_data
            Arc::new(Mutex::new(HashMap::new())), // dkg_session_states  
            Arc::new(Mutex::new(HashMap::new())), // signing_session_states
            validator_key.clone(),
            validator_public_key.into(), // validator_public_key
            keystore.clone(), // keystore
            peer_mapper,
            gossip_to_sm_rx,
            runtime_to_sm_rx,
            sm_to_gossip_tx,
            peer_id.to_bytes(),
            Some(TssMessage::Announce(Default::default(), Vec::new(), Vec::new(), Vec::new(), 0)),
            TestClientManager::new(),
            false, // retry_enabled
        );

        TestNode {
            session_manager,
            runtime_tx: runtime_to_sm_tx,
            gossip_rx: sm_to_gossip_rx,
            gossip_tx: gossip_to_sm_tx,
            storage,
            key_storage,
        }
    }

    /// Inject a runtime event into the session manager
    pub fn inject_runtime_event(&mut self, event: TSSRuntimeEvent) {
        self.runtime_tx.unbounded_send(event).unwrap();
    }

    /// Simulate receiving a gossip message
    pub fn receive_gossip_message(&mut self, sender: PeerId, message: TssMessage) {
        // Create a SignedTssMessage for testing
        let signed_message = SignedTssMessage {
            message,
            sender_public_key: [0u8; 32], // dummy for tests
            signature: [0u8; 64], // dummy for tests
            block_number: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        self.gossip_tx.unbounded_send((signed_message, Some(sender))).unwrap();
    }

    /// Get all outgoing messages from the session_manager to the gossip_handler
    /// SM => GH
    pub fn outgoing_messages(&mut self) -> (Vec<TssMessage>, Vec<(TssMessage, PeerId)>) { // (broadcast, direct)
        let mut handler = MockTssMessageHandler::default();

    while let Ok(signed_msg) = self.gossip_rx.try_recv() {
            process_session_manager_message(&mut handler, signed_msg).unwrap();
        }

        let broadcast = handler.broadcast_messages.borrow().clone();
        let direct = handler.sent_messages.borrow().clone();
        
        handler.broadcast_messages.borrow_mut().clear();
        handler.sent_messages.borrow_mut().clear();

        (broadcast, direct)
    }
    /// Get all incoming messages to the Session Manager from the Gossip Handler
    /// GH => SM
    pub fn incoming_messages(&mut self) -> Vec<(PeerId, TssMessage)> {
        let mut messages = Vec::new();
        while let Ok((signed_msg, sender)) = self.session_manager.communication_manager.gossip_to_session_manager_rx.try_recv()
        {
            // Convert SignedTssMessage back to the expected format for tests
            // In real scenarios, we'd need to extract the peer_id from the message
            let dummy_peer_id = sender.unwrap_or_else(|| PeerId::from_bytes(&signed_msg.sender_public_key).unwrap_or_else(|_| PeerId::random()));
            messages.push((dummy_peer_id, signed_msg.message));
        }
        messages
    }
}

/// Generate deterministic peer data for testing
fn generate_peer_data(index: usize) -> (PeerId, TSSPublic) {
    use sp_core::{sr25519, Pair};
    let seed = [index as u8; 32];
    let pair = sr25519::Pair::from_seed(&seed);
    let peer_id = PeerId::random();
    (peer_id, pair.public().to_vec())
}

#[derive(Default)]
pub struct MockTssMessageHandler {
    pub sent_messages: RefCell<Vec<(TssMessage, PeerId)>>,
    pub broadcast_messages: RefCell<Vec<TssMessage>>,
    pub forwarded_messages: RefCell<Vec<(PeerId, TssMessage)>>,
    pub announcements: RefCell<Vec<(PeerId, TssMessage)>>,
    pub should_fail: RefCell<bool>,
}

impl TssMessageHandler for MockTssMessageHandler {
    fn send_signed_message(&mut self, message: TssMessage, recipient: PeerId) -> Result<(), String> {
        if *self.should_fail.borrow() {
            return Err("SendFailure".to_string());
        }
        self.sent_messages.borrow_mut().push((message, recipient));
        Ok(())
    }

    fn broadcast_signed_message(&mut self, message: TssMessage) -> Result<(), String> {
        if *self.should_fail.borrow() {
            return Err("BroadcastFailure".to_string());
        }
        self.broadcast_messages.borrow_mut().push(message);
        Ok(())
    }

    fn handle_announcment(&mut self, sender: PeerId, message: TssMessage) {
        self.announcements.borrow_mut().push((sender, message));
    }

    fn forward_to_session_manager(
        &self,
        signed_message: SignedTssMessage,
        sender: Option<PeerId>,
    ) -> Result<(), TrySendError<(SignedTssMessage, Option<PeerId>)>> {
        // For testing, we'll extract the message and create a dummy peer ID from the sender's public key
        let dummy_peer_id = sender.unwrap_or_else(|| {
            PeerId::from_bytes(&signed_message.sender_public_key[..]).unwrap_or_else(|_| PeerId::random())
        });
        self.forwarded_messages.borrow_mut().push((dummy_peer_id, signed_message.message));
        Ok(())
    }
}

// Helper methods for tests
impl MockTssMessageHandler {
    pub fn set_failure(&self, should_fail: bool) {
        *self.should_fail.borrow_mut() = should_fail;
    }

    pub fn count_sent_messages(&self) -> usize {
        self.sent_messages.borrow().len()
    }

    pub fn count_broadcast_messages(&self) -> usize {
        self.broadcast_messages.borrow().len()
    }

    pub fn clear_all(&self) {
        self.sent_messages.borrow_mut().clear();
        self.broadcast_messages.borrow_mut().clear();
        self.forwarded_messages.borrow_mut().clear();
        self.announcements.borrow_mut().clear();
    }
}

#[test]
fn test_process_session_manager_message_dkg_round1() {
    init_test_logging();
    reset_tss_storage_dir();
    let mut handler = MockTssMessageHandler::default();
    let session_id: SessionId = 0;
    let data = vec![1, 2, 3];

    let signed_message = SignedTssMessage {
        message: TssMessage::DKGRound1(session_id, data.clone()),
        sender_public_key: [0u8; 32], // dummy sender key for tests
        signature: [0u8; 64], // dummy signature for tests
        block_number: 0, // dummy block_number for tests
    };

    let result = process_session_manager_message(&mut handler, signed_message);

    assert!(result.is_ok());
    assert_eq!(handler.count_broadcast_messages(), 1);
    assert_eq!(handler.count_sent_messages(), 0);

    let broadcast_msgs = handler.broadcast_messages.borrow();
    match &broadcast_msgs[0] {
        TssMessage::DKGRound1(id, bytes) => {
            assert_eq!(id, &session_id);
            assert_eq!(bytes, &data);
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_buffer_stores_peerid_bytes_for_dkg_round1() {
    init_test_logging();
    reset_tss_storage_dir();
    // Create a 2-node test network
    let mut network = TestNetwork::new(2, TestConfig::default());

    // Pick two distinct peers: receiver (A) and sender (B)
    let mut iter = network.nodes().keys();
    let a_peer = iter.next().expect("at least one node").clone();
    let b_peer = iter.next().expect("at least two nodes").clone();

    // Prepare a signed DKGRound1 message from B to A for a session that doesn't exist yet on A
    let session_id: SessionId = 42;
    let payload = vec![9, 9, 9];

    // Use B's validator key as the sender_public_key
    let b_validator_key = network
        .nodes()
        .get(&b_peer)
        .unwrap()
        .session_manager
        .session_core
        .validator_key
        .clone();
    let mut sender_pk = [0u8; 32];
    sender_pk.copy_from_slice(&b_validator_key[..32]);

    // Block number must be recent to pass block-number validation
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let signed = SignedTssMessage {
        message: TssMessage::DKGRound1(session_id, payload.clone()),
        sender_public_key: sender_pk,
        signature: [0u8; 64], // in tests this bypasses signature verification
        block_number: now,
    };

    // Inject directly into A's SessionManager as if received from B
    let node_a = network.node_mut(&a_peer);
    node_a
        .session_manager
        .process_gossip_message_with_sender(signed, b_peer.clone());

    // Since the session doesn't exist on A, the message should be buffered
    let buffer_guard = node_a.session_manager.buffer.lock().unwrap();
    let entry = buffer_guard
        .get(&session_id)
        .expect("buffer entry should exist for session");
    assert!(entry.len() >= 1, "buffer should contain at least one message");

    // The buffered tuple must store the sender PeerId bytes, not a public key
    let (sender_bytes, buffered_msg) = &entry[0];
    let parsed_pid = PeerId::from_bytes(&sender_bytes[..])
        .expect("buffer must contain valid PeerId bytes");
    assert_eq!(parsed_pid, b_peer, "decoded PeerId should match sender");

    // And the buffered message should match the original DKGRound1
    match buffered_msg {
        TssMessage::DKGRound1(id, bytes) => {
            assert_eq!(*id, session_id);
            assert_eq!(bytes, &payload);
        }
        _ => panic!("buffered message must be DKGRound1"),
    }
}

#[test]
fn test_route_ecdsa_message() {
    init_test_logging();
    reset_tss_storage_dir();
    let mut handler = MockTssMessageHandler::default();
    let session_id: SessionId = 1;
    let data = vec![1, 2, 3];

    // Test broadcast
    let result = handler.route_ecdsa_message(
        session_id,
        1.to_string(),
        data.clone(),
        ECDSAPhase::Key,
        None,
    );

    assert!(result.is_ok());
    assert_eq!(handler.count_broadcast_messages(), 1);

    // Test direct message
    let peer = PeerId::random();
    let result = handler.route_ecdsa_message(
        session_id,
        1.to_string(),
        data.clone(),
        ECDSAPhase::Sign,
        Some(peer.clone()),
    );

    assert!(result.is_ok());
    assert_eq!(handler.count_sent_messages(), 1);

    let sent_msgs = handler.sent_messages.borrow();
    match &sent_msgs[0] {
        (TssMessage::ECDSAMessageSign(id, idx, bytes), recipient) => {
            assert_eq!(id, &session_id);
            assert_eq!(idx, &1.to_string());
            assert_eq!(bytes, &data);
            assert_eq!(recipient, &peer);
        }
        _ => panic!("Wrong message type or recipient"),
    }
}
