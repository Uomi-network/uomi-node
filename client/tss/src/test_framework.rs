// test_framework.rs
use crate::*;
use crate::{
    dkghelpers::{FileStorage, MemoryStorage},
    ecdsa::ECDSAManager,
    DKGSessionState, PeerMapper, SessionData, SessionId, SessionManager, SigningSessionState,
    TSSParticipant, TSSPeerId, TSSPublic, TSSRuntimeEvent, TssMessage,
};
use sc_network::PeerId;
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use std::cell::RefCell;
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    sync::{Arc, Mutex},
};
use uomi_runtime::Block;

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

/// Represents a single node in the test network
pub struct TestNode {
    /// The core component under test
    pub session_manager: SessionManager<Block>,
    /// Transmitter for runtime events
    pub runtime_tx: TracingUnboundedSender<TSSRuntimeEvent>,
    /// Receiver for outgoing gossip messages
    pub gossip_rx: TracingUnboundedReceiver<(PeerId, TssMessage)>,
    /// Sender for outgoing gossip messages
    pub gossip_tx: TracingUnboundedSender<(PeerId, TssMessage)>,
    /// Spy on storage state
    pub storage: Arc<Mutex<MemoryStorage>>,
    /// Spy on key storage
    pub key_storage: Arc<Mutex<FileStorage>>,
}

impl TestNetwork {
    /// Create a new test network with the given number of nodes
    pub fn new(node_count: usize, config: TestConfig) -> Self {
        let mut nodes = HashMap::with_capacity(node_count);

        for i in 0..node_count {
            let (peer_id, validator_key) = generate_peer_data(i);
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
                    node.session_manager.peer_mapper.lock().unwrap().add_peer(
                        other_peer_id.clone(),
                        nodes.get(other_peer_id).unwrap().session_manager.validator_key.clone(),
                    );
            
                }
            
            }
            // verify that each peer_mapper contains the elements it should
            assert_eq!(
                node_count,
                node.session_manager.peer_mapper.lock().unwrap().peers.keys().len()
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

            // Handle broadcast (empty recipient) or direct message
            let recipients = if recipient_bytes.is_empty() {
                // if it's broadcast it means we send to everyone BUT the sender_id
                self.nodes.keys().filter(|key| **key != sender_id).cloned().collect()
            } else {
                vec![PeerId::from_bytes(&recipient_bytes).unwrap()]
            };

            for recipient_id in recipients {
                // Skip failed peers
                if self.config.fail_specific_peers.contains(&recipient_id) {
                    continue;
                }

                if let Some(node) = self.nodes.get_mut(&recipient_id) {
                    //node.receive_gossip_message(sender_id.clone(), msg.clone());
                    node.session_manager
                        .process_gossip_message(sender_id.clone(), msg.clone());
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
        // Collect all outgoing messages from nodes
        for (peer_id, node) in &mut self.nodes {
            let mut handler = MockTssMessageHandler::default();
            let outbound_queue = node.outgoing_messages();

            for msg in outbound_queue {
                assert!(process_session_manager_message(&mut handler, msg).is_ok());
            }

            // manage the handler.broadcast queue
            for msg in handler.broadcast_messages.borrow().iter() {
                self.message_queue
                    .push_back((peer_id.clone(), vec![], msg.clone()));
            }

            // manage the p2p connections
            for msg in handler.sent_messages.borrow().iter() {
                self.message_queue
                    .push_back((peer_id.clone(), msg.1.to_bytes(), msg.0.clone()));
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

        let ecdsa_manager = Arc::new(Mutex::new(ECDSAManager::new()));

        let session_manager = SessionManager {
            storage: storage.clone(),
            key_storage: key_storage.clone(),
            sessions_participants,
            sessions_data: Arc::new(Mutex::new(HashMap::new())),
            dkg_session_states: Arc::new(Mutex::new(HashMap::new())),
            signing_session_states: Arc::new(Mutex::new(HashMap::new())),
            validator_key: validator_key.clone(),
            peer_mapper,
            gossip_to_session_manager_rx: gossip_to_sm_rx,
            runtime_to_session_manager_rx: runtime_to_sm_rx,
            session_manager_to_gossip_tx: sm_to_gossip_tx,
            buffer: Arc::new(Mutex::new(HashMap::new())),
            local_peer_id: peer_id.to_bytes(),
            ecdsa_manager,
            session_timeout: 3600,
            session_timestamps: Arc::new(Mutex::new(HashMap::new())),
            _phantom: PhantomData,
            active_participants: Arc::new(Mutex::new(HashMap::new())),
        };

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
        // Get the gossip_to_session_manager_tx from the session manager
        // This would need an accessor method in the real SessionManager
        self.gossip_tx.unbounded_send((sender, message)).unwrap();
    }

    /// Get all outgoing messages from the session_manager to the gossip_handler
    /// SM => GH
    pub fn outgoing_messages(&mut self) -> Vec<(PeerId, TssMessage)> {
        let mut messages = Vec::new();
        while let Ok((peer_id, msg)) = self.gossip_rx.try_recv() {
            messages.push((peer_id, msg));
        }
        messages
    }
    /// Get all incoming messages to the Session Manager from the Gossip Handler
    /// GH => SM
    pub fn incoming_messages(&mut self) -> Vec<(PeerId, TssMessage)> {
        let mut messages = Vec::new();
        while let Ok((peer_id, msg)) = self.session_manager.gossip_to_session_manager_rx.try_recv()
        {
            messages.push((peer_id, msg));
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
    fn send_message(&mut self, message: TssMessage, recipient: PeerId) -> Result<(), String> {
        if *self.should_fail.borrow() {
            return Err("SendFailure".to_string());
        }
        self.sent_messages.borrow_mut().push((message, recipient));
        Ok(())
    }

    fn broadcast_message(&mut self, message: TssMessage) -> Result<(), String> {
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
        sender: PeerId,
        message: TssMessage,
    ) -> Result<(), TrySendError<(PeerId, TssMessage)>> {
        self.forwarded_messages.borrow_mut().push((sender, message));
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
    let mut handler = MockTssMessageHandler::default();
    let session_id: SessionId = 0;
    let data = vec![1, 2, 3];
    let recipient = PeerId::random();

    let message = (
        recipient.clone(),
        TssMessage::DKGRound1(session_id, data.clone()),
    );

    let result = process_session_manager_message(&mut handler, message);

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
fn test_route_ecdsa_message() {
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

/// We mock the network in this way:
///
/// 1. MockNetwork holds references to half of the ends, specifically:
///     a. Runtime to SessionManager transmitter
///     b. Gossip to SessionManager transmitter
///     c. SessionManager to Gossip receiver
/// 2. When we mock a SessionManager, we also automatically add a node to the network, giving it the necessary channels to communicate.
/// 3. The MockNetwork routes messages. It uses PeerId for direct messages. SessionId is used within the SessionManager to direct messages to the correct session's logic.
/// 4. Broadcast messages are sent by the MockNetwork to all connected SessionManagers. The SessionManager then handles internal routing based on the SessionId.
///
/// The original creates these channels
/// // Set up communication channels
/// let (gossip_to_session_manager_tx, gossip_to_session_manager_rx) =
/// sc_utils::mpsc::tracing_unbounded::<(PeerId, TssMessage)>(
///     "gossip_to_session_manager",
///     1024,
/// );
/// let (session_manager_to_gossip_tx, session_manager_to_gossip_rx) =
/// sc_utils::mpsc::tracing_unbounded::<(PeerId, TssMessage)>(
///     "session_manager_to_gossip",
///     1024,
/// );
/// let (runtime_to_session_manager_tx, runtime_to_session_manager_rx) =
/// sc_utils::mpsc::tracing_unbounded::<TSSRuntimeEvent>("runtime_to_session_manager", 1024);
fn fake() {}
