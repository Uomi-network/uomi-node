use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sc_network::PeerId;

use crate::{SessionId, TssMessage};

/// Handles peer management and unknown message queueing
pub struct PeerManager {
    unknown_peer_queue: Arc<Mutex<HashMap<PeerId, Vec<TssMessage>>>>,
}

impl PeerManager {
    pub fn new(unknown_peer_queue: Arc<Mutex<HashMap<PeerId, Vec<TssMessage>>>>) -> Self {
        Self {
            unknown_peer_queue,
        }
    }

    // Add a TssMessage we received from an unknown peer until they announce themselves
    pub fn add_unknown_peer_message(&self, peer_id: PeerId, message: TssMessage) {
        log::info!("[TSS] Adding unknown peer message from {:?}", peer_id);
        let mut unknown_peer_queue = self.unknown_peer_queue.lock().unwrap();
        let messages = unknown_peer_queue.entry(peer_id).or_insert_with(Vec::new);
        messages.push(message);
        drop(unknown_peer_queue);
    }

    // Consume the queue of an unknown peer as soon as they have announced themselves
    pub fn consume_unknown_peer_queue(&self, peer_id: PeerId) -> Vec<TssMessage> {
        log::info!("[TSS] Consuming unknown peer queue for {:?}", peer_id);
        let mut unknown_peer_queue = self.unknown_peer_queue.lock().unwrap();
        let messages = unknown_peer_queue.remove(&peer_id).unwrap_or_default();
        drop(unknown_peer_queue);
        messages
    }
}