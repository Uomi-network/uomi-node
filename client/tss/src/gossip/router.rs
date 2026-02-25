use codec::{Decode, Encode};
use sc_utils::mpsc::{TracingUnboundedSender, TracingUnboundedReceiver, TrySendError};
use sp_keystore::{KeystorePtr};
use sc_network_types::{PeerId};
use std::{
    collections::{btree_map::Keys, VecDeque, HashSet},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    future::Future,
    marker::PhantomData,
};
use futures::{channel::mpsc::Receiver, prelude::*, stream::FusedStream};
use sc_network_gossip::{
    GossipEngine, TopicNotification,
};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, Hash as HashT};
use sp_core::{sr25519, ByteArray};
use sp_io::crypto::sr25519_verify;
use frost_ed25519::{
    round1::SigningCommitments,
    Identifier,
};
use log::info;

use crate::types::{TssMessage, SignedTssMessage, SessionId};
use crate::ecdsa::ECDSAPhase;
use crate::network::PeerMapper;

use crate::gossip::signing::SigningService;
use crate::gossip::message_processor::MessageProcessor;

// Define a trait for message handling to make testing easier
pub trait TssMessageHandler {
    fn send_signed_message(&mut self, message: TssMessage, recipient: PeerId) -> Result<(), String>;
    fn broadcast_signed_message(&mut self, message: TssMessage) -> Result<(), String>;
    fn handle_announcment(&mut self, sender: PeerId, message: TssMessage);
    fn forward_to_session_manager(&self, signed_message: SignedTssMessage, sender: Option<PeerId>) -> Result<(), TrySendError<(SignedTssMessage, Option<PeerId>)>>;
}

pub struct GossipHandler<B: BlockT> {
    gossip_engine: GossipEngine<B>,
    peer_mapper: Arc<Mutex<PeerMapper>>,
    gossip_to_session_manager_tx: TracingUnboundedSender<(SignedTssMessage, Option<PeerId>)>,
    session_manager_to_gossip_rx: TracingUnboundedReceiver<SignedTssMessage>,
    gossip_handler_message_receiver: Receiver<TopicNotification>,
    signing_service: SigningService,
    get_block_number: Arc<dyn Fn() -> u64 + Send + Sync>,
    // LRU-style replay cache for (peer_id_bytes, nonce)
    announce_replay_cache: VecDeque<(Vec<u8>, u16)>,
    announce_replay_set: HashSet<(Vec<u8>, u16)>,
}

impl<B: BlockT> GossipHandler<B> {
    pub fn new(
        gossip_engine: GossipEngine<B>,
    gossip_to_session_manager_tx: TracingUnboundedSender<(SignedTssMessage, Option<PeerId>)>,
    session_manager_to_gossip_rx: TracingUnboundedReceiver<SignedTssMessage>,
        peer_mapper: Arc<Mutex<PeerMapper>>,
        gossip_handler_message_receiver: Receiver<TopicNotification>,
        keystore: KeystorePtr,
        validator_public_key: [u8; 32],
        get_block_number: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            gossip_engine,
            peer_mapper,
            gossip_to_session_manager_tx,
            session_manager_to_gossip_rx,
            gossip_handler_message_receiver,
            signing_service: SigningService::new(keystore, validator_public_key),
            get_block_number,
            announce_replay_cache: VecDeque::with_capacity(512),
            announce_replay_set: HashSet::with_capacity(512),
        }
    }

    /// Create a signed message using the signing service
    fn create_signed_message(&self, message: TssMessage) -> Result<SignedTssMessage, String> {
        let block = (self.get_block_number)();
        self.signing_service.create_signed_message(message, block)
    }
}
impl<B:BlockT> TssMessageHandler for GossipHandler<B> {
    fn send_signed_message(&mut self, message: TssMessage, peer_id: PeerId) -> Result<(), String> {
        log::debug!("[TSS] 📤 GossipHandler CREATING SIGNED P2P MESSAGE: {:?} for peer: {}", 
            std::mem::discriminant(&message), peer_id.to_base58());
        
        let signed_message = self.create_signed_message(message)?;
        
        log::debug!("[TSS] 🚀 Sending signed direct message to peer: {}", peer_id.to_base58());
        self.gossip_engine.send_message(vec![peer_id], signed_message.encode());
        Ok(())
    }

    fn broadcast_signed_message(&mut self, message: TssMessage) -> Result<(), String> {
        log::debug!("[TSS] 📤 GossipHandler CREATING SIGNED BROADCAST MESSAGE: {:?}", 
            std::mem::discriminant(&message));
        
        let signed_message = self.create_signed_message(message)?;
        
        let topic = <<B::Header as HeaderT>::Hashing as HashT>::hash("tss_topic".as_bytes());
        log::debug!("[TSS] 📡 Broadcasting signed message to all peers");
        self.gossip_engine.gossip_message(topic, signed_message.encode(), false);
        Ok(())
    }

    fn handle_announcment(&mut self, _peer_id: PeerId, data: TssMessage) {
    process_announcement(
            &self.peer_mapper,
            &mut self.announce_replay_cache,
            &mut self.announce_replay_set,
            data,
        );
    }
    fn forward_to_session_manager(&self, signed_message: SignedTssMessage, sender: Option<PeerId>) -> Result<(), TrySendError<(SignedTssMessage, Option<PeerId>)>> {
        self.gossip_to_session_manager_tx.unbounded_send((signed_message, sender))
    }
}

/// Process an announcement message: verify signature, apply replay protection, and register peer.
/// Returns true if the announcement was accepted and added; false otherwise.
pub fn process_announcement(
    peer_mapper: &Arc<Mutex<PeerMapper>>,
    replay_cache: &mut VecDeque<(Vec<u8>, u16)>,
    replay_set: &mut HashSet<(Vec<u8>, u16)>,
    data: TssMessage,
) -> bool {
    if let TssMessage::Announce(nonce, peer_id, public_key_data, signature, challenge_answer) = data {
        info!(
            "[TSS] Handling peer_id {:?} with pubkey {:?}",
            peer_id, public_key_data
        );

        // Replay protection
        let key = (peer_id.clone(), nonce);
        if replay_set.contains(&key) {
            log::warn!("[TSS] Ignoring replayed announcement for peer {:?} nonce {}", peer_id, nonce);
            return false;
        }

        let public_key = match sr25519::Public::from_slice(&public_key_data[..]) {
            Ok(pk) => pk,
            Err(_) => {
                log::warn!("[TSS] Invalid public key length in announcement");
                return false;
            }
        };
        // Reconstruct payload (public_key || peer_id || nonce_le)
        let mut payload = Vec::with_capacity(public_key_data.len() + peer_id.len() + 2);
        payload.extend_from_slice(&public_key_data[..]);
        payload.extend_from_slice(&peer_id[..]);
    payload.extend_from_slice(&nonce.to_le_bytes());
    if challenge_answer != 0 { payload.extend_from_slice(&challenge_answer.to_le_bytes()); }

        let Ok(sig_bytes): Result<[u8;64], _> = signature.clone().try_into() else {
            log::warn!("[TSS] Invalid signature length in announcement");
            return false;
        };
        let sig = sr25519::Signature::from_raw(sig_bytes);

        if sr25519_verify(&sig, &payload, &public_key) {
            match PeerId::from_bytes(&peer_id[..]) {
                Ok(pid) => {
                    peer_mapper.lock().unwrap().add_peer(pid, public_key_data);
                    const MAX_CACHE: usize = 512;
                    replay_cache.push_back(key.clone());
                    replay_set.insert(key);
                    if replay_cache.len() > MAX_CACHE {
                        if let Some(old) = replay_cache.pop_front() { replay_set.remove(&old); }
                    }
                    return true;
                }
                Err(e) => {
                    log::error!("[TSS] Invalid peer ID bytes in Announce message: {:?}", e);
                    return false;
                }
            }
        } else {
            log::warn!("[TSS] Announcement signature verification failed for peer_id {:?}", peer_id);
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::Pair;
    use rand::RngCore; // kept for potential randomness in future tests
    use proptest::prelude::*;

    fn make_signed_announce(nonce: u16, pair: &sr25519::Pair, peer_id: &PeerId) -> TssMessage {
        let pubkey = pair.public().0.to_vec();
        let peer_bytes = peer_id.to_bytes();
        let mut payload = Vec::new();
        payload.extend_from_slice(&pubkey);
        payload.extend_from_slice(&peer_bytes);
        payload.extend_from_slice(&nonce.to_le_bytes());
        let signature = pair.sign(&payload).0.to_vec();
    TssMessage::Announce(nonce, peer_bytes, pubkey, signature, 0)
    }

    fn make_signed_announce_with_challenge(nonce: u16, challenge_answer: u32, pair: &sr25519::Pair, peer_id: &PeerId) -> TssMessage {
        let pubkey = pair.public().0.to_vec();
        let peer_bytes = peer_id.to_bytes();
        let mut payload = Vec::new();
        payload.extend_from_slice(&pubkey);
        payload.extend_from_slice(&peer_bytes);
        payload.extend_from_slice(&nonce.to_le_bytes());
        if challenge_answer != 0 { payload.extend_from_slice(&challenge_answer.to_le_bytes()); }
        let signature = pair.sign(&payload).0.to_vec();
        TssMessage::Announce(nonce, peer_bytes, pubkey, signature, challenge_answer)
    }

    #[test]
    fn test_announce_replay_same_nonce_rejected() {
        let sessions_participants = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants)));
        let mut cache = VecDeque::new();
        let mut set = HashSet::new();

        let pair = sr25519::Pair::from_seed(&[1u8;32]);
        let peer_id = PeerId::random();
        let msg = make_signed_announce(10, &pair, &peer_id);

        let first = process_announcement(&peer_mapper, &mut cache, &mut set, msg.clone());
        assert!(first, "First announcement should be accepted");
        let second = process_announcement(&peer_mapper, &mut cache, &mut set, msg.clone());
        assert!(!second, "Replay announcement should be rejected");
    }

    #[test]
    fn test_announce_modified_nonce_with_old_signature_fails() {
        let sessions_participants = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants)));
        let mut cache = VecDeque::new();
        let mut set = HashSet::new();

        let pair = sr25519::Pair::from_seed(&[2u8;32]);
        let peer_id = PeerId::random();
        let valid = make_signed_announce(42, &pair, &peer_id);
        assert!(process_announcement(&peer_mapper, &mut cache, &mut set, valid.clone()));

        // Craft tampered message: change nonce but reuse signature (invalid signature)
        if let TssMessage::Announce(_, peer_bytes, pubkey, signature, _) = valid {
            let tampered = TssMessage::Announce(43, peer_bytes, pubkey, signature, 0); // signature does not match new nonce
            let accepted = process_announcement(&peer_mapper, &mut cache, &mut set, tampered);
            assert!(!accepted, "Tampered nonce with old signature must be rejected");
        } else { panic!("Unexpected variant"); }
    }

    #[test]
    fn test_announce_with_challenge_binding_valid() {
        let sessions_participants = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants)));
        let mut cache = VecDeque::new();
        let mut set = HashSet::new();
        let pair = sr25519::Pair::from_seed(&[9u8;32]);
        let peer_id = PeerId::random();
        let challenge_answer: u32 = 0xDEADBEEF;
        let msg = make_signed_announce_with_challenge(55, challenge_answer, &pair, &peer_id);
        let accepted = process_announcement(&peer_mapper, &mut cache, &mut set, msg);
        assert!(accepted, "Announcement with bound challenge should verify");
    }

    #[test]
    fn test_announce_with_incorrect_challenge_signature_fails() {
        // Create a valid message first
        let sessions_participants = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants)));
        let mut cache = VecDeque::new();
        let mut set = HashSet::new();
        let pair = sr25519::Pair::from_seed(&[10u8;32]);
        let peer_id = PeerId::random();
        let challenge_answer: u32 = 12345678;
        let valid = make_signed_announce_with_challenge(60, challenge_answer, &pair, &peer_id);
        // Tamper challenge without resigning
        if let TssMessage::Announce(nonce, peer_bytes, pubkey, signature, _old) = valid {
            let tampered = TssMessage::Announce(nonce, peer_bytes, pubkey, signature, challenge_answer + 1);
            let accepted = process_announcement(&peer_mapper, &mut cache, &mut set, tampered);
            assert!(!accepted, "Tampered challenge answer should cause signature verification failure");
        } else { panic!("pattern"); }
    }

    #[test]
    fn test_announce_different_nonce_new_signature_accepted() {
        let sessions_participants = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants)));
        let mut cache = VecDeque::new();
        let mut set = HashSet::new();

        let pair = sr25519::Pair::from_seed(&[3u8;32]);
        let peer_id = PeerId::random();
        let first = make_signed_announce(5, &pair, &peer_id);
        assert!(process_announcement(&peer_mapper, &mut cache, &mut set, first));
        let second = make_signed_announce(6, &pair, &peer_id);
        assert!(process_announcement(&peer_mapper, &mut cache, &mut set, second), "Different nonce with correct signature should be accepted");
    }

    #[test]
    fn test_lru_eviction_allows_old_nonce_again() {
        let sessions_participants = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants)));
        let mut cache = VecDeque::new();
        let mut set = HashSet::new();
        let pair = sr25519::Pair::from_seed(&[4u8;32]);
        let peer_id = PeerId::random();

        // Insert 513 unique nonces (0..=512). MAX_CACHE=512 so nonce 0 should be evicted.
        for nonce in 0u16..=512u16 { // inclusive range gives 513 entries
            let msg = make_signed_announce(nonce, &pair, &peer_id);
            let accepted = process_announcement(&peer_mapper, &mut cache, &mut set, msg);
            assert!(accepted, "Unique nonce {} should be accepted", nonce);
        }

        // Replay of first nonce (0) should now be accepted again due to eviction.
        let msg_again = make_signed_announce(0, &pair, &peer_id);
        let accepted_again = process_announcement(&peer_mapper, &mut cache, &mut set, msg_again);
        assert!(accepted_again, "Evicted old nonce should be accepted again after LRU eviction");
    }

    #[test]
    fn test_duplicate_does_not_create_additional_peer_entries() {
        let sessions_participants = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants)));
        let mut cache = VecDeque::new();
        let mut set = HashSet::new();
        let pair = sr25519::Pair::from_seed(&[5u8;32]);
        let peer_id = PeerId::random();
        let msg = make_signed_announce(77, &pair, &peer_id);
        assert!(process_announcement(&peer_mapper, &mut cache, &mut set, msg.clone()));
        // Duplicate
        assert!(!process_announcement(&peer_mapper, &mut cache, &mut set, msg.clone()));
        let map = peer_mapper.lock().unwrap();
        assert_eq!(map.peers().lock().unwrap().len(), 1, "Peer map should contain exactly one entry");
    }

    proptest! {
        // Property: Without exceeding LRU capacity (keep sequence length <= 200),
        // an announcement is accepted iff its (peer, nonce) pair has not appeared before.
        #[test]
        fn prop_unique_nonce_acceptance(seq in proptest::collection::vec(0u16..500u16, 1..200usize)) {
            let sessions_participants = Arc::new(Mutex::new(std::collections::HashMap::new()));
            let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants)));
            let mut cache = VecDeque::new();
            let mut set = HashSet::new();
            let pair = sr25519::Pair::from_seed(&[6u8;32]);
            let peer_id = PeerId::random();
            let mut seen = std::collections::HashSet::new();
            for nonce in seq {                
                let msg = make_signed_announce(nonce, &pair, &peer_id);
                let accepted = process_announcement(&peer_mapper, &mut cache, &mut set, msg);
                let expected = seen.insert(nonce); // true if newly inserted
                prop_assert_eq!(accepted, expected, "Acceptance mismatch for nonce {}", nonce);
            }
        }
    }
}

// Define a trait for routing ECDSA messages
pub trait ECDSAMessageRouter {
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
                    "[TSS] Sending signed message to peer_id {:?} for session_id {:?}, phase is {:?}",
                    peer,
                    session_id,
                    phase
                );
                self.send_signed_message(message, peer)
            },
            None => {
                log::debug!(
                    "[TSS] Broadcasting signed message to all peers for session_id {:?} with phase {:?}",
                    session_id,
                    phase
                );
                self.broadcast_signed_message(message)
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
pub fn process_gossip_notification<T: TssMessageHandler>(
    handler: &mut T, 
    notification: TopicNotification
) -> Option<()> {
    let sender = notification.sender?;
    
    // Try to decode as SignedTssMessage first
    match SignedTssMessage::decode(&mut &notification.message[..]) {
        Ok(signed_message) => {
            log::debug!("[TSS] 🔄 GossipHandler forwarding SIGNED MESSAGE: {:?} from sender: {:?}", 
                std::mem::discriminant(&signed_message.message),
                sender.to_base58());
            
            // Forward the signed message to session manager
            if let Err(e) = handler.forward_to_session_manager(signed_message, Some(sender.clone())) {
                log::error!("[TSS] Failed to forward signed message to session manager: {:?}", e);
            } else {
                log::debug!("[TSS] ✅ Successfully forwarded signed message to session manager");
            }
        }
        Err(_) => {
            log::warn!("[TSS] Failed to decode message from {:?}", sender);
            return Some(());
        }
    }
    
    Some(())
}

// Helper method to process session manager messages
pub fn process_session_manager_message<T: TssMessageHandler + ECDSAMessageRouter>(
    handler: &mut T,
    signed_message: SignedTssMessage
) -> Result<(), String> {
    MessageProcessor::process_session_manager_message(handler, signed_message)
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
                log::debug!("[TSS] Received notification without sender: {:?}", notification.message);
                continue;
            }

            // Correct and concise solution: Use get_mut()
            process_gossip_notification(self.as_mut().get_mut(), notification);
        }

        // Process session manager messages
        while let Poll::Ready(Some(signed_message)) = self.session_manager_to_gossip_rx.poll_next_unpin(cx) {
            if let Err(e) = process_session_manager_message(self.as_mut().get_mut(), signed_message) {
                log::warn!("[TSS] Error processing session manager message: {:?}", e);
            }
        }

        // Check if any channel has closed
        if self.gossip_handler_message_receiver.is_terminated() ||
            self.session_manager_to_gossip_rx.is_terminated() {
            log::error!("[TSS] GossipHandler channel terminated unexpectedly, TSS gossip is shutting down");
            return Poll::Ready(());
        }

        Poll::Pending
    }
}