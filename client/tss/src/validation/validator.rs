use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use log::info;
use codec::{Compact, Decode, Encode, EncodeLike, Error};

use sc_network::{PeerId, ObservedRole};
use sc_network_gossip::{Validator, ValidatorContext, ValidationResult};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, Hash as HashT};

use crate::types::{TssMessage, SignedTssMessage};
use crate::security::verification;
use sp_runtime::SaturatedConversion;
use std::sync::atomic::{AtomicU64, Ordering};

/// TSS message validator for the gossip network
pub struct TssValidator {
    announcement: Option<TssMessage>,
    signed_announcement: Option<SignedTssMessage>, // Pre-signed announcement
    // Track processed messages with their insert times
    processed_messages: Arc<Mutex<HashMap<Vec<u8>, Instant>>>,
    // How long to keep messages in the cache before expiring them
    message_expiry: Duration,
    // Sent announcements, to avoid double sending
    sent_announcements: Arc<Mutex<HashMap<PeerId, Instant>>>,
    // Maximum message age in blocks (for replay protection)
    max_message_age_blocks: u64,
    // Provider to get current block number
    get_block_number: std::sync::Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl TssValidator {
    /// Create a new TSS validator
    pub fn new(
        message_expiry: Duration,
        announcement: Option<TssMessage>,
        signed_announcement: Option<SignedTssMessage>,
        get_block_number: std::sync::Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            announcement,
            signed_announcement,
            processed_messages: Arc::new(Mutex::new(HashMap::new())),
            message_expiry,
            sent_announcements: Arc::new(Mutex::new(HashMap::new())),
            max_message_age_blocks: 100, // 5 minutes worth of blocks as an approximate upper bound, since 3s block time
            get_block_number,
        }
    }
}

impl<B: BlockT> Validator<B> for TssValidator {
    fn new_peer(
        &self,
        context: &mut dyn ValidatorContext<B>,
        who: &PeerId,
        _role: ObservedRole,
    ) {
        info!("[TSS]: New Peer Connected: {}", who.to_base58());

        // Verify if we already sent an announcement to this peer
        let mut sent_announcements = self.sent_announcements.lock().unwrap();

        if sent_announcements.contains_key(who) {
            log::info!("[TSS]: Already sent announcement to peer {}", who.to_base58());
            return;
        }

        // If we haven't sent an announcement, send it now
        sent_announcements.insert(who.clone(), Instant::now());
        drop(sent_announcements);

        // Send the pre-signed announcement message to the new peer
        if let Some(signed_announcement) = &self.signed_announcement {
            log::info!("[TSS] 📤 Sending SIGNED ANNOUNCEMENT to new peer: {}", who.to_base58());
            context.send_message(
                who,
                signed_announcement.encode(),
            );
        } else {
            log::warn!("[TSS] No pre-signed announcement available for peer: {}", who.to_base58());
        }
    }

    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<B>,
        sender: &PeerId,
        data: &[u8],
    ) -> ValidationResult<B::Hash> {
        info!("[TSS]: Received message from {}", sender.to_base58());

        // Try to decode as SignedTssMessage first
        match SignedTssMessage::decode(&mut &data[..]) {
            Ok(signed_message) => {
                log::info!("[TSS]: ✅ RECEIVED SIGNED MESSAGE from {} - message type: {:?}", 
                    sender.to_base58(), 
                    std::mem::discriminant(&signed_message.message));
                
                // Verify the signature
                if !verification::verify_signature(&signed_message) {
                    log::warn!("[TSS]: Message signature verification failed from {}", sender.to_base58());
                    return ValidationResult::Discard;
                }
                // Check block number to prevent replay attacks
                let current_block = (self.get_block_number)();
                if !verification::is_block_number_valid(&signed_message, current_block, self.max_message_age_blocks) {
                    log::warn!("[TSS]: Message block number invalid or too old from {}", sender.to_base58());
                    return ValidationResult::Discard;
                }

                log::info!("[TSS]: ✅ Verified signed message from {} - signature and block number valid", sender.to_base58());
            }
            Err(_) => {
                log::warn!("[TSS]: Failed to decode message from {}", sender.to_base58());
                return ValidationResult::Discard;
            }
        }

        // Safely modify the processed messages
        let mut processed_messages = self.processed_messages.lock().unwrap();
                
        // Mark the message as processed
        processed_messages.insert(data.to_vec(), Instant::now());
        
        // Cleanup can happen here or in a background task
        let now = Instant::now();
        processed_messages.retain(|_, inserted_at| {
            now.duration_since(*inserted_at) < self.message_expiry
        });
        
        let topic = <<B::Header as HeaderT>::Hashing as HashT>::hash("tss_topic".as_bytes());
        
        ValidationResult::ProcessAndKeep(topic)
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(<B as BlockT>::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_topic, data| {
            let processed_messages = self.processed_messages.lock().unwrap();
            let now = Instant::now();
            if let Some(inserted_at) = processed_messages.get(data) {
                return now.duration_since(*inserted_at) >= self.message_expiry;
            }
            // If we don't recognize the message, expire it to avoid indefinite retention
            true
        })
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, sc_network_gossip::MessageIntent, &<B as BlockT>::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_peer_id, _intent, _topic, _data| {
            // Allow propagation; throttling per-peer is handled by the gossip engine.
            // Replay protection is enforced in `validate`, expiry via `message_expired`.
            true
        })
    }
}