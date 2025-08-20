use codec::{Decode, Encode};
use sc_utils::mpsc::{TracingUnboundedSender, TracingUnboundedReceiver, TrySendError};
use sp_keystore::{KeystorePtr};
use sc_network::{PeerId};
use std::{
    collections::btree_map::Keys,
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
    ) -> Self {
        Self {
            gossip_engine,
            peer_mapper,
            gossip_to_session_manager_tx,
            session_manager_to_gossip_rx,
            gossip_handler_message_receiver,
            signing_service: SigningService::new(keystore, validator_public_key),
        }
    }

    /// Create a signed message using the signing service
    fn create_signed_message(&self, message: TssMessage) -> Result<SignedTssMessage, String> {
        self.signing_service.create_signed_message(message)
    }
}
impl<B:BlockT> TssMessageHandler for GossipHandler<B> {
    fn send_signed_message(&mut self, message: TssMessage, peer_id: PeerId) -> Result<(), String> {
        log::info!("[TSS] 📤 GossipHandler CREATING SIGNED P2P MESSAGE: {:?} for peer: {}", 
            std::mem::discriminant(&message), peer_id.to_base58());
        
        let signed_message = self.create_signed_message(message)?;
        
        log::info!("[TSS] 🚀 Sending signed direct message to peer: {}", peer_id.to_base58());
        self.gossip_engine.send_message(vec![peer_id], signed_message.encode());
        Ok(())
    }

    fn broadcast_signed_message(&mut self, message: TssMessage) -> Result<(), String> {
        log::info!("[TSS] 📤 GossipHandler CREATING SIGNED BROADCAST MESSAGE: {:?}", 
            std::mem::discriminant(&message));
        
        let signed_message = self.create_signed_message(message)?;
        
        let topic = <<B::Header as HeaderT>::Hashing as HashT>::hash("tss_topic".as_bytes());
        log::info!("[TSS] 📡 Broadcasting signed message to all peers");
        self.gossip_engine.gossip_message(topic, signed_message.encode(), false);
        Ok(())
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
                match PeerId::from_bytes(&peer_id[..]) {
                    Ok(pid) => {
                        self.peer_mapper
                            .lock()
                            .unwrap()
                            .add_peer(pid, public_key_data);
                    }
                    Err(e) => {
                        log::error!(
                            "[TSS] Invalid peer ID bytes in Announce message: {:?}",
                            e
                        );
                        return;
                    }
                }
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
    fn forward_to_session_manager(&self, signed_message: SignedTssMessage, sender: Option<PeerId>) -> Result<(), TrySendError<(SignedTssMessage, Option<PeerId>)>> {
        self.gossip_to_session_manager_tx.unbounded_send((signed_message, sender))
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
            log::info!("[TSS] 🔄 GossipHandler forwarding SIGNED MESSAGE: {:?} from sender: {:?}", 
                std::mem::discriminant(&signed_message.message),
                sender.to_base58());
            
            // Forward the signed message to session manager
            if let Err(e) = handler.forward_to_session_manager(signed_message, Some(sender.clone())) {
                log::error!("[TSS] Failed to forward signed message to session manager: {:?}", e);
            } else {
                log::info!("[TSS] ✅ Successfully forwarded signed message to session manager");
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
                log::info!("[TSS] Received notification without sender: {:?}", notification.message);
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
            return Poll::Ready(());
        }

        Poll::Pending
    }
}