use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use sc_network::PeerId;
use sp_core::{sr25519, ByteArray};
use sp_io::crypto::sr25519_verify;

use crate::{
    types::{SignedTssMessage, TssMessage, SessionId, TSSPeerId, TSSPublic, SessionManagerError},
    ecdsa::{ECDSAManager, ECDSAIndexWrapper, ECDSAPhase, ECDSAError},
    security::verification,
    session::SessionCore,
    retry::mechanism::RetryMechanism,
    client::ClientManager,
    empty_hash_map,
};

use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use uomi_runtime::pallet_tss::TssOffenceType;

/// Message processor for handling gossip messages in TSS sessions
pub struct MessageProcessor;

impl MessageProcessor {
    /// Main message processing logic extracted from SessionManager
    pub fn handle_gossip_message<B, C>(
        session_manager: &mut crate::SessionManager<B, C>,
        signed_message: SignedTssMessage,
        network_sender_peer_id: Option<PeerId>,
    ) where
        B: sp_runtime::traits::Block,
        C: ClientManager<B>,
    {
        log::info!("[TSS] 📨 SessionManager RECEIVED SIGNED MESSAGE: {:?} from public key: {:?}", 
            std::mem::discriminant(&signed_message.message),
            signed_message.sender_public_key);
        
        // Verify the signature and timestamp
        if !verification::verify_signature(&signed_message) {
            log::warn!("[TSS] Received message with invalid signature");
            return;
        }
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if !verification::is_timestamp_valid(&signed_message, current_time, 300) { // 5 minutes max age
            log::warn!("[TSS] Received message with invalid or old timestamp");
            return;
        }
        
        log::info!("[TSS] ✅ Signed message signature and timestamp verified successfully");
        
        // Extract the inner message and sender info
        let message = signed_message.message.clone();
        let sender_public_key = signed_message.sender_public_key.to_vec();
        
        // Try to find the peer ID from the public key
        let mut peer_mapper = session_manager.session_core.peer_mapper.lock().unwrap();
    let sender_peer_id = peer_mapper.get_peer_id_from_account_id(&sender_public_key).cloned();
        drop(peer_mapper);
        
        let sender_peer_id = match sender_peer_id {
            Some(peer_id) => peer_id,
            None => {
                // Special handling for announcement messages - they introduce new peers
                if let TssMessage::Announce(_nonce, peer_id_bytes, _public_key_data, _signature) = &message {
                    // For announcements, use the peer ID from the message itself
                    match PeerId::from_bytes(&peer_id_bytes[..]) {
                        Ok(peer_id) => {
                            log::info!("[TSS] 🆕 Processing announcement from new peer: {}", peer_id.to_base58());
                            peer_id
                        }
                        Err(_) => {
                            log::error!("[TSS] Cannot create peer ID from announcement message");
                            return;
                        }
                    }
                } else {
                    log::warn!("[TSS] Sender public key not found in peer_mapper: {:?}", sender_public_key);
                    // If we have the sender's real PeerId from the network layer, use it for unknown peer queue
                    if let Some(network_peer_id) = network_sender_peer_id {
                        log::info!("[TSS] Using network-provided PeerId for unknown peer: {}", network_peer_id.to_base58());
                        session_manager.add_unknown_peer_message(network_peer_id.clone(), message.clone());
                        
                        // Send a GetInfo message to identify the sender
                        let get_info_message = TssMessage::GetInfo(session_manager.session_core.validator_key.clone());
                        if let Err(e) = session_manager.send_signed_message(get_info_message) {
                            log::error!("[TSS] Failed to send GetInfo message: {:?}", e);
                        }
                        return;
                    }
                    
                    log::error!("[TSS] No sender PeerId available and public key not found in peer_mapper");
                    return;
                }
            }
        };

        match &message {
            TssMessage::GetInfo(ref _public_key) => {
                // Someone's asking about ourselves, we need to announce ourselves
                log::info!("[TSS] Received GetInfo message from {:?}", sender_peer_id);                
                if let Some(announcement) = session_manager.announcement.clone() {
                    // Send the announcement message to the sender
                    if let Err(e) = session_manager.send_signed_message(announcement) {
                        log::error!("[TSS] Failed to send signed announcement message: {:?}", e);
                    }
                } else {
                    log::warn!("[TSS] Announcement message is None");
                }
            }
            TssMessage::DKGRound1(session_id, ref bytes) => {
                // Check if this session exists or is timed out
                if !session_manager.session_exists(session_id) {
                    log::warn!("[TSS] Received DKGRound1 message for non-existent session {}", session_id);
                    // Buffer the message in case session is created later
                    session_manager.buffer
                        .lock()
                        .unwrap()
                        .entry(*session_id)
                        .or_insert(Vec::new())
                        .push((sender_peer_id.to_bytes(), TssMessage::DKGRound1(*session_id, bytes.clone())));
                    return;
                }
                
                if session_manager.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received DKGRound1 message for timed out session {}", session_id);
                    return;
                }

                // Check if the node is authorized for this session
                if !session_manager.is_authorized_for_session(session_id) {
                    log::warn!("[TSS] Node not authorized for session {}", session_id);
                    return;
                }

                if let Err(error) = session_manager.dkg_handle_round1_message(
                    *session_id,
                    bytes,
                    sender_peer_id,
                ) {
                    match error {
                        SessionManagerError::IdentifierNotFound => {
                            log::debug!("[TSS] Buffering DKGRound1 message for session {} (identifier not found yet)", session_id);
                            session_manager.buffer
                                .lock()
                                .unwrap()
                                .entry(*session_id)
                                .or_insert(Vec::new())
                                .push((sender_peer_id.to_bytes(), TssMessage::DKGRound1(*session_id, bytes.clone())));
                        },
                        _ => {
                            log::error!("[TSS] Error handling DKGRound1 for session {}: {:?}", session_id, error);
                        },
                    }
                } else {
                    session_manager.add_active_participant(session_id, &sender_peer_id);
                }
            }
            TssMessage::DKGRound2(session_id, ref bytes, ref recipient) => {
                // Check if this session exists or is timed out
                if !session_manager.session_exists(session_id) {
                    log::warn!("[TSS] Received DKGRound2 message for non-existent session {}", session_id);
                    return;
                }
                
                if session_manager.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received DKGRound2 message for timed out session {}", session_id);
                    return;
                }

                // Check if the node is authorized for this session
                if !session_manager.is_authorized_for_session(session_id) {
                    log::warn!("[TSS] Node not authorized for session {}", session_id);
                    return;
                }

                log::debug!(
                    "[TSS] TssMessage::DKGRound2({:?}, {:?}, {:?})",
                    session_id,
                    bytes,
                    recipient
                );
                if let Err(error) = session_manager.dkg_handle_round2_message(
                    *session_id,
                    bytes,
                    recipient,
                    sender_peer_id,
                ) {
                    match error {
                        SessionManagerError::Round2SecretPackageNotYetAvailable => {
                            log::debug!("[TSS] Buffering DKGRound2 message for session {} (round 2 not ready yet)", session_id);
                            session_manager.buffer
                                .lock()
                                .unwrap()
                                .entry(*session_id)
                                .or_insert(Vec::new())
                                .push((
                                    sender_peer_id.to_bytes(),
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
                    session_manager.add_active_participant(session_id, &sender_peer_id);
                }
            }
            TssMessage::SigningCommitment(session_id, ref bytes) => {
                // Check if this session exists or is timed out
                if !session_manager.session_exists(session_id) {
                    log::warn!("[TSS] Received SigningCommitment message for non-existent session {}", session_id);
                    return;
                }
                
                if session_manager.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received SigningCommitment message for timed out session {}", session_id);
                    return;
                }

                if let Err(error) = session_manager.signing_handle_commitment(
                    *session_id,
                    bytes,
                    sender_peer_id,
                ) {
                    // only the coordinator is supposed to receive this
                    log::error!("[TSS] Error Handling Signing Commitment for session {}: {:?}", session_id, error);
                } else {
                    session_manager.add_active_participant(session_id, &sender_peer_id);
                }
            }
            TssMessage::SigningShare(session_id, ref bytes) => {
                // Check if this session exists or is timed out
                if !session_manager.session_exists(session_id) {
                    log::warn!("[TSS] Received SigningShare message for non-existent session {}", session_id);
                    return;
                }
                
                if session_manager.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received SigningShare message for timed out session {}", session_id);
                    return;
                }

                // only the coordinator is supposed to receive this
                match session_manager.signing_handle_signature_share(
                    *session_id,
                    bytes,
                    sender_peer_id,
                ) {
                    Err(error) => log::error!("[TSS] Error Handling Signing Share for session {}: {:?}", session_id, error),
                    Ok(_signature) => {
                        session_manager.add_active_participant(session_id, &sender_peer_id);
                    }
                } 
            }

            TssMessage::SigningPackage(session_id, bytes) => {
                // Check if this session exists or is timed out
                if !session_manager.session_exists(session_id) {
                    log::warn!("[TSS] Received SigningPackage message for non-existent session {}", session_id);
                    return;
                }
                
                if session_manager.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received SigningPackage message for timed out session {}", session_id);
                    return;
                }

                // this should be for the participants
                // be careful, if participant is also the coordinator they should not send
                // stuff to themselves.
                if let Err(error) = session_manager.signing_handle_signing_package(
                    *session_id,
                    &bytes,
                    sender_peer_id,
                ) {
                    log::error!("[TSS] Error Handling Signing Package for session {}: {:?}", session_id, error);
                } else {
                    session_manager.add_active_participant(session_id, &sender_peer_id);
                }
            }

            TssMessage::Announce(_nonce, peer_id_bytes, public_key_data, signature) => {
                // Handle the announcement by extracting peer information and adding to peer_mapper
                if let Ok(announcing_peer_id) = PeerId::from_bytes(&peer_id_bytes[..]) {
                    log::info!("[TSS] 📢 Processing signed announcement from peer: {} with public key: {:?}", 
                        announcing_peer_id.to_base58(), 
                        public_key_data);
                    
                    // Verify the inner announcement signature (this is the original sr25519 signature of the announcement)
                    let public_key = &sr25519::Public::from_slice(&&public_key_data[..]).unwrap();
                    let is_valid_signature = {
                        // In test environments, skip signature verification for dummy signatures
                        #[cfg(test)]
                        {
                            if signature == &vec![0u8; 64] {
                                true
                            } else {
                                sr25519_verify(
                                    &signature[..].try_into().unwrap(),
                                    &[&public_key_data[..], &peer_id_bytes[..]].concat(),
                                    public_key,
                                )
                            }
                        }
                        #[cfg(not(test))]
                        {
                            sr25519_verify(
                                &signature[..].try_into().unwrap(),
                                &[&public_key_data[..], &peer_id_bytes[..]].concat(),
                                public_key,
                            )
                        }
                    };
                    
                    if is_valid_signature {
                        // Add the peer to our peer_mapper
                        let mut peer_mapper = session_manager.session_core.peer_mapper.lock().unwrap();
                        peer_mapper.add_peer(announcing_peer_id.clone(), public_key_data.clone());
                        drop(peer_mapper);
                        
                        log::info!("[TSS] ✅ Successfully added peer {} to peer_mapper", announcing_peer_id.to_base58());
                        
                        // Now consume any queued messages for this peer
                        // We need to check both the real peer_id and messages stored by public key
                        let mut messages = session_manager.consume_unknown_peer_queue(announcing_peer_id.clone());
                        let mut messages_by_key = session_manager.consume_unknown_peer_queue_by_public_key(&public_key_data);
                        messages.append(&mut messages_by_key);
                        for queued_message in messages {
                            log::info!("[TSS] 🔄 Processing queued message for newly announced peer: {:?}", 
                                std::mem::discriminant(&queued_message));
                            
                            // Since these messages were received before we knew the sender, 
                            // we need to process them directly without signature verification.
                            // We now know the sender from the announcement, so we can trust the queued messages.
                            session_manager.process_queued_message_directly(queued_message, announcing_peer_id.clone());
                        }
                    } else {
                        log::warn!("[TSS] Invalid announcement signature from peer: {}", announcing_peer_id.to_base58());
                    }
                } else {
                    log::error!("[TSS] Invalid peer ID in announcement message");
                }
            }
            TssMessage::Ping => {
                //  Handle these if needed.  They are likely more relevant to the GossipHandler.
                //  Maybe in the future we might want to implement some explicit request for information to another Peer
            }
            TssMessage::ECDSAMessageBroadcast(_, _, _, _)
            | TssMessage::ECDSAMessageP2p(_, _, _, _, _)
            | TssMessage::ECDSAMessageSubset(_, _, _, _) => {
                //  We use this as utils enum values only in for inner communication. They are handled in the GossipHandler
            }

            TssMessage::ECDSARetryRequest(session_id, phase, round, missing_participants) => {
                log::info!("[TSS] Received retry request for session {} phase {:?} round {}", session_id, phase, round);
                if let Some(msg) = session_manager.retry_mechanism.handle_retry_request(*session_id, phase.clone(), *round, missing_participants.clone(), &session_manager.session_core.peer_mapper) {
                    if let Err(e) = session_manager.send_signed_message(msg) {
                        log::error!("[TSS] Failed to send retry response: {:?}", e);
                    }
                }
            }

            TssMessage::ECDSARetryResponse(session_id, phase, round, sender_index, message_data) => {
                log::info!("[TSS] Received retry response for session {} phase {:?} round {} from {}", 
                    session_id, phase, round, sender_index);
                if let Some(msg) = session_manager.retry_mechanism.handle_retry_response(*session_id, phase.clone(), *round, sender_index.clone(), message_data.clone()) {
                    // Re-inject the message into the system
                    if let Err(e) = session_manager.send_signed_message(msg) {
                        log::error!("[TSS] Failed to re-inject message from retry response: {:?}", e);
                    }
                }
            }

            TssMessage::ECDSAMessageKeygen(session_id, _index, msg)
            | TssMessage::ECDSAMessageReshare(session_id, _index, msg)
            | TssMessage::ECDSAMessageSign(session_id, _index, msg)
            | TssMessage::ECDSAMessageSignOnline(session_id, _index, msg) => {
                // Check if this session exists or is timed out
                if !session_manager.session_exists(session_id) {
                    log::warn!("[TSS] Received ECDSA message for non-existent session {}", session_id);
                    return;
                }
                
                if session_manager.is_session_timed_out(session_id) {
                    log::warn!("[TSS] Received ECDSA message for timed out session {}", session_id);
                    return;
                }
                
                // Check if the node is authorized for this session
                if !session_manager.is_authorized_for_session(session_id) {
                    log::warn!("[TSS] Node not authorized for session {}", session_id);
                    return;
                }

                // Track round start and received message for retry mechanism (if enabled)
                if session_manager.retry_mechanism.is_enabled() {
                    let (phase, participant_index) = match &message {
                        TssMessage::ECDSAMessageKeygen(_, index, _) => (ECDSAPhase::Key, index.clone()),
                        TssMessage::ECDSAMessageReshare(_, index, _) => (ECDSAPhase::Reshare, index.clone()),
                        TssMessage::ECDSAMessageSign(_, index, _) => (ECDSAPhase::Sign, index.clone()),
                        TssMessage::ECDSAMessageSignOnline(_, index, _) => (ECDSAPhase::SignOnline, index.clone()),
                        _ => unreachable!(), // We're in the ECDSA message block
                    };
                    
                    // For now, assume round 0 - this should be extracted from message content in a real implementation
                    let round = 0u8; // TODO: Extract actual round from message content when available
                    
                    session_manager.retry_mechanism.track_round_start(*session_id, phase.clone(), round);
                    session_manager.retry_mechanism.track_received_message(*session_id, phase, round, participant_index);
                }

                // This means we received a message through gossip. This can be handled in multiple ways depending on multiple possibilities
                // 1. We know who we are
                // 2. We know who sent this message (sender)
                // 3. We can handle all the messages in the same loop for the key gen
                let mut manager = session_manager.ecdsa_manager.lock().unwrap();

                // Use message_type to determine which function to call instead of matching on message again
                let (sending_messages, phase) = match message.clone() {
                    TssMessage::ECDSAMessageKeygen(_, index, _) => session_manager
                        .handle_buffer_and_sending_messages_for_keygen(
                            session_id,
                            msg,
                            &mut manager,
                            ECDSAIndexWrapper(index),
                        ),
                    TssMessage::ECDSAMessageSign(_, index, _) => {
                        log::debug!("[TSS] Starting consuming buffer");
                        session_manager.handle_buffer_and_sending_messages_for_sign_offline(
                            session_id,
                            msg,
                            &mut manager,
                            ECDSAIndexWrapper(index),
                        )
                    }
                    TssMessage::ECDSAMessageSignOnline(_, index, _) => session_manager
                        .handle_buffer_and_sending_messages_for_sign_online(
                            session_id,
                            msg,
                            &mut manager,
                            ECDSAIndexWrapper(index),
                        ),
                    _ => (
                        Err(ECDSAError::ECDSAError(
                            crate::ecdsa::GENERIC_ERROR.to_string(), // if this happens there's a bug in the code.
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
                    session_manager.add_active_participant(session_id, &sender_peer_id);
                    
                    // Track that we received a message from this participant
                    let mut peer_mapper = session_manager.session_core.peer_mapper.lock().unwrap();
                    if let Some(sender_index) = peer_mapper.get_id_from_peer_id(session_id, &sender_peer_id) {
                        // For simplicity, assume round 0 for now - in practice you'd need to determine the actual round
                        // from the message content or maintain round state
                        let round = 0;
                        session_manager.retry_mechanism.track_received_message(*session_id, phase.clone(), round, sender_index.to_string());
                        
                        // Trigger retry check for this session/phase/round
                        if let Some(retry_message) = session_manager.retry_mechanism.check_and_request_retries(*session_id, phase.clone(), round, &session_manager.session_core.peer_mapper) {
                            if let Err(e) = session_manager.send_signed_message(retry_message) {
                                log::error!("[TSS] Failed to send retry request: {:?}", e);
                            }
                        }
                    }
                    drop(peer_mapper);
                }
                log::debug!("[TSS] calling handle_ecdsa_sending_messages()");

                session_manager.handle_ecdsa_sending_messages(
                    *session_id,
                    sending_messages.unwrap(),
                    &mut manager,
                    phase,
                );
            }
        }
    }
}