use sc_network_types::PeerId;
use log;
use crate::types::{TssMessage, SignedTssMessage, SessionId};
use crate::ecdsa::ECDSAPhase;
use super::router::{TssMessageHandler, ECDSAMessageRouter};

/// Handles processing of different TSS message types
pub struct MessageProcessor;

impl MessageProcessor {
    /// Process session manager messages with proper routing and error handling
    pub fn process_session_manager_message<T: TssMessageHandler + ECDSAMessageRouter>(
        handler: &mut T,
        signed_message: SignedTssMessage
    ) -> Result<(), String> {
        let message = signed_message.message;
        
        match message {
            TssMessage::DKGRound1(id, bytes) => {
                Self::handle_dkg_round1(handler, id, bytes)
            }
            
            TssMessage::DKGRound2(id, bytes, recipient_bytes) => {
                Self::handle_dkg_round2(handler, id, bytes, recipient_bytes)
            }
            
            TssMessage::SigningCommitmentP2p(id, bytes, recipient_bytes) => {
                Self::handle_signing_p2p(handler, "SigningCommitment", id, bytes, recipient_bytes)
            }
            
            TssMessage::SigningPackageP2p(id, bytes, recipient_bytes) => {
                Self::handle_signing_p2p(handler, "SigningPackage", id, bytes, recipient_bytes)
            }
            
            TssMessage::SigningShareP2p(id, bytes, recipient_bytes) => {
                Self::handle_signing_p2p(handler, "SigningShare", id, bytes, recipient_bytes)
            }
            
            TssMessage::SigningPackage(id, bytes) => {
                Self::handle_signing_message(handler, "SigningPackage", id, bytes)
            }
            
            TssMessage::SigningCommitment(id, bytes) => {
                Self::handle_signing_message(handler, "SigningCommitment", id, bytes)
            }
            
            TssMessage::SigningShare(id, bytes) => {
                Self::handle_signing_message(handler, "SigningShare", id, bytes)
            }
            
            TssMessage::ECDSAMessageBroadcast(session_id, index, bytes, phase) |
            TssMessage::ECDSAMessageSubset(session_id, index, bytes, phase) => {
                handler.route_ecdsa_message(session_id, index, bytes, phase, None)
            }
            
            TssMessage::ECDSAMessageP2p(session_id, index, peer_id, bytes, phase) => {
                Self::handle_ecdsa_p2p(handler, session_id, index, peer_id, bytes, phase)
            }
            
            TssMessage::GetInfo(_, _) | TssMessage::Announce(_,_,_,_,_) => {
                handler.broadcast_signed_message(message)
            }
            
            TssMessage::ECDSARetryRequest(_, _, _, _) | 
            TssMessage::ECDSARetryResponse(_, _, _, _, _) => {
                handler.broadcast_signed_message(message)
            }
            
            _ => Ok(())
        }
    }

    fn handle_dkg_round1<T: TssMessageHandler>(
        handler: &mut T,
        id: SessionId,
        bytes: Vec<u8>
    ) -> Result<(), String> {
        handler.broadcast_signed_message(TssMessage::DKGRound1(id, bytes))
            .map_err(|e| {
                log::error!("[TSS] Error broadcasting signed TssMessage::DKGRound1 for session_id {:?} with error {:?}", id, e);
                e
            })
    }

    fn handle_dkg_round2<T: TssMessageHandler>(
        handler: &mut T,
        id: SessionId,
        bytes: Vec<u8>,
        recipient_bytes: Vec<u8>
    ) -> Result<(), String> {
    match PeerId::from_bytes(&recipient_bytes[..]) {
            Ok(peer_id) => {
                handler.send_signed_message(TssMessage::DKGRound2(id, bytes, recipient_bytes.clone()), peer_id)
                    .map_err(|e| {
                        log::error!("[TSS] Error sending signed TssMessage::DKGRound2 for session_id {:?}, peer_id {:?} with error {:?}", 
                            id, recipient_bytes, e);
                        e
                    })
            }
            Err(e) => {
                log::error!("[TSS] Invalid peer ID in DKGRound2 message: {:?}", e);
                Err("Invalid Peer Id".to_string())
            }
        }
    }

    fn handle_signing_p2p<T: TssMessageHandler>(
        handler: &mut T,
        message_type: &str,
        id: SessionId,
        bytes: Vec<u8>,
        recipient_bytes: Vec<u8>
    ) -> Result<(), String> {
        match PeerId::from_bytes(&recipient_bytes[..]) {
            Ok(peer_id) => {
                let message = match message_type {
                    "SigningCommitment" => TssMessage::SigningCommitmentP2p(id, bytes, recipient_bytes.clone()),
                    "SigningPackage" => TssMessage::SigningPackageP2p(id, bytes, recipient_bytes.clone()),
                    "SigningShare" => TssMessage::SigningShareP2p(id, bytes, recipient_bytes.clone()),
                    _ => return Err(format!("Unknown signing P2P message type: {}", message_type)),
                };
                
                handler.send_signed_message(message, peer_id)
                    .map_err(|e| {
                        log::error!("[TSS] Error sending signed TssMessage::{} for session_id {:?}, peer_id {:?} with error {:?}", 
                            message_type, id, recipient_bytes, e);
                        e
                    })
            }
            Err(e) => {
                log::error!("[TSS] Invalid peer ID in {} P2P message: {:?}", message_type, e);
                Err("Invalid Peer Id".to_string())
            }
        }
    }

    fn handle_signing_message<T: TssMessageHandler>(
        handler: &mut T,
        message_type: &str,
        id: SessionId,
        bytes: Vec<u8>
    ) -> Result<(), String> {
        log::warn!("[TSS] Broadcasting {} message instead of targeted send - recipient info not available", message_type);
        
        let message = match message_type {
            "SigningPackage" => TssMessage::SigningPackage(id, bytes),
            "SigningCommitment" => TssMessage::SigningCommitment(id, bytes),
            "SigningShare" => TssMessage::SigningShare(id, bytes),
            _ => return Err(format!("Unknown signing message type: {}", message_type)),
        };

        handler.broadcast_signed_message(message)
            .map_err(|e| {
                log::error!("[TSS] Error broadcasting signed TssMessage::{} for session_id {:?} with error {:?}", 
                    message_type, id, e);
                e
            })
    }

    fn handle_ecdsa_p2p<T: ECDSAMessageRouter>(
        handler: &mut T,
        session_id: SessionId,
        index: String,
        peer_id: Vec<u8>,
        bytes: Vec<u8>,
        phase: ECDSAPhase
    ) -> Result<(), String> {
    match PeerId::from_bytes(&peer_id[..]) {
            Ok(recipient_peer) => {
                handler.route_ecdsa_message(session_id, index, bytes, phase, Some(recipient_peer))
            }
            Err(_) => {
                log::error!("[TSS] Invalid peer ID in ECDSAMessageP2p");
                handler.route_ecdsa_message(session_id, index, bytes, phase, None)
            }
        }
    }
}