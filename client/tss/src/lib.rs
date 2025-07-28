use codec::{Decode, Encode, EncodeLike, Error};
use ecdsa::{ECDSAError, ECDSAIndexWrapper, ECDSAManager};
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

use crate::utils::get_validator_key_from_keystore;
use crate::utils::sign_announcment;
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
use sp_core::{sr25519, ByteArray, Pair};
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
    pallet_tss::{TssApi, TssOffenceType},
    AccountId
};

// Import types from the new types module
use types::{
    TssMessage, SignedTssMessage,
    SessionManagerMessage, TSSRuntimeEvent, SessionManagerError, TSSParticipant,
    TSSPeerId, TSSPublic, TSSSignature, SessionData, SessionId, SessionError
};
use session::{
    dkg_state_manager::{DKGStateManager, DKGSessionState}, 
    MessageProcessor, 
    SessionCore, 
    signing_state_manager::{SigningStateManager, SigningSessionState},
    managers::{StorageManager, CommunicationManager, StateManagerGroup, ParticipantManager, AuthenticationManager},
    SessionManager
};
use ecdsa::ECDSAPhase;
use network::PeerMapper;
use validation::TssValidator;
use retry::mechanism::RetryMechanism;
use crate::security::verification;
use gossip::{GossipHandler, TssMessageHandler, ECDSAMessageRouter, process_gossip_notification, process_session_manager_message};
use client::{ClientManager, ClientWrapper};
use runtime::RuntimeEventHandler;
use utils::{empty_hash_map};

mod client;
mod dkg_session;
mod dkghelpers;
mod dkground1;
mod dkground2;
mod dkground3;
mod ecdsa;
mod gossip;
mod network;
mod retry;
mod runtime;
mod session;
mod signing;
mod types;
pub mod utils;
mod validation;
pub mod security;
#[cfg(test)]
mod test_framework;
#[cfg(test)]
mod test_framework_multi_node;

const TSS_PROTOCOL: &str = "/tss/1";
pub use utils::get_config;
    

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

        // Create a signed version of the announcement for the gossip validator
        let signed_announcement = if let Some(ref announcement_msg) = announcement {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            // Create the payload to sign (message + public key + timestamp)
            let mut payload = Vec::new();
            payload.extend_from_slice(&announcement_msg.encode());
            payload.extend_from_slice(&validator_key_clone);
            payload.extend_from_slice(&current_time.to_le_bytes());
            
            // Sign the payload using the keystore
            match keystore_container.keystore().sign_with(
                UOMI,
                sr25519::CRYPTO_ID,
                &validator_key_clone,
                &payload,
            ) {
                Ok(Some(signature_bytes)) => {
                    match signature_bytes.try_into() {
                        Ok(signature) => {
                            log::info!("[TSS] ✅ Created signed announcement for gossip validator");
                            Some(SignedTssMessage {
                                message: announcement_msg.clone(),
                                sender_public_key: validator_key_clone[..32].try_into().unwrap(),
                                signature,
                                timestamp: current_time,
                            })
                        }
                        Err(_) => {
                            log::error!("[TSS] Invalid signature length for signed announcement");
                            None
                        }
                    }
                }
                Ok(None) => {
                    log::error!("[TSS] Failed to get signature from keystore for signed announcement");
                    None
                }
                Err(e) => {
                    log::error!("[TSS] Failed to sign announcement: {:?}", e);
                    None
                }
            }
        } else {
            None
        };

        let gossip_validator = Arc::new(TssValidator::new(Duration::from_secs(120), announcement.clone(), signed_announcement));

        // Set up communication channels
        let (gossip_to_session_manager_tx, gossip_to_session_manager_rx) =
            sc_utils::mpsc::tracing_unbounded::<SignedTssMessage>(
                "gossip_to_session_manager",
                1024,
            );
        let (session_manager_to_gossip_tx, session_manager_to_gossip_rx) =
            sc_utils::mpsc::tracing_unbounded::<SignedTssMessage>(
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

        let validator_public_key_array: [u8; 32] = validator_key[..32].try_into()
            .expect("Validator key should be 32 bytes");

        let mut gossip_handler = GossipHandler::new(
            gossip_engine,
            gossip_to_session_manager_tx,
            session_manager_to_gossip_rx,
            peer_mapper.clone(),
            gossip_handler_message_receiver,
            keystore_container.keystore(),
            validator_public_key_array,
        );

        // Broadcast initial announcement if available
        if let Some(a) = announcement.clone() {
            if let Err(e) = gossip_handler.broadcast_signed_message(a) {
                log::error!("[TSS] Failed to broadcast signed announcement: {:?}", e);
            } else {
                log::info!("[TSS] Signed announcement broadcasted successfully");
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
            validator_public_key_array,
            keystore_container.keystore(),
            peer_mapper.clone(),
            gossip_to_session_manager_rx,
            runtime_to_session_manager_rx,
            session_manager_to_gossip_tx,
            local_peer_id.to_bytes(),
            announcement.clone(),
            ClientWrapper::new(Arc::clone(&client), keystore_container.keystore().clone(), transaction_pool.clone()),
            false, // Enable retry mechanism by default
        );
        
        // Configure session timeout (default is 1 hour, make it 2 hours for production)
        session_manager.session_core.session_timeout = 15; // 2 hours in seconds

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

