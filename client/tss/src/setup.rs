use codec::{Decode, Encode, EncodeLike, Error};
use multi_party_ecdsa::communication::sending_messages::SendingMessages;
use rand::prelude::*;
use sc_transaction_pool_api::{LocalTransactionPool, OffchainTransactionPoolFactory};
use substrate_prometheus_endpoint::Registry;
use sp_keystore::{KeystoreExt, KeystorePtr};
use std::{
    collections::{HashMap},
    fmt::Debug,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, Mutex},
    thread::sleep, time::Duration,
};

use crate::utils::get_validator_key_from_keystore;
use crate::utils::sign_announcment;
use crate::dkghelpers::{FileStorage, MemoryStorage};
use frame_support::Parameter;
use frost_ed25519::Identifier;
use futures::{channel::mpsc::Receiver, prelude::*};
use log::info;
use sc_service::{KeystoreContainer, TransactionPool};
use sp_core::{sr25519, ByteArray};
use sc_client_api::{BlockchainEvents, HeaderBackend};
use sc_network::{
    NetworkSigner, NetworkStateInfo, NotificationService, PeerId, ProtocolName
};
use sc_network_gossip::{
    GossipEngine, Network, Syncing, TopicNotification,
};
use sc_utils::mpsc::TracingUnboundedReceiver;
use sp_api::{ProvideRuntimeApi};
use sp_core::crypto::Ss58AddressFormat;
use std::option::Option;
use sp_runtime::app_crypto::Ss58Codec;
use uomi_runtime::pallet_uomi_engine::crypto::CRYPTO_KEY_TYPE as UOMI;
use sp_runtime::traits::Member;
use sp_runtime::{
    traits::{Block as BlockT, Hash as HashT, Header as HeaderT},
};

use uomi_runtime::AccountId;

use crate::types::{
    TssMessage, SignedTssMessage,
    TSSRuntimeEvent, TSSPublic, SessionData, SessionId
};
use crate::session::{
    dkg_state_manager::{DKGStateManager, DKGSessionState}, 
    signing_state_manager::{SigningStateManager, SigningSessionState},
    SessionManager
};
use crate::network::PeerMapper;
use crate::validation::TssValidator;
use crate::gossip::GossipHandler;
use crate::client::ClientWrapper;
use crate::runtime::RuntimeEventHandler;
use crate::gossip::router::TssMessageHandler;

fn wait_for_validator_key(keystore_container: &KeystoreContainer) -> Vec<u8> {
    while get_validator_key_from_keystore(keystore_container).is_none() {
        log::warn!("[TSS] No validator key found in keystore. Waiting for key");
        sleep(Duration::from_secs(30));
    }
    
    let validator_key = get_validator_key_from_keystore(keystore_container);
    validator_key.unwrap().0.to_vec()
}

fn create_announcement_message(
    keystore_container: &KeystoreContainer,
    validator_key: &[u8],
    local_peer_id: &PeerId,
    rng: &mut ThreadRng,
) -> Option<TssMessage> {
    // Generate nonce first so it can be included in the signature payload
    let nonce: u16 = rng.gen();
    if let Some(signature) = sign_announcment(
        keystore_container,
        validator_key,
        &local_peer_id.to_bytes()[..],
        nonce,
    ) {
        let announcement = TssMessage::Announce(
            nonce,
            local_peer_id.to_bytes(),
            validator_key.to_vec(),
            signature,
        );
        Some(announcement)
    } else {
        log::warn!("[TSS] Failed to sign announcement message");
        None
    }
}

fn create_signed_announcement(
    announcement: &Option<TssMessage>,
    keystore_container: &KeystoreContainer,
    validator_key: &[u8],
) -> Option<SignedTssMessage> {
    let announcement_msg = announcement.as_ref()?;
    
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let mut payload = Vec::new();
    payload.extend_from_slice(&announcement_msg.encode());
    payload.extend_from_slice(validator_key);
    payload.extend_from_slice(&current_time.to_le_bytes());
    
    match keystore_container.keystore().sign_with(
        UOMI,
        sr25519::CRYPTO_ID,
        validator_key,
        &payload,
    ) {
        Ok(Some(signature_bytes)) => {
            match signature_bytes.try_into() {
                Ok(signature) => {
                    log::info!("[TSS] ✅ Created signed announcement for gossip validator");
                    Some(SignedTssMessage {
                        message: announcement_msg.clone(),
                        sender_public_key: validator_key[..32].try_into().unwrap(),
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
}

fn setup_communication_channels() -> (
    sc_utils::mpsc::TracingUnboundedSender<(SignedTssMessage, Option<PeerId>)>,
    TracingUnboundedReceiver<(SignedTssMessage, Option<PeerId>)>,
    sc_utils::mpsc::TracingUnboundedSender<SignedTssMessage>,
    TracingUnboundedReceiver<SignedTssMessage>,
    sc_utils::mpsc::TracingUnboundedSender<TSSRuntimeEvent>,
    TracingUnboundedReceiver<TSSRuntimeEvent>,
) {
    let (gossip_to_session_manager_tx, gossip_to_session_manager_rx) =
    sc_utils::mpsc::tracing_unbounded::<(SignedTssMessage, Option<PeerId>)>(
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

    (
        gossip_to_session_manager_tx,
        gossip_to_session_manager_rx,
        session_manager_to_gossip_tx,
        session_manager_to_gossip_rx,
        runtime_to_session_manager_tx,
        runtime_to_session_manager_rx,
    )
}

fn initialize_shared_state() -> (
    Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    Arc<Mutex<HashMap<SessionId, SessionData>>>,
    Arc<Mutex<HashMap<SessionId, DKGSessionState>>>,
    Arc<Mutex<HashMap<SessionId, SigningSessionState>>>,
    Arc<Mutex<MemoryStorage>>,
    Arc<Mutex<FileStorage>>,
) {
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

    (
        sessions_participants,
        sessions_data,
        dkg_session_states,
        signing_session_states,
        storage,
        key_storage,
    )
}

fn setup_peer_mapper(
    sessions_participants: Arc<Mutex<HashMap<SessionId, HashMap<Identifier, TSSPublic>>>>,
    local_peer_id: &PeerId,
    validator_key: &[u8],
) -> Arc<Mutex<PeerMapper>> {
    let peer_mapper = Arc::new(Mutex::new(PeerMapper::new(sessions_participants)));
    {
        let mut handle = peer_mapper.lock().unwrap();
        handle.add_peer(local_peer_id.clone(), validator_key.to_vec());
    }

    log::info!(
        "[TSS] Local peer ID: {:?}",
        local_peer_id.to_base58()
    );

    peer_mapper
}

fn create_gossip_handler<B, N, S>(
    network: N,
    sync: S,
    notification_service: Box<dyn NotificationService>,
    protocol_name: ProtocolName,
    gossip_validator: Arc<TssValidator>,
    registry: Option<&Registry>,
    gossip_to_session_manager_tx: sc_utils::mpsc::TracingUnboundedSender<(SignedTssMessage, Option<PeerId>)>,
    session_manager_to_gossip_rx: TracingUnboundedReceiver<SignedTssMessage>,
    peer_mapper: Arc<Mutex<PeerMapper>>,
    keystore: KeystorePtr,
    validator_public_key_array: [u8; 32],
) -> GossipHandler<B>
where
    B: BlockT,
    N: Network<B> + Clone + Send + Sync + 'static + NetworkStateInfo + NetworkSigner,
    S: Syncing<B> + Clone + Send + 'static,
{
    let mut gossip_engine = GossipEngine::new(
        network.clone(),
        sync,
        notification_service,
        protocol_name.clone(),
        gossip_validator,
        registry,
    );

    let topic = <<B::Header as HeaderT>::Hashing as HashT>::hash("tss_topic".as_bytes());
    let gossip_handler_message_receiver: Receiver<TopicNotification> =
        gossip_engine.messages_for(topic);

    GossipHandler::new(
        gossip_engine,
        gossip_to_session_manager_tx,
        session_manager_to_gossip_rx,
        peer_mapper,
        gossip_handler_message_receiver,
        keystore,
        validator_public_key_array,
    )
}

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
    TP: TransactionPool<Block = B> + LocalTransactionPool<Block = B> + Send + Sync + 'static,
    RE: EncodeLike + Eq + Debug + Parameter + Sync + Send + Member,
{
    let mut rng = rand::thread_rng();

    let setup_gossip_pin = move || {
        let client = Arc::clone(&client);
        
        // Wait for validator key and extract it
        let validator_key = wait_for_validator_key(&keystore_container);
        let validator_key_clone = validator_key.clone();
        let local_peer_id = network.local_peer_id();

        info!(
            "[TSS] My Validator key is {:}",
            AccountId::from_slice(&validator_key_clone)
                .unwrap()
                .to_ss58check_with_version(Ss58AddressFormat::custom(87))
        );
        
        // Create announcement messages
        let announcement = create_announcement_message(
            &keystore_container,
            &validator_key,
            &local_peer_id,
            &mut rng,
        );
        
        let signed_announcement = create_signed_announcement(
            &announcement,
            &keystore_container,
            &validator_key_clone,
        );

        let gossip_validator = Arc::new(TssValidator::new(
            Duration::from_secs(120),
            announcement.clone(),
            signed_announcement,
        ));

        // Set up communication channels
        let (
            gossip_to_session_manager_tx,
            gossip_to_session_manager_rx,
            session_manager_to_gossip_tx,
            session_manager_to_gossip_rx,
            runtime_to_session_manager_tx,
            runtime_to_session_manager_rx,
        ) = setup_communication_channels();

        // Initialize shared state
        let (
            sessions_participants,
            sessions_data,
            dkg_session_states,
            signing_session_states,
            storage,
            key_storage,
        ) = initialize_shared_state();

        // Set up peer mapping
        let peer_mapper = setup_peer_mapper(
            sessions_participants.clone(),
            &local_peer_id,
            &validator_key,
        );

        let validator_public_key_array: [u8; 32] = validator_key[..32].try_into()
            .expect("Validator key should be 32 bytes");

        // Create gossip handler
        let mut gossip_handler = create_gossip_handler::<B, _, _>(
            network.clone(),
            sync,
            notification_service,
            protocol_name.clone(),
            gossip_validator,
            registry.as_ref(),
            gossip_to_session_manager_tx,
            session_manager_to_gossip_rx,
            peer_mapper.clone(),
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
        
        // Create runtime event handler
        let runtime_event_handler =
            RuntimeEventHandler::<B, C>::new(client.clone(), runtime_to_session_manager_tx);

        // Create session manager
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
            false,
        );
        
        // Configure session timeout
        session_manager.session_core.session_timeout = 3600;

        // Start the components
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