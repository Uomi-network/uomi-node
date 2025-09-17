#![cfg(test)]
use super::super::session_creator::*; // for methods on SessionManager
use crate::{
    session::{manager::SessionManager, core::SessionCore},
    client::manager::ClientManager,
    dkghelpers::{MemoryStorage, FileStorage, StorageType},
    types::{SessionId, SessionData, TSSParticipant},
    network::PeerMapper,
};
use sp_runtime::{traits::{Block as BlockT, Header as HeaderT}, generic::Block as GenericBlock, OpaqueExtrinsic};
use sp_core::H256;
use std::{sync::{Arc, Mutex}, collections::HashMap};
use frost_ed25519::Identifier;

// Use a standard generic block type that already satisfies required codec/traits
type TestHeader = sp_runtime::generic::Header<u32, sp_runtime::traits::BlakeTwo256>;
type TestBlock = GenericBlock<TestHeader, OpaqueExtrinsic>;

#[derive(Clone)]
struct DummyClient;
impl ClientManager<TestBlock> for DummyClient {
    fn best_hash(&self) -> <TestBlock::Header as HeaderT>::Hash { H256::zero() }
    fn best_number(&self) -> <TestBlock::Header as HeaderT>::Number { 0 }
    fn report_participants(&self, _h: <TestBlock::Header as HeaderT>::Hash, _s: SessionId, _i: Vec<[u8;32]>) -> Result<(), String> { Ok(()) }
    fn submit_dkg_result(&self, _h: <TestBlock::Header as HeaderT>::Hash, _s: SessionId, _k: Vec<u8>) -> Result<(), String> { Ok(()) }
    fn complete_reshare_session(&self, _h: <TestBlock::Header as HeaderT>::Hash, _s: SessionId) -> Result<(), String> { Ok(()) }
    fn report_tss_offence(&self, _h: <TestBlock::Header as HeaderT>::Hash, _s: SessionId, _o: uomi_runtime::pallet_tss::TssOffenceType, _off: Vec<[u8;32]>) -> Result<(), String> { Ok(()) }
}

fn new_manager() -> SessionManager<TestBlock, DummyClient> {
    use crate::session::{dkg_state_manager::DKGSessionState, signing_state_manager::SigningSessionState, managers::{StorageManager, CommunicationManager, StateManagerGroup, ParticipantManager, AuthenticationManager}};
    use sc_utils::mpsc::tracing_unbounded;
    let storage = Arc::new(Mutex::new(MemoryStorage::new()));
    let key_storage = Arc::new(Mutex::new(FileStorage::in_memory()));
    let sessions_participants = Arc::new(Mutex::new(HashMap::<SessionId, HashMap<Identifier, [u8;32]>>::new()));
    let sessions_data = Arc::new(Mutex::new(HashMap::<SessionId, SessionData>::new()));
    let dkg_states = Arc::new(Mutex::new(HashMap::<SessionId, DKGSessionState>::new()));
    let signing_states = Arc::new(Mutex::new(HashMap::<SessionId, SigningSessionState>::new()));
    let peer_mapper = Arc::new(Mutex::new(PeerMapper::new()));
    let (tx_gossip, rx_gossip) = tracing_unbounded();
    let (tx_runtime, rx_runtime) = tracing_unbounded();
    let (tx_out, _rx_out) = tracing_unbounded();
    SessionManager::new(
        storage,
        key_storage,
        sessions_participants,
        sessions_data,
        dkg_states,
        signing_states,
        [1u8;32],
        [2u8;32],
        Arc::new(sp_keystore::testing::MemoryKeystore::new()) as sp_keystore::KeystorePtr,
        peer_mapper,
        rx_gossip,
        rx_runtime,
        tx_out,
        [3u8;32],
        None,
        DummyClient,
        false,
    )
}

fn setup_session(sm: &SessionManager<TestBlock, DummyClient>, dkg_id: SessionId, signing_id: SessionId, t: u16, n: u16, participants: Vec<[u8;32]>) {
    // Insert session data (message can be empty)
    sm.add_session_data(dkg_id, t, n, [0u8;32], participants.clone(), vec![]).unwrap();
    sm.add_session_data(signing_id, t, n, [0u8;32], participants.clone(), vec![0x11]).unwrap();
    // Create peer mapper mapping
    let mut pm = sm.session_core.peer_mapper.lock().unwrap();
    pm.create_session(dkg_id, participants.iter().map(|pk| pk.clone()).collect());
    pm.create_session(signing_id, participants.iter().map(|pk| pk.clone()).collect());
    for (i, pk) in participants.iter().enumerate() { pm.set_validator_id(pk.clone(), (i as u32)+1); }
}

#[test]
fn fallback_queues_online_then_drains() {
    let sm = new_manager();
    let dkg_id: SessionId = 42; let signing_id: SessionId = 4242; let participants = vec![[10u8;32],[11u8;32],[12u8;32]]; setup_session(&sm, dkg_id, signing_id, 2, 3, participants.clone());
    // Pretend keygen keys exist but offline output not yet
    {
        let identifier: Identifier = 1u16.try_into().unwrap();
        let ks = sm.storage_manager.key_storage.lock().unwrap();
        ks.write_data(dkg_id, StorageType::EcdsaKeys, identifier.serialize(), b"{\"pubkey\":{\"pk\":[\"0x01\",\"0x02\"]}}".to_vec()).unwrap();
    }
    sm.ecdsa_create_sign_phase(signing_id, dkg_id, participants.iter().map(|p| p.to_vec()).collect(), vec![0xaa]);
    // Expect queued (no sign_online yet)
    {
        let mgr = sm.ecdsa_manager.lock().unwrap();
        assert!(mgr.signs_online.is_empty());
        assert!(!mgr.signs.is_empty()); // offline started
    }
    assert!(sm.pending_sign_online_after_offline.lock().unwrap().get(&signing_id).is_some());
    // Simulate offline success
    sm.handle_sign_offline_success(dkg_id, "{\"r\":\"00\",\"s\":\"00\"}".into());
    // Now online phase should exist (created via drain)
    {
        let mgr = sm.ecdsa_manager.lock().unwrap();
        assert!(!mgr.signs_online.is_empty(), "sign_online phase not created after offline success");
    }
    assert!(sm.pending_sign_online_after_offline.lock().unwrap().get(&signing_id).is_none());
}

#[test]
fn multiple_online_requests_collapsed() {
    let sm = new_manager();
    let dkg_id: SessionId = 7; let signing_id: SessionId = 700; let participants = vec![[21u8;32],[22u8;32],[23u8;32]]; setup_session(&sm, dkg_id, signing_id, 2, 3, participants.clone());
    {
        let identifier: Identifier = 1u16.try_into().unwrap();
        let ks = sm.storage_manager.key_storage.lock().unwrap();
        ks.write_data(dkg_id, StorageType::EcdsaKeys, identifier.serialize(), b"{\"pubkey\":{\"pk\":[\"0x01\",\"0x02\"]}}".to_vec()).unwrap();
    }
    sm.ecdsa_create_sign_phase(signing_id, dkg_id, participants.iter().map(|p| p.to_vec()).collect(), vec![0x01]);
    sm.ecdsa_create_sign_phase(signing_id, dkg_id, participants.iter().map(|p| p.to_vec()).collect(), vec![0x02]);
    let queued = sm.pending_sign_online_after_offline.lock().unwrap().get(&signing_id).cloned().unwrap();
    assert_eq!(queued.len(), 2, "Expected two queued online requests");
    sm.handle_sign_offline_success(dkg_id, "{\"r\":\"00\",\"s\":\"00\"}".into());
    let mgr = sm.ecdsa_manager.lock().unwrap();
    assert!(!mgr.signs_online.is_empty());
}

#[test]
fn no_fallback_when_offline_present() {
    let sm = new_manager();
    let dkg_id: SessionId = 9; let signing_id: SessionId = 900; let participants = vec![[31u8;32],[32u8;32],[33u8;32]]; setup_session(&sm, dkg_id, signing_id, 2, 3, participants.clone());
    // Insert both keygen keys and offline output
    {
        let identifier: Identifier = 1u16.try_into().unwrap();
        let ks = sm.storage_manager.key_storage.lock().unwrap();
        ks.write_data(dkg_id, StorageType::EcdsaKeys, identifier.serialize(), b"{\"pubkey\":{\"pk\":[\"0x01\",\"0x02\"]}}".to_vec()).unwrap();
        ks.write_data(dkg_id, StorageType::EcdsaOfflineOutput, identifier.serialize(), b"{\"r\":\"00\",\"s\":\"00\"}".to_vec()).unwrap();
    }
    sm.ecdsa_create_sign_phase(signing_id, dkg_id, participants.iter().map(|p| p.to_vec()).collect(), vec![0x55]);
    assert!(sm.pending_sign_online_after_offline.lock().unwrap().get(&signing_id).is_none(), "Queue unexpectedly populated when offline output existed");
    let mgr = sm.ecdsa_manager.lock().unwrap();
    assert!(!mgr.signs_online.is_empty(), "sign_online not created directly");
}
