// pallet/src/runtime_api.rs
#![cfg_attr(not(feature = "std"), no_std)]
use codec::{Decode, Encode};
use sp_std::prelude::*;
use crate::RelayerEventInput;
use sp_core::sr25519;

sp_api::decl_runtime_apis! {
    #[api_version(1)]
    pub trait RelayerOrchestrationRuntimeApi<AccountId, Hash> 
    where
        AccountId: Encode + Decode + Clone + 'static,
        Hash: Encode + Decode + Clone + 'static,
    {
        
        fn submit_event(
            relayer: AccountId,
            chain_id: Vec<u8>,
            block_number: u64,
            contract_address: Vec<u8>,
            event_data: Vec<u8>,
            signature: sr25519::Signature
        ) -> Hash;
        
        
        
        fn batch_submit_events(
            relayer: AccountId,
            events: Vec<RelayerEventInput>,
            signature: sr25519::Signature
        ) -> Vec<Hash>;

        
        fn get_events(
            chain_id: Vec<u8>,
            contract_address: Vec<u8>,
            limit: u32
        ) -> Vec<Vec<u8>>;
        
      
        fn register_relayer(
            relayer: AccountId,
            public_key: sr25519::Public,
            validator_signature: sr25519::Signature
        ) -> bool;
        
       
        fn remove_relayer(
            relayer: AccountId,
            validator_signature: sr25519::Signature
        ) -> bool;

        
        fn list_relayers() -> Vec<(AccountId, sr25519::Public)>;
        
        
        fn check_relayer_status(
            relayer: AccountId
        ) -> bool;
        
        
        fn validator_submit_event(
            relayer: AccountId,
            chain_id: Vec<u8>,
            block_number: u64,
            contract_address: Vec<u8>,
            event_data: Vec<u8>,
            validator_signature: sr25519::Signature
        ) -> Hash;
    }
}