// pallet/src/runtime_api.rs
#![cfg_attr(not(feature = "std"), no_std)]
use codec::{Decode, Encode};
use sp_std::prelude::*;
use sp_core::sr25519;
use sp_runtime::traits::Block as BlockT;

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
        ) -> Result<<Block as BlockT>::Extrinsic, sp_runtime::RuntimeString>;

        
        fn get_events(
            chain_id: Vec<u8>,
            contract_address: Vec<u8>,
            limit: u32
        ) -> Vec<Vec<u8>>;
        
      
        fn register_relayer(
            relayer: AccountId,
            public_key: sr25519::Public,
            validator_signature: sr25519::Signature
        ) -> <Block as BlockT>::Extrinsic;
        
       
        fn remove_relayer(
            relayer: AccountId,
            validator_signature: sr25519::Signature
        ) -> <Block as BlockT>::Extrinsic;

        
        fn list_relayers() -> Vec<(AccountId, sr25519::Public)>;
        
        
        fn check_relayer_status(
            relayer: AccountId
        ) -> bool;
    }
}