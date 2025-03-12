// pallet/src/rpc.rs
use jsonrpsee::{
    core::RpcResult,
    types::error::ErrorObject,
    proc_macros::rpc,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{traits::Block as BlockT};
use std::sync::Arc;
use codec::{Encode, Decode};
use sp_core::sr25519;

use crate::{RelayerEventInput, RelayerOrchestrationRuntimeApi};


impl<C, Block> RelayerOrchestration<C, Block> {
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            _marker: Default::default(),
        }
    }
}

impl<C, Block, AccountId, Hash> 
    RelayerOrchestrationApiServer<<Block as BlockT>::Hash, AccountId, Hash>
    for RelayerOrchestration<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: RelayerOrchestrationRuntimeApi<Block, AccountId, Hash>,
    AccountId: Encode + Decode + Clone + std::fmt::Debug + Send + Sync + 'static,
    Hash: Encode + Decode + Clone + std::fmt::Debug + Send + Sync + 'static,
{
    fn submit_event(
        &self,
        relayer: AccountId,
        chain_id: Vec<u8>,
        block_number: u64,
        contract_address: Vec<u8>,
        event_data: Vec<u8>,
        signature: sr25519::Signature,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<Hash> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);

        api.submit_event(
            at_hash,
            relayer,
            chain_id,
            block_number,
            contract_address,
            event_data,
            signature
        ).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        })
    }
    
    fn batch_submit_events(
        &self,
        relayer: AccountId,
        events: Vec<RelayerEventInput>,
        signature: sr25519::Signature,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<Vec<Hash>> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);

        api.batch_submit_events(
            at_hash,
            relayer,
            events,
            signature
        ).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        })
    }

    fn get_events(
        &self,
        chain_id: Vec<u8>,
        contract_address: Vec<u8>,
        limit: u32,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<Vec<Vec<u8>>> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);
        
        api.get_events(
            at_hash, 
            chain_id, 
            contract_address, 
            limit
        ).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        })
    }
    
    fn register_relayer(
        &self,
        relayer: AccountId,
        public_key: sr25519::Public,
        validator_signature: sr25519::Signature,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<bool> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);

        api.register_relayer(
            at_hash,
            relayer,
            public_key,
            validator_signature
        ).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        })
    }
    
    fn remove_relayer(
        &self,
        relayer: AccountId,
        validator_signature: sr25519::Signature,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<bool> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);

        api.remove_relayer(
            at_hash,
            relayer,
            validator_signature
        ).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        })
    }
    
    fn list_relayers(
        &self,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<Vec<(AccountId, sr25519::Public)>> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);

        api.list_relayers(at_hash).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        })
    }
    
    fn check_relayer_status(
        &self,
        relayer: AccountId,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<bool> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);

        api.check_relayer_status(
            at_hash,
            relayer
        ).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        })
    }
    
    // Implement the new validator-relayer specific methods
    fn validator_submit_event(
        &self,
        relayer: AccountId,
        chain_id: Vec<u8>,
        block_number: u64,
        contract_address: Vec<u8>,
        event_data: Vec<u8>,
        validator_signature: sr25519::Signature,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<Hash> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);

        api.validator_submit_event(
            at_hash,
            relayer,
            chain_id,
            block_number,
            contract_address,
            event_data,
            validator_signature
        ).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        })
    }
    
}



#[rpc(client, server)]
pub trait RelayerOrchestrationApi<BlockHash, AccountId, Hash> {
    #[method(name = "relayer_submitEvent")]
    fn submit_event(
        &self,
        relayer: AccountId,
        chain_id: Vec<u8>,
        block_number: u64,
        contract_address: Vec<u8>,
        event_data: Vec<u8>,
        signature: sr25519::Signature,
        at: Option<BlockHash>
    ) -> RpcResult<Hash>;
    
    
    #[method(name = "relayer_batchSubmitEvents")]
    fn batch_submit_events(
        &self,
        relayer: AccountId,
        events: Vec<RelayerEventInput>,
        signature: sr25519::Signature,
        at: Option<BlockHash>
    ) -> RpcResult<Vec<Hash>>;

    #[method(name = "relayer_getEvents")]
    fn get_events(
        &self,
        chain_id: Vec<u8>,
        contract_address: Vec<u8>,
        limit: u32,
        at: Option<BlockHash>
    ) -> RpcResult<Vec<Vec<u8>>>;
    
    #[method(name = "relayer_register")]
    fn register_relayer(
        &self,
        relayer: AccountId,
        public_key: sr25519::Public,
        validator_signature: sr25519::Signature,
        at: Option<BlockHash>
    ) -> RpcResult<bool>;
    
    #[method(name = "relayer_remove")]
    fn remove_relayer(
        &self,
        relayer: AccountId,
        validator_signature: sr25519::Signature,
        at: Option<BlockHash>
    ) -> RpcResult<bool>;
    
    #[method(name = "relayer_listRelayers")]
    fn list_relayers(
        &self,
        at: Option<BlockHash>
    ) -> RpcResult<Vec<(AccountId, sr25519::Public)>>;
    
    #[method(name = "relayer_checkStatus")]
    fn check_relayer_status(
        &self,
        relayer: AccountId,
        at: Option<BlockHash>
    ) -> RpcResult<bool>;
    
    // New methods for validator-relayers that use the same key
    #[method(name = "validator_submitEvent")]
    fn validator_submit_event(
        &self,
        relayer: AccountId,
        chain_id: Vec<u8>,
        block_number: u64,
        contract_address: Vec<u8>,
        event_data: Vec<u8>,
        validator_signature: sr25519::Signature,
        at: Option<BlockHash>
    ) -> RpcResult<Hash>;
    
}

/// A module that offers the RelayerOrchestrationApi implementation
pub struct RelayerOrchestration<C, Block> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<Block>,
}