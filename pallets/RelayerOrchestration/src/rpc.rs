// pallet/src/rpc.rs
use jsonrpsee::{
    core::{RpcResult, async_trait},
    types::error::ErrorObject,
    proc_macros::rpc,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use codec::{Encode, Decode};
use sp_core::sr25519;
use std::marker::PhantomData;
use sc_transaction_pool_api::TransactionPool;
use sp_runtime::transaction_validity::TransactionSource;

use crate::RelayerOrchestrationRuntimeApi;


impl<C, Block, P> RelayerOrchestration<C, Block, P> {
    pub fn new(client: Arc<C>, pool: Arc<P>) -> Self {
        Self {
            client,
            pool,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<C, Block, AccountId, Hash, P> 
    RelayerOrchestrationApiServer<<Block as BlockT>::Hash, AccountId, Hash>
    for RelayerOrchestration<C, Block, P>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    P: TransactionPool<Block = Block> + 'static,
    C::Api: RelayerOrchestrationRuntimeApi<Block, AccountId, Hash>,
    AccountId: Encode + Decode + Clone + std::fmt::Debug + Send + Sync + 'static,
    Hash: Encode + Decode + Clone + std::fmt::Debug + Send + Sync + 'static,
{
    async fn submit_event(
        &self,
        relayer: AccountId,
        chain_id: Vec<u8>,
        block_number: u64,
        contract_address: Vec<u8>,
        event_data: Vec<u8>,
        signature: sr25519::Signature,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<bool> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);
        log::info!("submit_event: relayer: {:?}, chain_id: {:?}, block_number: {:?}, contract_address: {:?}, event_data: {:?}, signature: {:?}", relayer, chain_id, block_number, contract_address, event_data, signature);

        let extrinsic = api.submit_event(
            at_hash,
            relayer,
            chain_id,
            block_number,
            contract_address,
            event_data,
            signature
        ).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        });

        let extrinsic = match extrinsic {
            Ok(extrinsic) => extrinsic,
            Err(_) => {
                return Ok(false);
            }
        };
        
        let block_hash = self.client.info().best_hash;
        
        match self.pool
            .submit_one(
                block_hash,
                TransactionSource::Local,
                extrinsic.unwrap(),
            ).await {
            Ok(_) => Ok(true),
            Err(e) => {
                log::error!("Error submitting extrinsic: {:?}", e);
                Ok(false)
            }
        }
    }

    fn get_events(
        &self,
        chain_id: Vec<u8>,
        contract_address: Vec<u8>,
        limit: u32,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<Vec<Vec<u8>>> {
        log::info!("get_events: chain_id: {:?}, contract_address: {:?}, limit: {:?}", chain_id, contract_address, limit);
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
    
    async fn register_relayer(
        &self,
        relayer: AccountId,
        public_key: sr25519::Public,
        validator_signature: sr25519::Signature,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<bool> {
        log::info!("register_relayer: relayer: {:?}, public_key: {:?}, validator_signature: {:?}", relayer, public_key, validator_signature);
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);


        let extrinsic = api.register_relayer(
            at_hash,
            relayer,
            public_key,
            validator_signature
        ).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        });

       let extrinsic = match extrinsic {
            Ok(extrinsic) => extrinsic,
            Err(_e) => {
                return Ok(false);
            }
        };
        
        let block_hash = self.client.info().best_hash;
        
        let result = self.pool
			.submit_one(
                block_hash,
				TransactionSource::Local,
				extrinsic,
			).await;

        match result {
            Ok(_) => Ok(true),
            Err(e) => {
                log::error!("Error submitting extrinsic: {:?}", e);
                Ok(false)
            }
        }   
    }
    
    async fn remove_relayer(
        &self,
        relayer: AccountId,
        validator_signature: sr25519::Signature,
        at: Option<<Block as BlockT>::Hash>
    ) -> RpcResult<bool> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);

        let extrinsic= api.remove_relayer(
            at_hash,
            relayer,
            validator_signature
        ).map_err(|e| {
            ErrorObject::owned(1, format!("Runtime error: {:?}", e), None::<()>)
        });

        let extrinsic = match extrinsic {
            Ok(extrinsic) => extrinsic,
            Err(_e) => {
                return Ok(false);
            }
        };
        
        let block_hash = self.client.info().best_hash;
        
        let result = self.pool
			.submit_one(
                block_hash,
				TransactionSource::Local,
				extrinsic,
			).await;

        match result {
            Ok(_) => Ok(true),
            Err(e) => {
                log::error!("Error submitting extrinsic: {:?}", e);
                Ok(false)
            }
        }   
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
    
}

#[rpc(client, server)]
pub trait RelayerOrchestrationApi<BlockHash, AccountId, Hash> {
    #[method(name = "relayer_submitEvent")]
    async fn submit_event(
        &self,
        relayer: AccountId,
        chain_id: Vec<u8>,
        block_number: u64,
        contract_address: Vec<u8>,
        event_data: Vec<u8>,
        signature: sr25519::Signature,
        at: Option<BlockHash>
    ) -> RpcResult<bool>;

    #[method(name = "relayer_getEvents")]
    fn get_events(
        &self,
        chain_id: Vec<u8>,
        contract_address: Vec<u8>,
        limit: u32,
        at: Option<BlockHash>
    ) -> RpcResult<Vec<Vec<u8>>>;
    
    #[method(name = "relayer_register")]
    async fn register_relayer(
        &self,
        relayer: AccountId,
        public_key: sr25519::Public,
        validator_signature: sr25519::Signature,
        at: Option<BlockHash>
    ) -> RpcResult<bool>;
    
    #[method(name = "relayer_remove")]
    async fn remove_relayer(
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

    
}

/// A module that offers the RelayerOrchestrationApi implementation
pub struct RelayerOrchestration<C, Block, P> {
    client: Arc<C>,
    _marker: PhantomData<(Block, P)>,
    pool: Arc<P>,
}