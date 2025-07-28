use std::{marker::PhantomData, sync::Arc};
use sp_api::ApiExt;
use codec::Encode;
use sc_client_api::{BlockchainEvents, HeaderBackend};
use sc_transaction_pool_api::{LocalTransactionPool, OffchainTransactionPoolFactory, TransactionPool};
use sp_api::ProvideRuntimeApi;
use sp_keystore::{KeystoreExt, KeystorePtr};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use uomi_runtime::pallet_tss::{TssApi, TssOffenceType};

use crate::types::SessionId;
use super::manager::ClientManager;

pub struct ClientWrapper<B: BlockT, C: BlockchainEvents<B> + ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static, TP> where 
 TP: TransactionPool + LocalTransactionPool<Block = B> + Send + Sync + 'static,
{
    client: Arc<C>,
    phantom: PhantomData<B>,
    keystore: KeystorePtr,
    transaction_pool: Arc<TP>,
}   

impl <B: BlockT, C: BlockchainEvents<B> + ProvideRuntimeApi<B, Api=T> + HeaderBackend<B> + Send + Sync + 'static, T:TssApi<B>, TP> ClientWrapper<B, C, TP> where 
 TP: TransactionPool + LocalTransactionPool<Block = B> + Send + Sync + 'static
 {
    pub fn new(client: Arc<C>, keystore: KeystorePtr, transaction_pool: Arc<TP> ) -> Self {
        Self {
            client,
            phantom: Default::default(),
            keystore,
            transaction_pool
        }
    }
}

impl<B: BlockT, C, TP> ClientManager<B> for ClientWrapper<B, C, TP>
where
    C: BlockchainEvents<B> + ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    C::Api: uomi_runtime::pallet_tss::TssApi<B>,
    TP: TransactionPool + LocalTransactionPool<Block = B> + Send + Sync + 'static,
{
    fn best_hash(&self) -> <<B as BlockT>::Header as HeaderT>::Hash {
        self.client.info().best_hash
    }

    fn report_participants(
        &self,
        hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        inactive_participants: Vec<[u8; 32]>,
    ) -> Result<(), String> {

        let mut runtime = self.client.runtime_api();
        runtime.register_extension(KeystoreExt(self.keystore.clone()));
    
        let otpf = OffchainTransactionPoolFactory::new(self.transaction_pool.clone());
        runtime.register_extension(otpf.offchain_transaction_pool(self.client.info().best_hash));

        runtime
            .report_participants(hash, session_id, inactive_participants)
            .map_err(|e| format!("Failed to report participants: {:?}", e))
    }

    fn submit_dkg_result(
            &self,
            hash: <<B as BlockT>::Header as HeaderT>::Hash,
            session_id: SessionId,
            aggregated_key: Vec<u8>,
        ) -> Result<(), String> {
            let mut runtime = self.client.runtime_api();
            runtime.register_extension(KeystoreExt(self.keystore.clone()));
        
            let otpf = OffchainTransactionPoolFactory::new(self.transaction_pool.clone());
            runtime.register_extension(otpf.offchain_transaction_pool(self.client.info().best_hash));
    
            runtime
                .submit_dkg_result(hash, session_id, aggregated_key)
                .map_err(|e| format!("Failed to submit DKG result: {:?}", e))
    }

    fn report_tss_offence(
        &self,
        hash: <<B as BlockT>::Header as HeaderT>::Hash,
        session_id: SessionId,
        offence_type: TssOffenceType,
        offenders: Vec<[u8; 32]>,
    ) -> Result<(), String> {
        let mut runtime = self.client.runtime_api();
        runtime.register_extension(KeystoreExt(self.keystore.clone()));
    
        let otpf = OffchainTransactionPoolFactory::new(self.transaction_pool.clone());
        runtime.register_extension(otpf.offchain_transaction_pool(self.client.info().best_hash));

        // With the new pallet implementation, report_tss_offence_from_client will handle this
        // by creating a signed payload for an unsigned transaction
        let offence_type_encoded = offence_type.encode();
        
        let _ = runtime
            .report_tss_offence(hash, session_id, offence_type_encoded, offenders)
            .map_err(|e| format!("Failed to report TSS offence: {:?}", e));

        Ok(())
    }
}