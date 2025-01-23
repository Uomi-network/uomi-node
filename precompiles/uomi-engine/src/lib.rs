#![cfg_attr(not(feature = "std"), no_std)]

use fp_evm::{PrecompileHandle};
use precompile_utils::prelude::*;
use sp_runtime::DispatchResult;
use frame_support::pallet_prelude::IsType;
use sp_std::vec::Vec;
use core::marker::PhantomData;
use sp_core::{U256, H160};

/// A precompile that exposes `call_agent` function.
pub struct UomiEnginePrecompile<T>(PhantomData<T>);

#[precompile_utils::precompile]
impl<R> UomiEnginePrecompile<R>
where
    R: pallet_evm::Config + pallet_uomi_engine::Config,
    R::AccountId: IsType<sp_core::crypto::AccountId32>,
{
    #[precompile::public("call_agent(uint256,uint256,address,bytes,bytes,uint256,uint256)")]
    fn call_agent(
        handle: &mut impl PrecompileHandle,
        request_id: U256,
        nft_id: U256,
        sender: Address,  // Changed from H160 to Address
        data: UnboundedBytes,
        data_cid: UnboundedBytes,
        min_validators: U256,
        min_blocks: U256,
    ) -> EvmResult<bool> {
        // Get the caller   
        let caller = handle.context().caller;
        
       
        // Convert Address to H160 for internal use
        let sender: H160 = caller.into();

        //check if sender is 0xDB5e49D00321ACC34C76Af6fa02E7D9766b6e0F5
        let agent_address = H160::from_slice(&hex::decode("DB5e49D00321ACC34C76Af6fa02E7D9766b6e0F5").expect("Invalid hex"));

        if sender != agent_address {
            return Err(revert("Only the agent contract can call this function"));
        }
        
        
        //convert data to vec<u8>
        let data_vec: Vec<u8> = data.into();
        let file_cid: Vec<u8> = data_cid.into();

        // Prepare the call to the pallet
        let dispatch_result: DispatchResult = pallet_uomi_engine::Pallet::<R>::run_request(
            request_id,
            sender,
            nft_id,
            data_vec,
            file_cid,
            min_validators,
            min_blocks,
        );
        
        match dispatch_result {
            Ok(_) => Ok(true),
            Err(e) => {
                log::info!("Error executing call_agent: {:?}", e);
                let message: &str = "Error executing call_agent";
                return Err(revert(message))
            }
        }
    }

    #[precompile::public("get_agent_output(uint256)")]
    #[precompile::view]
    fn get_agent_output(
        _: &mut impl PrecompileHandle,
        request_id: U256,
    ) -> EvmResult<(UnboundedBytes, U256, U256)> {
        // Read the value from the storage - it returns the value directly because of ValueQuery
        let (data, total_executions, total_consensus) = pallet_uomi_engine::Outputs::<R>::get(request_id);
        
        let data_vec_u8: Vec<u8> = data.into_inner().to_vec();
        Ok((
            data_vec_u8.into(),
            U256::from(total_executions),
            U256::from(total_consensus)
        ))
    }
}