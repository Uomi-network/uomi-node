#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

use fp_evm::{PrecompileHandle};
use precompile_utils::prelude::*;
use sp_runtime::{traits::SaturatedConversion, DispatchResult};
use pallet_evm::AddressMapping;
use sp_std::vec::Vec;
use core::marker::PhantomData;
use sp_core::{U256, H160};

/// A precompile that exposes `call_agent` function.
pub struct UomiEnginePrecompile<T>(PhantomData<T>);

#[precompile_utils::precompile]
impl<R> UomiEnginePrecompile<R>
where
    R: pallet_evm::Config + pallet_uomi_engine::Config,
    R::AddressMapping: AddressMapping<R::AccountId>,
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
        let _ = (handle, request_id, nft_id, sender, data, data_cid, min_validators, min_blocks);
        Err(revert("call_agent requires max_output_tokens and msg.value"))
    }

    #[precompile::public("quote_inference(uint256,uint256,uint256,uint256)")]
    #[precompile::view]
    fn quote_inference(
        _: &mut impl PrecompileHandle,
        nft_id: U256,
        input_size: U256,
        min_validators: U256,
        max_output_tokens: U256,
    ) -> EvmResult<U256> {
        let input_size = u256_to_u32(input_size, "input_size too large")?;
        let max_output_tokens = u256_to_u32(max_output_tokens, "max_output_tokens too large")?;
        let quote = pallet_uomi_engine::Pallet::<R>::quote_inference_for_request_v1(
            nft_id,
            input_size,
            min_validators,
            max_output_tokens,
        ).map_err(|_| revert("Error calculating quote_inference"))?;

        Ok(U256::from(quote))
    }

    #[precompile::public("call_agent(uint256,uint256,address,bytes,bytes,uint256,uint256,uint256)")]
    #[precompile::payable]
    fn call_agent_payable(
        handle: &mut impl PrecompileHandle,
        request_id: U256,
        nft_id: U256,
        sender: Address,
        data: UnboundedBytes,
        data_cid: UnboundedBytes,
        min_validators: U256,
        min_blocks: U256,
        max_output_tokens: U256,
    ) -> EvmResult<bool> {
        let caller = handle.context().caller;
        let user_address: H160 = sender.into();
        let agent_address = H160::from_slice(&hex::decode("Db8434F12f21a678F749cb34E6CE0c168776461c").expect("Invalid hex"));

        if caller != agent_address {
            return Err(revert("Only the agent contract can call this function"));
        }

        let data_vec: Vec<u8> = data.into();
        let file_cid: Vec<u8> = data_cid.into();
        let max_output_tokens = u256_to_u32(max_output_tokens, "max_output_tokens too large")?;
        let required_payment = pallet_uomi_engine::Pallet::<R>::quote_inference_for_request_v1(
            nft_id,
            data_vec.len() as u32,
            min_validators,
            max_output_tokens,
        ).map_err(|_| revert("Error calculating inference payment"))?;

        let paid_amount = u256_to_u128(handle.context().apparent_value, "msg.value too large")?;
        if paid_amount < required_payment {
            return Err(revert("Insufficient inference payment"));
        }

        let payer = R::AddressMapping::into_account_id(user_address);
        let escrow_account = R::AddressMapping::into_account_id(handle.context().address);

        let dispatch_result: DispatchResult = pallet_uomi_engine::Pallet::<R>::run_request_with_payment(
            request_id,
            user_address,
            nft_id,
            data_vec,
            file_cid,
            min_validators,
            min_blocks,
            payer,
            escrow_account,
            paid_amount.saturated_into(),
        );

        match dispatch_result {
            Ok(_) => Ok(true),
            Err(e) => {
                log::info!("Error executing payable call_agent: {:?}", e);
                Err(revert("Error executing call_agent"))
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
    let (data, total_executions, total_consensus, _nft_id) = pallet_uomi_engine::Outputs::<R>::get(request_id);
        
        let data_vec_u8: Vec<u8> = data.into_inner().to_vec();
        Ok((
            data_vec_u8.into(),
            U256::from(total_executions),
            U256::from(total_consensus)
        ))
    }
}

fn u256_to_u32(value: U256, error: &'static str) -> EvmResult<u32> {
    if value > U256::from(u32::MAX) {
        return Err(revert(error));
    }

    Ok(value.low_u32())
}

fn u256_to_u128(value: U256, error: &'static str) -> EvmResult<u128> {
    if value > U256::from(u128::MAX) {
        return Err(revert(error));
    }

    Ok(value.low_u128())
}
