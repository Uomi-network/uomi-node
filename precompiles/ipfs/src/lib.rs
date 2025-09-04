#![cfg_attr(not(feature = "std"), no_std)]

use fp_evm::{ PrecompileHandle };
use precompile_utils::prelude::*;
use sp_runtime::DispatchResult;
use frame_support::{ pallet_prelude::IsType, BoundedVec };
use sp_std::vec::Vec;
use core::marker::PhantomData;
use sp_core::U256;
use pallet_evm::AddressMapping;
use pallet_ipfs::types::MaxCidSize;
use frame_system::pallet_prelude::BlockNumberFor;
use sp_core::H160;

/// A precompile that exposes IPFS functions
pub struct IpfsPrecompile<T>(PhantomData<T>);

#[precompile_utils::precompile]
impl<R> IpfsPrecompile<R>
    where
        R: pallet_evm::Config + pallet_ipfs::Config,
        R::AccountId: IsType<sp_core::crypto::AccountId32>
{
    #[precompile::public("pin_agent(bytes,uint256,uint8)")]
    fn pin_agent(
        handle: &mut impl PrecompileHandle,
        cid: UnboundedBytes,
        nft_id: U256,
        threshold: u8
    ) -> EvmResult<bool> {
       ;
        // Get the caller's EVM address
        let caller = handle.context().caller;
        let caller_account_id = R::AddressMapping::into_account_id(caller);
        let sender: H160 = caller.into();

        //check if sender is 0x61D99C81c841eE0D1A1a5F5EAACc8A8D259741A2
        let agent_address = H160::from_slice(&hex::decode("61D99C81c841eE0D1A1a5F5EAACc8A8D259741A2").expect("Invalid hex"));
     
        if sender != agent_address {
            let message: &str = "Only the ipfs contract can call this function";
           
            return Err(revert(message))
        }


        // Convert CID to Vec<u8>
        let agent_cid: Vec<u8> = cid.into();

        // Try to convert Vec<u8> to BoundedVec
        let bounded_cid: BoundedVec<u8, MaxCidSize> = agent_cid
            .try_into()
            .map_err(|_| revert("CID too long"))?;

        // Prepare the call to the pallet using the converted account ID as origin
        let dispatch_result: DispatchResult = pallet_ipfs::Pallet::<R>::pin_agent(
            frame_system::RawOrigin::Signed(caller_account_id).into(),
            bounded_cid,
            nft_id,
            threshold
        );

        match dispatch_result {
            Ok(_) => Ok(true),
            Err(e) => {
                log::info!("Error executing pin_agent: {:?}", e);
                let message: &str = "Error executing pin_agent";
                return Err(revert(message));
            }
        }
    }

    #[precompile::public("pin_file(bytes,uint256)")]
    fn pin_file(
        handle: &mut impl PrecompileHandle,
        cid: UnboundedBytes,
        duration: U256
    ) -> EvmResult<bool> {
        // Get the caller's EVM address
        let caller = handle.context().caller;
        
        let caller_account_id = R::AddressMapping::into_account_id(caller);
        // Convert Address to H160 for internal use
        let sender: H160 = caller.into();

        //check if sender is 0x61D99C81c841eE0D1A1a5F5EAACc8A8D259741A2
        let agent_address = H160::from_slice(&hex::decode("1734a76d43761555FA2F8E77160a43FB5b97A925").expect("Invalid hex"));
        if sender != agent_address {
            let message: &str = "Only the ipfs contract can call this function";
            return Err(revert(message))
        }

        // Convert CID to Vec<u8>
        let file_cid: Vec<u8> = cid.into();

        // Try to convert Vec<u8> to BoundedVec
        let bounded_cid: BoundedVec<u8, MaxCidSize> = file_cid
            .try_into()
            .map_err(|_| revert("CID too long"))?;

        //convert duration to block number
        let duration_u32: u32 = duration.try_into().map_err(|_| revert("Duration too large"))?;
        let block_number: BlockNumberFor<R> = duration_u32.into();

        // Prepare the call to the pallet using the converted account ID as origin
        let dispatch_result: DispatchResult = pallet_ipfs::Pallet::<R>::pin_file(
            frame_system::RawOrigin::Signed(caller_account_id).into(),
            bounded_cid,
            block_number
        );

        match dispatch_result {
            Ok(_) => Ok(true),
            Err(e) => {
                log::info!("Error executing pin_file: {:?}", e);
                let message: &str = "Error executing pin_file";
                return Err(revert(message));
            }
        }
    }
}
