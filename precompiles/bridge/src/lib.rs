#![cfg_attr(not(feature = "std"), no_std)]

use fp_evm::{PrecompileHandle, Log};
use precompile_utils::prelude::*;
use sp_runtime::{DispatchResult, traits::UniqueSaturatedInto};
use frame_support::pallet_prelude::{IsType, StorageMap};
use sp_std::{vec, vec::Vec, convert::TryFrom};
use core::marker::PhantomData;
use sp_core::{H160, U256, H256};
use frame_support::BoundedVec;
use pallet_bridge::pallet::{BridgeTransfer, Config as BridgeConfig};

/// A precompile that exposes bridge functionality between EVM and Substrate.
pub struct BridgePrecompile<R>(PhantomData<R>);

#[precompile_utils::precompile]
impl<R> BridgePrecompile<R>
where
    R: pallet_evm::Config + pallet_bridge::Config,
    R::AccountId: IsType<<R as frame_system::Config>::AccountId> + From<[u8; 32]>,
    <<R as frame_system::Config>::Lookup as sp_runtime::traits::StaticLookup>::Source: From<<R as frame_system::Config>::AccountId>,
{
    /// Send tokens from EVM to Substrate
    /// This function burns ERC20 tokens on the EVM side and mints native tokens on the Substrate side
    #[precompile::public("sendToSubstrate(bytes,address,uint256)")]
    fn send_to_substrate(
        handle: &mut impl PrecompileHandle,
        token_address: Address,
        receiver: UnboundedBytes,
        amount: U256,
    ) -> EvmResult<bool> {
        // Get the caller
        let caller = handle.context().caller;
        
        // Convert amount to u128 (safe since Substrate balances typically use u128)
        if amount > U256::from(u128::MAX) {
            return Err(revert("Amount exceeds maximum value"));
        }
        let amount_u128 = amount.low_u128();
        
        // Convert token_address to BoundedVec
        let token_address_bytes = token_address.as_bytes().to_vec();
        let token_address_bounded = BoundedVec::<u8, <R as BridgeConfig>::MaxDataSize>::try_from(token_address_bytes)
            .map_err(|_| revert("Token address too large"))?;
        
        // Convert caller to BoundedVec
        let sender_bytes = caller.as_bytes().to_vec();
        let sender_bounded = BoundedVec::<u8, <R as BridgeConfig>::MaxDataSize>::try_from(sender_bytes)
            .map_err(|_| revert("Sender address too large"))?;
        
        // Convert receiver from bytes to AccountId
        let receiver_bytes = receiver.as_bytes();
        if receiver_bytes.len() != 32 {
            return Err(revert("Invalid receiver address length"));
        }
        
        let mut account_bytes = [0u8; 32];
        account_bytes.copy_from_slice(receiver_bytes);
        let receiver_account_id: R::AccountId = account_bytes.into();
        
        // Get the source chain ID (EVM chain ID)
        let source_chain_id = handle.context().chain_id.to_string().into_bytes();
        let source_chain_id_bounded = BoundedVec::<u8, <R as BridgeConfig>::MaxDataSize>::try_from(source_chain_id)
            .map_err(|_| revert("Chain ID too large"))?;

        // First, burn the tokens on the EVM side
        // Create the ERC20 burn call data
        // Selector for "burnFrom(address,uint256)"
        let burn_selector = hex_literal::hex!("79cc6790");
        
        // Encode caller address
        let mut encoded_from = [0u8; 32];
        encoded_from[12..32].copy_from_slice(caller.as_bytes());
        
        // Encode amount
        let mut encoded_amount = [0u8; 32];
        amount.to_big_endian(&mut encoded_amount);
        
        // Combine selector and parameters
        let mut call_data = Vec::new();
        call_data.extend_from_slice(&burn_selector);
        call_data.extend_from_slice(&encoded_from);
        call_data.extend_from_slice(&encoded_amount);
        
        // Create gasometer for the call
        let mut gasometer = handle.gasometer();
        
        // Execute the burn call
        // Note: The precompile must have approval to burn tokens
        handle.call(
            token_address,
            None,             // Use default context caller
            call_data,        // Call data with burn function
            U256::zero(),     // No ETH value sent
            false,            // Not a static call
            &mut gasometer,   // Gas management
        )?;
        
        // After burning tokens, invoke the pallet to create the bridge transfer
        let next_nonce = pallet_bridge::NextOutboundNonce::<R>::get();
        
        // Call the pallet to handle the substrate side
        // We use unsigned transactions with signed payload pattern
        let result = pallet_bridge::Pallet::<R>::submit_inbound_transfer_from_evm(
            source_chain_id_bounded,
            token_address_bounded,
            sender_bounded,
            receiver_account_id,
            amount_u128,
            next_nonce,
        );
        
        if let Err(_) = result {
            return Err(revert("Failed to process inbound transfer"));
        }
        
        // Emit an event on the EVM side
        let mut topics = Vec::new();
        // Event signature: TokensBridged(address,bytes,uint256,uint256)
        topics.push(H256::from_slice(&keccak256("TokensBridged(address,bytes,uint256,uint256)")));
        topics.push(H256::from_slice(&[0; 12][..]).as_fixed_bytes().into());
        topics.push(H256::from(next_nonce));
        topics.push(H256::from_low_u64_be(amount_u128 as u64));
        
        let log = Log {
            address: token_address,
            topics,
            data: receiver.into(),
        };
        handle.record_log(log)?;
        
        Ok(true)
    }

    /// Receive tokens from Substrate to EVM
    /// This function is called by the Substrate pallet to mint tokens on the EVM side
    #[precompile::public("receiveFromSubstrate(uint256,address,address,uint256)")]
    fn receive_from_substrate(
        handle: &mut impl PrecompileHandle,
        nonce: U256,
        token_address: Address,
        receiver: Address,
        amount: U256,
    ) -> EvmResult<bool> {
        // Check caller - should only be called via the Substrate pallet
        let caller = handle.context().caller;
        
        // This would be the precompile's own address or a trusted system address
        // You might want to implement an access control mechanism here
        
        // Create ERC20 mint call data
        // Selector for "mint(address,uint256)"
        let mint_selector = hex_literal::hex!("40c10f19");
        
        // Encode receiver address
        let mut encoded_receiver = [0u8; 32];
        encoded_receiver[12..32].copy_from_slice(receiver.as_bytes());
        
        // Encode amount
        let mut encoded_amount = [0u8; 32];
        amount.to_big_endian(&mut encoded_amount);
        
        // Combine selector and parameters
        let mut call_data = Vec::new();
        call_data.extend_from_slice(&mint_selector);
        call_data.extend_from_slice(&encoded_receiver);
        call_data.extend_from_slice(&encoded_amount);
        
        // Create gasometer for the call
        let mut gasometer = handle.gasometer();
        
        // Execute the mint call
        handle.call(
            token_address,
            None,             // Use default context caller
            call_data,        // Call data with mint function
            U256::zero(),     // No ETH value sent
            false,            // Not a static call
            &mut gasometer,   // Gas management
        )?;
        
        // Emit an event on the EVM side
        let mut topics = Vec::new();
        // Event signature: TokensReceived(address,address,uint256,uint256)
        topics.push(H256::from_slice(&keccak256("TokensReceived(address,address,uint256,uint256)")));
        topics.push(H256::from(token_address));
        topics.push(H256::from(receiver));
        topics.push(H256::from(nonce));
        
        let log = Log {
            address: handle.context().address,
            topics,
            data: amount.encode().into(),
        };
        handle.record_log(log)?;
        
        Ok(true)
    }

    /// Get the status of an outbound transfer
    #[precompile::public("getOutboundTransfer(uint256)")]
    fn get_outbound_transfer(
        _handle: &mut impl PrecompileHandle,
        nonce: U256,
    ) -> EvmResult<(UnboundedBytes, U256, U256)> {
        // Convert nonce to u64
        if nonce > U256::from(u64::MAX) {
            return Err(revert("Nonce exceeds maximum value"));
        }
        let nonce_u64 = nonce.low_u64();
        
        // Read the transfer status from the pallet
        if let Some((data, verifications, required)) = pallet_bridge::OutboundTransfers::<R>::get(nonce_u64) {
            Ok((
                data.to_vec().into(),
                U256::from(verifications),
                U256::from(required),
            ))
        } else {
            Err(revert("Transfer not found"))
        }
    }
    
    /// Check if an address is a registered validator
    #[precompile::public("isValidator(address)")]
    fn is_validator(
        _handle: &mut impl PrecompileHandle,
        address: Address,
    ) -> EvmResult<bool> {
        // Convert address to AccountId
        let mut account_bytes = [0u8; 32];
        account_bytes[12..32].copy_from_slice(address.as_bytes());
        let account_id: R::AccountId = account_bytes.into();
        
        // Check if this is a validator
        let is_validator = pallet_bridge::Validators::<R>::contains_key(&account_id);
        
        Ok(is_validator)
    }
}

// Utility functions
fn keccak256(s: &str) -> [u8; 32] {
    use sp_io::hashing::keccak_256;
    keccak_256(s.as_bytes())
}