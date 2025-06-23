// This file is part of Uomi.

// Copyright (C) Uomi.
// SPDX-License-Identifier: GPL-3.0-or-later

// Uomi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Uomi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Uomi. If not, see <http://www.gnu.org/licenses/>.

#![cfg_attr(not(feature = "std"), no_std)]

//! Core Uomi types.
//!
//! These core Uomi types are used by the Uomi, finney and Local runtime.


/// EVM primitives.
pub mod evm;

/// Precompiles
pub mod precompiles;

/// Governance primitives.
pub mod governance;

/// Benchmark primitives
#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarks;

use sp_runtime::{
    generic,
    traits::{BlakeTwo256, IdentifyAccount, Verify},
};
use frame_support::{BoundedVec};


/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = sp_runtime::MultiSignature;
/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;

/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Balance of an account.
pub type Balance = u128;
/// An index to a block.
pub type BlockNumber = u32;
/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;
/// Id used for identifying assets.
///
/// AssetId allocation:
/// [1; 2^32-1]     Custom user assets (permissionless)
/// [2^32; 2^64-1]  Statemine assets (simple map)
/// [2^64; 2^128-1] Ecosystem assets
/// 2^128-1         Relay chain token (KSM)
pub type AssetId = u128;
/// Block type.
pub type Block = sp_runtime::generic::Block<Header, sp_runtime::OpaqueExtrinsic>;
/// Index of a transaction in the chain.
pub type Nonce = u32;

/// Trait for TSS (Threshold Signature Scheme) functionality
/// This allows other pallets to interact with TSS without direct dependencies
pub trait TssInterface<T: frame_system::Config> {
    /// Create a new wallet for an agent
    fn create_agent_wallet(nft_id: sp_core::U256, threshold: u8) -> frame_support::pallet_prelude::DispatchResult;
    
    /// Check if a wallet exists for an agent
    fn agent_wallet_exists(nft_id: sp_core::U256) -> bool;
    
    /// Get wallet address for an agent
    fn get_agent_wallet_address(nft_id: sp_core::U256) -> Option<sp_core::H160>;
}
