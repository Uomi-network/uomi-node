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

use num_enum::{IntoPrimitive, TryFromPrimitive};
use parity_scale_codec::{Decode, Encode};
use sp_runtime::{DispatchError, ModuleError};

pub const LOG_TARGET: &str = "pallet-chain-extension-assets";

#[repr(u16)]
#[derive(TryFromPrimitive, IntoPrimitive, Decode, Encode)]
pub enum Command {
    Transfer = 0,
    Mint = 1,
    Burn = 2,
    ApproveTransfer = 4,
    TransferApproved = 5,
    BalanceOf = 6,
    TotalSupply = 7,
    Allowance = 8,
    MetadataName = 9,
    MetadataSymbol = 10,
    MetadataDecimals = 11,
    MinimumBalance = 12,
}

#[derive(PartialEq, Eq, Copy, Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum Outcome {
    /// Success
    Success = 0,
    /// Account balance must be greater than or equal to the transfer amount.
    BalanceLow = 1,
    /// The account to alter does not exist.
    NoAccount = 2,
    /// The signing account has no permission to do the operation.
    NoPermission = 3,
    /// The given asset ID is unknown.
    Unknown = 4,
    /// The origin account is frozen.
    Frozen = 5,
    /// The asset ID is already taken.
    InUse = 6,
    /// Invalid witness data given.
    BadWitness = 7,
    /// Minimum balance should be non-zero.
    MinBalanceZero = 8,
    /// Unable to increment the consumer reference counters on the account. Either no provider
    /// reference exists to allow a non-zero balance of a non-self-sufficient asset, or one
    /// fewer then the maximum number of consumers has been reached.
    UnavailableConsumer = 9,
    /// Invalid metadata given.
    BadMetadata = 10,
    /// No approval exists that would allow the transfer.
    Unapproved = 11,
    /// The source account would not survive the transfer and it needs to stay alive.
    WouldDie = 12,
    /// The asset-account already exists.
    AlreadyExists = 13,
    /// The asset-account doesn't have an associated deposit.
    NoDeposit = 14,
    /// The operation would result in funds being burned.
    WouldBurn = 15,
    /// The asset is a live asset and is actively being used. Usually emit for operations such
    /// as `start_destroy` which require the asset to be in a destroying state.
    LiveAsset = 16,
    /// The asset is not live, and likely being destroyed.
    AssetNotLive = 17,
    /// The asset status is not the expected status.
    IncorrectStatus = 18,
    /// The asset should be frozen before the given operation.
    NotFrozen = 19,
    /// Callback action resulted in error
    CallbackFailed = 20,
    /// Unknown error
    RuntimeError = 99,
}

impl From<DispatchError> for Outcome {
    fn from(input: DispatchError) -> Self {
        let error_text = match input {
            DispatchError::Module(ModuleError { message, .. }) => message,
            _ => Some("No module error Info"),
        };
        return match error_text {
            Some("BalanceLow") => Outcome::BalanceLow,
            Some("NoAccount") => Outcome::NoAccount,
            Some("NoPermission") => Outcome::NoPermission,
            Some("Unknown") => Outcome::Unknown,
            Some("Frozen") => Outcome::Frozen,
            Some("InUse") => Outcome::InUse,
            Some("BadWitness") => Outcome::BadWitness,
            Some("MinBalanceZero") => Outcome::MinBalanceZero,
            Some("UnavailableConsumer") => Outcome::UnavailableConsumer,
            Some("BadMetadata") => Outcome::BadMetadata,
            Some("Unapproved") => Outcome::Unapproved,
            Some("WouldDie") => Outcome::WouldDie,
            Some("AlreadyExists") => Outcome::AlreadyExists,
            Some("NoDeposit") => Outcome::NoDeposit,
            Some("WouldBurn") => Outcome::WouldBurn,
            Some("LiveAsset") => Outcome::LiveAsset,
            Some("AssetNotLive") => Outcome::AssetNotLive,
            Some("IncorrectStatus") => Outcome::IncorrectStatus,
            Some("NotFrozen") => Outcome::NotFrozen,
            Some("CallbackFailed") => Outcome::CallbackFailed,
            _ => Outcome::RuntimeError,
        };
    }
}

#[macro_export]
macro_rules! handle_result {
    ($call_result:expr) => {{
        return match $call_result {
            Err(e) => {
                log::trace!(target: LOG_TARGET, "err: {:?}", e);
                let mapped_error = Outcome::from(e);
                Ok(RetVal::Converging(mapped_error as u32))
            }
            Ok(_) => Ok(RetVal::Converging(Outcome::Success as u32)),
        };
    }};
}

#[macro_export]
macro_rules! selector_bytes {
    ($s:expr) => {{
        let hash = blake2_256($s.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }};
}
