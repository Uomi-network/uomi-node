use frame_support::traits::{OnRuntimeUpgrade, GetStorageVersion, Get};
use frame_support::{weights::Weight, storage_alias, Blake2_128Concat, BoundedVec};
use frame_support::pallet_prelude::{OptionQuery, ValueQuery};
use crate::pallet::{Pallet, SigningSession};
use ethereum_types::U256;
use codec::{Decode, Encode};
use sp_runtime::RuntimeDebug;
use scale_info::TypeInfo;
use sp_std::prelude::*;
use log; // diagnostics

// --- Legacy Types (v0) -----------------------------------------------------
// Legacy SigningSession (v0) did NOT have request_id and did NOT store chain_id.
// Legacy separate map: nft_id -> (chain_id, message)
// New layout (v1): adds request_id (U256) to SigningSession and new map request_id -> (nft_id, chain_id, message)
#[derive(Decode, Encode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct SigningSessionV0<BoundedMsg, Sig> {
    pub dkg_session_id: u64,            // SessionId alias (u64)
    pub nft_id: crate::types::NftId,
    pub message: BoundedMsg,
    pub state: crate::pallet::SessionState,
    pub aggregated_sig: Option<Sig>,
}

// Storage alias to access old raw values under the same map prefix.
// We only use it when on-chain storage version < 1.
#[storage_alias]
type SigningSessionsOld<T: crate::Config> = StorageMap<
    Pallet<T>,
    Blake2_128Concat,
    crate::types::SessionId,
    SigningSessionV0<
        BoundedVec<u8, crate::types::MaxMessageSize>,
        crate::types::Signature
    >,
    OptionQuery
>;

#[storage_alias]
type NextRequestId<T: crate::Config> = StorageValue<Pallet<T>, u32, ValueQuery>;

#[storage_alias]
type FsaTransactionRequests<T: crate::Config> = StorageMap<
    Pallet<T>,
    Blake2_128Concat,
    U256,
    (crate::types::NftId, u32, BoundedVec<u8, crate::types::MaxMessageSize>),
    OptionQuery
>;

// Legacy map (v0): nft_id -> (chain_id, message)
#[storage_alias]
type FsaTransactionRequestsByNft<T: crate::Config> = StorageMap<
    Pallet<T>,
    Blake2_128Concat,
    crate::types::NftId,
    (u32, BoundedVec<u8, crate::types::MaxMessageSize>),
    OptionQuery
>;

/// Migration 0 -> 1 for pallet_tss.
/// Transforms legacy:
///  * SigningSessions: SessionId -> SigningSessionV0 (no request_id)
///  * FsaTransactionRequestsByNft: nft_id -> (chain_id, message)
/// Into new:
///  * SigningSessions: SessionId -> SigningSession (with request_id)
///  * FsaTransactionRequests: request_id -> (nft_id, chain_id, message)
/// Steps per session:
///  * Take legacy (chain_id, message) by nft_id (if exists)
///  * Allocate request_id (u32 counter -> U256)
///  * Insert new FsaTransactionRequests entry
///  * Remove legacy nft entry (done by take)
///  * Rewrite session with request_id
/// Fallback when missing chain data: chain_id = 4386 (current single supported chain).
pub struct MigrateV0ToV1<T: crate::Config>(core::marker::PhantomData<T>);

// impl<T: crate::Config> OnRuntimeUpgrade for MigrateV0ToV1<T> {
//     fn on_runtime_upgrade() -> Weight {
//         let on_chain = <Pallet<T> as GetStorageVersion>::on_chain_storage_version();
//         if on_chain >= 1 { return Weight::zero(); }

//         let mut reads: u64 = 1; // version read
//         let mut writes: u64 = 1; // version write
//         let mut migrated: u64 = 0;
//     let mut missing_chain: u64 = 0;
//         let mut msg_mismatch: u64 = 0; // unlikely but check if messages diverge

//         let mut next_req = NextRequestId::<T>::get(); reads += 1;

//         for (session_id, old) in SigningSessionsOld::<T>::iter() {
//             reads += 1; // old session

//             let legacy_chain = FsaTransactionRequestsByNft::<T>::take(&old.nft_id);
//             if legacy_chain.is_some() { reads += 1; writes += 1; } // removal write
//             let (chain_id, legacy_message) = legacy_chain.unwrap_or_else(|| { missing_chain += 1; (4386u32, old.message.clone()) });
//             if legacy_message != old.message { msg_mismatch += 1; }

//             let request_id_u32 = next_req; let request_id = U256::from(request_id_u32 as u64); next_req = next_req.saturating_add(1);
//             FsaTransactionRequests::<T>::insert(&request_id, (old.nft_id.clone(), chain_id, old.message.clone())); writes += 1;

//             let new_session = SigningSession { dkg_session_id: old.dkg_session_id, request_id, nft_id: old.nft_id.clone(), message: old.message, state: old.state, aggregated_sig: old.aggregated_sig };
//             crate::pallet::SigningSessions::<T>::insert(session_id, new_session); writes += 1; migrated += 1;
//         }

//         if migrated > 0 { NextRequestId::<T>::put(next_req); writes += 1; }

//     if missing_chain > 0 { log::warn!(target: "pallet_tss", "Migration: {} sessions lacked legacy chain data (chain_id=4386 fallback)", missing_chain); }
//     if msg_mismatch > 0 { log::warn!(target: "pallet_tss", "Migration: {} sessions had message mismatch with legacy map", msg_mismatch); }

//         frame_support::traits::StorageVersion::new(1).put::<Pallet<T>>();
//         T::DbWeight::get().reads_writes(reads, writes)
//     }

//     #[cfg(feature = "try-runtime")]
//     fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
//         use codec::Encode;
//         let on_chain = <Pallet<T> as GetStorageVersion>::on_chain_storage_version();
//         if on_chain >= 1 { return Ok(Vec::new()); }
//     let legacy_sessions: u32 = SigningSessionsOld::<T>::iter().count() as u32;
//     let legacy_fsa: u32 = FsaTransactionRequestsByNft::<T>::iter().count() as u32;
//     let next_req = NextRequestId::<T>::get();
//     Ok((legacy_sessions, legacy_fsa, next_req).encode())
//     }
//     #[cfg(feature = "try-runtime")]
//     fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
//         use codec::Decode;
//         let on_chain = <Pallet<T> as GetStorageVersion>::on_chain_storage_version();
//         if on_chain < 1 { return Err(sp_runtime::TryRuntimeError::Custom("StorageVersionNotUpdated".into())); }
//         if state.is_empty() { return Ok(()); } // nothing to check if we were already v1
//         let (legacy_sessions, legacy_fsa, pre_next_req) = <(u32, u32, u32)>::decode(&mut &state[..])
//             .map_err(|_| sp_runtime::TryRuntimeError::Custom("DecodeStateFailed".into()))?;
//         let new_sessions: u32 = crate::pallet::SigningSessions::<T>::iter().count() as u32;
//         if new_sessions < legacy_sessions { return Err(sp_runtime::TryRuntimeError::Custom("SessionLoss".into())); }
//         if legacy_sessions > 0 {
//             let after_next = NextRequestId::<T>::get();
//             if after_next < pre_next_req + legacy_sessions { return Err(sp_runtime::TryRuntimeError::Custom("NextRequestIdNotAdvanced".into())); }
//         }
//         // Ensure legacy nft keyed map mostly cleared (allowing for missing chain entries).
//         let remaining_legacy = FsaTransactionRequestsByNft::<T>::iter().count() as u32;
//         if remaining_legacy == legacy_fsa && legacy_fsa > 0 { return Err(sp_runtime::TryRuntimeError::Custom("LegacyMapNotConsumed".into())); }
//         Ok(())
//     }
// }
