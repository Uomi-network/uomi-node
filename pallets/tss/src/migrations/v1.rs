use frame_support::traits::{OnRuntimeUpgrade, GetStorageVersion, StorageVersion as _, Get};
use frame_support::{weights::Weight, storage_alias, Blake2_128Concat, BoundedVec};
use frame_support::pallet_prelude::{OptionQuery, ValueQuery};
use crate::pallet::{Pallet, SigningSession};
use sp_core::U256;
use codec::{Decode, Encode};
use sp_runtime::RuntimeDebug;
use scale_info::TypeInfo;
use sp_std::prelude::*;

// --- Legacy Types (v0) -----------------------------------------------------
// Legacy SigningSession (v0) did NOT have request_id but DID store chain_id directly.
// New layout (v1) introduces `request_id: U256` inside SigningSession and moves chain_id
// into separate FsaTransactionRequests map keyed by request_id.
#[derive(Decode, Encode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct SigningSessionV0<BoundedMsg, Sig> {
    pub dkg_session_id: u64,            // SessionId alias (u64)
    pub chain_id: u32,                  // moved out in v1
    pub nft_id: crate::types::NftId,    // same type in v1
    pub message: BoundedMsg,            // unchanged
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

/// Migration 0 -> 1 for pallet_tss.
/// Transforms legacy SigningSession layout (with embedded chain_id, no request_id)
/// into new layout (adds request_id, externalizes chain_id into FsaTransactionRequests).
pub struct MigrateV0ToV1<T: crate::Config>(core::marker::PhantomData<T>);

impl<T: crate::Config> OnRuntimeUpgrade for MigrateV0ToV1<T> {
    fn on_runtime_upgrade() -> Weight {
        let on_chain = <Pallet<T> as GetStorageVersion>::on_chain_storage_version();
        if on_chain >= 1 { return Weight::zero(); }

        let mut reads: u64 = 1; // storage version read
        let mut writes: u64 = 1; // storage version write
        let mut migrated: u64 = 0;

        // Starting point for new request ids.
        let mut next_req = NextRequestId::<T>::get();
        reads += 1; // read next_request_id
    // we will (re)write next_req at end only if we migrated anything

        for (session_id, old) in SigningSessionsOld::<T>::iter() {
            reads += 1; // old entry read
            // Allocate new request id (simple incremental). Use u32 -> U256.
            let request_id_u32 = next_req;
            let request_id = U256::from(request_id_u32 as u64);
            next_req = next_req.saturating_add(1);

            // Insert external FSA transaction request mapping if absent.
            if FsaTransactionRequests::<T>::get(&request_id).is_none() {
                FsaTransactionRequests::<T>::insert(&request_id, (old.nft_id.clone(), old.chain_id, old.message.clone()));
                writes += 1; // FSA map write
            }

            // Build new session (drop chain_id field, add request_id)
            let new_session = SigningSession {
                dkg_session_id: old.dkg_session_id,
                request_id,
                nft_id: old.nft_id.clone(),
                message: old.message,
                state: old.state,
                aggregated_sig: old.aggregated_sig,
            };
            // Overwrite storage key with new layout.
            crate::pallet::SigningSessions::<T>::insert(session_id, new_session);
            writes += 1; // new session write
            migrated += 1;
        }

        // Persist updated next request id if we migrated anything.
        if migrated > 0 { NextRequestId::<T>::put(next_req); writes += 1; }

        // Finally set the new storage version.
        frame_support::traits::StorageVersion::new(1).put::<Pallet<T>>();

        // Weight: rough estimate (reads + writes). For precision, benchmark a custom `on_runtime_upgrade`.
        T::DbWeight::get().reads_writes(reads, writes)
    }

    #[cfg(feature = "try-runtime")]
    fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
        use codec::Encode;
        let on_chain = <Pallet<T> as GetStorageVersion>::on_chain_storage_version();
        if on_chain >= 1 { return Ok(Vec::new()); }
        let legacy_count: u32 = SigningSessionsOld::<T>::iter().count() as u32;
        let next_req = NextRequestId::<T>::get();
        Ok((legacy_count, next_req).encode())
    }
    #[cfg(feature = "try-runtime")]
    fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
        use codec::Decode;
        let on_chain = <Pallet<T> as GetStorageVersion>::on_chain_storage_version();
        if on_chain < 1 { return Err(sp_runtime::TryRuntimeError::Custom("StorageVersionNotUpdated".into())); }
        if state.is_empty() { return Ok(()); } // nothing to check if we were already v1
        let (legacy_count, pre_next_req) = <(u32, u32)>::decode(&mut &state[..])
            .map_err(|_| sp_runtime::TryRuntimeError::Custom("DecodeStateFailed".into()))?;
        let new_count: u32 = crate::pallet::SigningSessions::<T>::iter().count() as u32;
        if new_count < legacy_count { return Err(sp_runtime::TryRuntimeError::Custom("SessionLoss".into())); }
        // If we migrated sessions, next_request_id should have advanced by at least legacy_count
        if legacy_count > 0 {
            let after_next = NextRequestId::<T>::get();
            if after_next < pre_next_req + legacy_count { return Err(sp_runtime::TryRuntimeError::Custom("NextRequestIdNotAdvanced".into())); }
        }
        Ok(())
    }
}
