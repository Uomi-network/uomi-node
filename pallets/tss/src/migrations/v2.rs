//! Migration v1 → v2: add `allocated_at: u64` to `PendingNonce`.
//!
//! Prior to this migration, `PendingNonce` had only `{ nonce, status }`. The M-2 security
//! fix added an `allocated_at: u64` field so stuck `Allocated` nonces can be expired in
//! `on_initialize`. Without this migration, existing `NonceStates` entries would fail
//! SCALE decoding against the new struct layout and `ValueQuery` would silently return
//! `Default::default()`, wiping on-chain nonce state.
//!
//! The migration iterates all `NonceStates` entries using a storage alias pointing at the
//! OLD layout, rebuilds each entry with `allocated_at = <current block number>`, and
//! writes it back. Storage version is bumped 0 → 1.

use frame_support::traits::{OnRuntimeUpgrade, GetStorageVersion, Get};
use frame_support::{weights::Weight, storage_alias, Blake2_128Concat, BoundedVec};
use frame_support::pallet_prelude::ValueQuery;
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_std::prelude::*;
use sp_runtime::RuntimeDebug;

use crate::pallet::Pallet;
use crate::types::{MaxPendingNonces, NftId, PendingStatus, NonceState, PendingNonce};

// --- Legacy Types (pre-M-2) ------------------------------------------------

#[derive(RuntimeDebug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct PendingNonceV0 {
    pub nonce: u64,
    pub status: PendingStatus,
}

#[derive(RuntimeDebug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, Default)]
pub struct NonceStateV0 {
    pub last_allocated: Option<u64>,
    pub last_accepted: Option<u64>,
    pub pending: BoundedVec<PendingNonceV0, MaxPendingNonces>,
}

#[storage_alias]
type NonceStatesOld<T: crate::Config> = StorageDoubleMap<
    Pallet<T>,
    Blake2_128Concat, NftId,
    Blake2_128Concat, u32,
    NonceStateV0,
    ValueQuery
>;

// --- Migration -------------------------------------------------------------

pub struct MigrateAddAllocatedAt<T: crate::Config>(core::marker::PhantomData<T>);

impl<T: crate::Config> OnRuntimeUpgrade for MigrateAddAllocatedAt<T> {
    fn on_runtime_upgrade() -> Weight {
        let on_chain = <Pallet<T> as GetStorageVersion>::on_chain_storage_version();
        if on_chain >= 1 {
            log::info!(target: "pallet_tss", "MigrateAddAllocatedAt: already at v{:?}, skipping", on_chain);
            return Weight::zero();
        }

        let current_block: u64 =
            frame_system::Pallet::<T>::block_number().try_into().unwrap_or(0u64);

        let mut reads: u64 = 1; // version read
        let mut writes: u64 = 1; // version write
        let mut migrated: u64 = 0;
        let mut drained: u64 = 0;

        // Drain old layout entries. `drain()` returns (key1, key2, value) and removes the
        // underlying storage after iteration so we can re-insert with the new layout.
        let old_entries: Vec<(NftId, u32, NonceStateV0)> = NonceStatesOld::<T>::drain().collect();
        reads = reads.saturating_add(old_entries.len() as u64);
        drained = old_entries.len() as u64;

        for (nft_id, chain_id, old_state) in old_entries {
            let new_pending_vec: Vec<PendingNonce> = old_state
                .pending
                .into_iter()
                .map(|p| PendingNonce {
                    nonce: p.nonce,
                    status: p.status,
                    allocated_at: current_block,
                })
                .collect();

            // New MaxPendingNonces is >= old, so try_from cannot fail given
            // drained data was bounded by the old limit.
            let new_pending: BoundedVec<PendingNonce, MaxPendingNonces> =
                BoundedVec::try_from(new_pending_vec).unwrap_or_default();

            let new_state = NonceState {
                last_allocated: old_state.last_allocated,
                last_accepted: old_state.last_accepted,
                pending: new_pending,
            };

            crate::pallet::NonceStates::<T>::insert(&nft_id, chain_id, new_state);
            writes = writes.saturating_add(1);
            migrated = migrated.saturating_add(1);
        }

        log::info!(
            target: "pallet_tss",
            "MigrateAddAllocatedAt: drained={} migrated={} allocated_at={} (block)",
            drained, migrated, current_block
        );

        frame_support::traits::StorageVersion::new(1).put::<Pallet<T>>();
        T::DbWeight::get().reads_writes(reads, writes)
    }

    #[cfg(feature = "try-runtime")]
    fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
        let on_chain = <Pallet<T> as GetStorageVersion>::on_chain_storage_version();
        if on_chain >= 1 {
            return Ok(Vec::new());
        }
        let count: u32 = NonceStatesOld::<T>::iter().count() as u32;
        Ok(count.encode())
    }

    #[cfg(feature = "try-runtime")]
    fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
        let on_chain = <Pallet<T> as GetStorageVersion>::on_chain_storage_version();
        if on_chain < 1 {
            return Err(sp_runtime::TryRuntimeError::Other("StorageVersionNotUpdated"));
        }
        if state.is_empty() {
            return Ok(());
        }
        let pre_count = <u32>::decode(&mut &state[..])
            .map_err(|_| sp_runtime::TryRuntimeError::Other("DecodeStateFailed"))?;
        let post_count: u32 = crate::pallet::NonceStates::<T>::iter().count() as u32;
        if post_count < pre_count {
            return Err(sp_runtime::TryRuntimeError::Other("NonceStateEntriesLost"));
        }
        // Legacy map should be fully drained.
        let remaining_old: u32 = NonceStatesOld::<T>::iter().count() as u32;
        if remaining_old > 0 {
            return Err(sp_runtime::TryRuntimeError::Other("LegacyNonceStateNotDrained"));
        }
        Ok(())
    }
}
