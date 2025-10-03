// pallets/ipfs/src/migrations.rs

use super::*;
use crate::pallet::{self, AgentsPins, CidReferenceCount, Config, Pallet, STORAGE_VERSION};
use crate::types::Cid;
use codec::{Decode, Encode};
use frame_support::{
    traits::{Get, OnRuntimeUpgrade, StorageVersion},
    weights::Weight,
};
use sp_std::collections::btree_map::BTreeMap;

#[cfg(feature = "try-runtime")]
use sp_runtime::TryRuntimeError;

/// Migration to initialize CidReferenceCount for all existing AgentsPins
pub struct InitializeCidReferenceCount<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> OnRuntimeUpgrade for InitializeCidReferenceCount<T> {
    fn on_runtime_upgrade() -> Weight {
        let current_version = Pallet::<T>::current_storage_version();
        let onchain_version = Pallet::<T>::on_chain_storage_version();

        log::info!(
            "IPFS Migration: Running migration from version {:?} to {:?}",
            onchain_version,
            current_version
        );

        // Execute only if on-chain version is < 2
        if onchain_version < 2 {
            log::info!("IPFS Migration: Starting CidReferenceCount initialization");

            // Count how many agents use each CID
            let mut cid_counts: BTreeMap<Cid, u32> = BTreeMap::new();
            let mut agent_count = 0u64;

            for (_nft_id, cid) in AgentsPins::<T>::iter() {
                if !cid.is_empty() {
                    *cid_counts.entry(cid).or_insert(0) += 1;
                    agent_count += 1;
                }
            }

            // Insert reference counts
            let mut inserted_count = 0u64;
            for (cid, count) in cid_counts.iter() {
                CidReferenceCount::<T>::insert(cid, *count);
                inserted_count += 1;
                
                log::info!(
                    "IPFS Migration: CID has {} references",
                    count
                );
            }

            log::info!(
                "IPFS Migration: Initialized {} unique CIDs from {} agent pins",
                inserted_count,
                agent_count
            );

            // Update storage version
            STORAGE_VERSION.put::<Pallet<T>>();

            // Calculate weight: 1 read per agent + 1 write per unique CID + version write
            T::DbWeight::get().reads_writes(agent_count + 1, inserted_count + 1)
        } else {
            log::info!("IPFS Migration: Already at version 2 or higher, skipping migration");
            Weight::zero()
        }
    }

    #[cfg(feature = "try-runtime")]
    fn pre_upgrade() -> Result<sp_std::vec::Vec<u8>, TryRuntimeError> {
        use sp_std::collections::btree_set::BTreeSet;

        log::info!("IPFS Migration: Running pre-upgrade checks");

        // Count agents and unique CIDs
        let mut unique_cids: BTreeSet<Cid> = BTreeSet::new();
        let mut agent_count = 0u32;

        for (_nft_id, cid) in AgentsPins::<T>::iter() {
            if !cid.is_empty() {
                unique_cids.insert(cid);
                agent_count += 1;
            }
        }

        log::info!(
            "IPFS Migration: Pre-upgrade found {} agents using {} unique CIDs",
            agent_count,
            unique_cids.len()
        );

        // Store for post-upgrade verification
        Ok((agent_count, unique_cids.len() as u32).encode())
    }

    #[cfg(feature = "try-runtime")]
    fn post_upgrade(state: sp_std::vec::Vec<u8>) -> Result<(), TryRuntimeError> {
        log::info!("IPFS Migration: Running post-upgrade validation");

        let (expected_agents, expected_unique_cids): (u32, u32) =
            Decode::decode(&mut &state[..])
                .map_err(|_| TryRuntimeError::Other("Failed to decode pre-upgrade state"))?;

        // Verify all CIDs have a reference count
        let mut total_refs = 0u32;
        let mut cid_count = 0u32;

        for (_cid, count) in CidReferenceCount::<T>::iter() {
            if count == 0 {
                log::error!("IPFS Migration: Found CID with zero reference count!");
                return Err(TryRuntimeError::Other("CID with zero reference count found"));
            }
            total_refs += count;
            cid_count += 1;
        }

        // Verify totals match
        if total_refs != expected_agents {
            log::error!(
                "IPFS Migration: Reference count mismatch! Expected: {}, Got: {}",
                expected_agents,
                total_refs
            );
            return Err(TryRuntimeError::Other("Reference count mismatch after migration"));
        }

        if cid_count != expected_unique_cids {
            log::error!(
                "IPFS Migration: Unique CID count mismatch! Expected: {}, Got: {}",
                expected_unique_cids,
                cid_count
            );
            return Err(TryRuntimeError::Other("Unique CID count mismatch after migration"));
        }

        // Verify storage version was updated
        let new_version = Pallet::<T>::on_chain_storage_version();
        if new_version < 2 {
            log::error!(
                "IPFS Migration: Storage version not updated! Current: {:?}",
                new_version
            );
            return Err(TryRuntimeError::Other("Storage version not updated"));
        }

        log::info!(
            "IPFS Migration: Successfully validated {} unique CIDs with {} total references",
            cid_count,
            total_refs
        );

        Ok(())
    }
}