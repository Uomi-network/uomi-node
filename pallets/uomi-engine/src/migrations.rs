use frame_support::{
    traits::{Get, OnRuntimeUpgrade, StorageVersion},
    weights::Weight,
    Blake2_128Concat,
};
use sp_std::vec::Vec;

/// The current storage version
pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

pub mod v1 {
    use super::*;
    use crate::{Config, pallet::Pallet};

    /// Migration struct for runtime
    pub struct Migration<T>(sp_std::marker::PhantomData<T>);

    impl<T: Config> OnRuntimeUpgrade for Migration<T> {
        fn on_runtime_upgrade() -> Weight {
            migrate::<T>()
        }

        #[cfg(feature = "try-runtime")]
        fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
            log::info!("UOMI-ENGINE: Pre-upgrade check for OpocBlacklist migration");
            
            // Define old storage structure
            #[frame_support::storage_alias]
            pub type OldOpocBlacklist<T: Config> = StorageMap
                Pallet<T>,
                Blake2_128Concat,
                <T as frame_system::Config>::AccountId,
                bool,
            >;

            let count = OldOpocBlacklist::<T>::iter().count();
            log::info!("UOMI-ENGINE: Found {} entries in old storage", count);
            
            Ok((count as u32).encode())
        }

        #[cfg(feature = "try-runtime")]
        fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
            use codec::Decode;
            
            let old_count = u32::decode(&mut &state[..])
                .map_err(|_| "Failed to decode pre-upgrade state")?;
            
            log::info!("UOMI-ENGINE: Post-upgrade check - removed {} old entries", old_count);
            
            // Verify old storage is empty
            #[frame_support::storage_alias]
            pub type OldOpocBlacklist<T: Config> = StorageMap
                Pallet<T>,
                Blake2_128Concat,
                <T as frame_system::Config>::AccountId,
                bool,
            >;

            let remaining = OldOpocBlacklist::<T>::iter().count();
            if remaining > 0 {
                return Err("Old storage not fully cleared".into());
            }
            
            log::info!("UOMI-ENGINE: Migration verification successful");
            Ok(())
        }
    }

    /// Migrate OpocBlacklist from StorageMap to StorageDoubleMap
    pub fn migrate<T: Config>() -> Weight {
        use frame_support::traits::StorageVersion;
        
        let onchain_version = Pallet::<T>::on_chain_storage_version();
        
        if onchain_version >= 1 {
            log::info!("UOMI-ENGINE: Migration already applied, skipping");
            return Weight::zero();
        }

        log::info!("UOMI-ENGINE: Starting OpocBlacklist migration to v1");
        
        let mut weight = Weight::zero();

        // Define old storage structure
        #[frame_support::storage_alias]
        pub type OldOpocBlacklist<T: Config> = StorageMap
            Pallet<T>,
            Blake2_128Concat,
            <T as frame_system::Config>::AccountId,
            bool,
        >;

        // Count entries for logging
        let old_entries: Vec<_> = OldOpocBlacklist::<T>::iter().collect();
        let count = old_entries.len();
        
        log::info!("UOMI-ENGINE: Found {} entries in old OpocBlacklist storage", count);
        
        // Add read weight for iteration
        weight = weight.saturating_add(T::DbWeight::get().reads(count as u64));

        // Clear all old entries
        let removed = OldOpocBlacklist::<T>::clear(u32::MAX, None);
        
        log::info!("UOMI-ENGINE: Removed {} entries from old OpocBlacklist storage", removed.backend);
        
        // Add write weight for removals
        weight = weight.saturating_add(T::DbWeight::get().writes(removed.backend as u64));

        // Update storage version
        StorageVersion::new(1).put::<Pallet<T>>();
        weight = weight.saturating_add(T::DbWeight::get().writes(1));

        log::info!("UOMI-ENGINE: OpocBlacklist migration to v1 completed successfully");

        weight
    }
}