use frame_support::{
    traits::{Get, OnRuntimeUpgrade, StorageVersion, GetStorageVersion},
    weights::Weight,
    Blake2_128Concat,
};
use sp_std::vec::Vec;
use codec::Encode;

/// La nuova versione del pallet
pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

pub mod v2 {
    use super::*;
    use crate::{Config, pallet::Pallet};

    pub struct Migration<T>(sp_std::marker::PhantomData<T>);

    impl<T: Config> OnRuntimeUpgrade for Migration<T> {
        fn on_runtime_upgrade() -> Weight {
            migrate::<T>()
        }

        #[cfg(feature = "try-runtime")]
        fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
            log::info!("UOMI-ENGINE: Pre-upgrade check for OpocBlacklist migration (v2)");

            #[frame_support::storage_alias]
            pub type OldOpocBlacklist<T: Config> = StorageMap<
                Pallet<T>,
                Blake2_128Concat,
                <T as frame_system::Config>::AccountId,
                bool,
            >;

            let count = OldOpocBlacklist::<T>::iter().count();
            log::info!("UOMI-ENGINE: Found {} entries to remove", count);

            Ok((count as u32).encode())
        }

        #[cfg(feature = "try-runtime")]
        fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
            use codec::Decode;
            let old_count = u32::decode(&mut &state[..])
                .map_err(|_| "Failed to decode pre-upgrade state")?;

            #[frame_support::storage_alias]
            pub type OldOpocBlacklist<T: Config> = StorageMap<
                Pallet<T>,
                Blake2_128Concat,
                <T as frame_system::Config>::AccountId,
                bool,
            >;

            let remaining = OldOpocBlacklist::<T>::iter().count();
            if remaining > 0 {
                return Err("Old storage not fully cleared".into());
            }

            log::info!("UOMI-ENGINE: Cleared {} old entries, storage is clean", old_count);
            Ok(())
        }
    }

    pub fn migrate<T: Config>() -> Weight {
        let onchain_version = Pallet::<T>::on_chain_storage_version();

        if onchain_version >= StorageVersion::new(2) {
            log::info!("UOMI-ENGINE: Migration already applied, skipping");
            return Weight::zero();
        }

        log::info!("UOMI-ENGINE: Starting OpocBlacklist migration to v2");

        #[frame_support::storage_alias]
        pub type OldOpocBlacklist<T: Config> = StorageMap<
            Pallet<T>,
            Blake2_128Concat,
            <T as frame_system::Config>::AccountId,
            bool,
        >;

        // Cancella tutto il vecchio storage
        let removed = OldOpocBlacklist::<T>::clear(u32::MAX, None);
        log::info!("UOMI-ENGINE: Removed {} entries", removed.backend);

        let mut weight = T::DbWeight::get().reads_writes(
            removed.backend as u64,
            removed.backend as u64,
        );

        // Aggiorna la versione del pallet
        STORAGE_VERSION.put::<Pallet<T>>();
        weight = weight.saturating_add(T::DbWeight::get().writes(1));

        log::info!("UOMI-ENGINE: Migration to v2 completed successfully");

        weight
    }
}
