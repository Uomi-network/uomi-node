use crate::{
    consts::{MAX_BLOCKS_TO_WAIT_NODE_UPDATE, PALLET_VERSION},
    types::{AiModelKey, BlockNumber, Data, Version},
    {AIModels, Config, NodesVersions, Pallet},
};
use frame_support::pallet_prelude::DispatchError;
use sp_std::collections::btree_map::BTreeMap;

impl<T: Config> Pallet<T> {
    // Aimodelscalc entry point
    pub fn aimodelscalc_run(current_block: BlockNumber) -> Result<BTreeMap<AiModelKey, (Data, Data, BlockNumber)>, DispatchError> {
        let mut aimodelscalc_operations = BTreeMap::<AiModelKey, (Data, Data, BlockNumber)>::new();

        let most_used_version = Self::aimodelscalc_get_most_used_version();
        let local_names_per_versions = Self::aimodelscalc_get_local_names_per_versions();
        let local_names_per_most_used_version = local_names_per_versions.get(&most_used_version).unwrap();

        for (ai_model_key, local_name) in local_names_per_most_used_version {
            let (current_local_name, _previous_local_name, available_from) = AIModels::<T>::get(&ai_model_key);
            if current_local_name == *local_name { // the local name is already set as official name for this ai model, nothing to do
                continue;
            }

            if current_block < available_from { // we will not change the names if the ai model is not available yet
                continue;
            }

            let new_previous_local_name = Some(current_local_name).unwrap_or(local_name.clone());
            aimodelscalc_operations.insert(ai_model_key.clone(), (local_name.clone(), new_previous_local_name, current_block + MAX_BLOCKS_TO_WAIT_NODE_UPDATE));
        }

        Ok(aimodelscalc_operations)
    }

    pub fn aimodelscalc_store_operations(aimodelscalc_operations: BTreeMap<AiModelKey, (Data, Data, BlockNumber)>) -> Result<(), DispatchError> {
        for (key, (local_name, previous_local_name, available_from_block_number)) in aimodelscalc_operations {
            AIModels::<T>::insert(key, (local_name, previous_local_name, available_from_block_number));
        }

        Ok(())
    }

    // IMPORTANT: This algorithm is just a placeholder, it should be replaced by a more complex one
    // The more complex should wait a better percentage of nodes to update their versions (like 80%)
    // To be sure that is not possible to have a downgrade of the version.
    // A downgrade of the version could be a security issue that permits to nodes to not have the requested version at a specific block.
    fn aimodelscalc_get_most_used_version() -> Version {
        // Check NodesVersions has at least one entry, if not return the PALLET_VERSION
        if NodesVersions::<T>::iter().next().is_none() {
            return PALLET_VERSION;
        }

        // Count the number of nodes per version
        let mut counters = BTreeMap::<Version, u32>::new();
        for (_k, v) in NodesVersions::<T>::iter() {
            *counters.entry(v).or_insert(0) += 1;
        }
    
        // Find the version with the most nodes
        let mut max = 0;
        let mut version = PALLET_VERSION;
        for (v, c) in counters {
            if c > max {
                max = c;
                version = v;
            }
        }

        version
    }

    fn aimodelscalc_get_local_names_per_versions() -> BTreeMap<Version, BTreeMap<AiModelKey, Data>> {
        let mut map = BTreeMap::new();
    
        let qwen2_5: Data = b"Qwen/Qwen2.5-32B-Instruct-GPTQ-Int4".to_vec().try_into().unwrap();

        // Version 2
        let mut version_2 = BTreeMap::new();
        version_2.insert(AiModelKey::from(1), qwen2_5.clone());
        map.insert(2 as u32, version_2);
    
        // Free for future releases...
    
        map
    }
}