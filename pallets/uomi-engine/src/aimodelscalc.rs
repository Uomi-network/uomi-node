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
        let temp2_5: Data = b"Temp2.5/Temp".to_vec().try_into().unwrap();
        let mistral_24b: Data = b"casperhansen/mistral-small-24b-instruct-2501-awq".to_vec().try_into().unwrap();
        let qwen_qwq_32b: Data = b"Qwen/QwQ-32B-AWQ".to_vec().try_into().unwrap();
        let dobby3_1_8b: Data = b"SentientAGI/Dobby-Mini-Unhinged-Llama-3.1-8B".to_vec().try_into().unwrap();
        let sana_1600m: Data = b"Efficient-Large-Model/Sana_1600M_1024px_BF16_diffusers".to_vec().try_into().unwrap();
        let qwen_deepseek_thinking: Data = b"deepseek-ai/DeepSeek-R1-0528-Qwen3-8B".to_vec().try_into().unwrap();
        let qwen_deepseek_non_thinking: Data = b"deepseek-ai/DeepSeek-R1-0528-Qwen3-8B".to_vec().try_into().unwrap();

        let mut version_2 = BTreeMap::new();
        version_2.insert(AiModelKey::from(1), qwen2_5.clone());
        map.insert(2 as u32, version_2);

        let mut version_3 = BTreeMap::new();
        version_3.insert(AiModelKey::from(1), temp2_5.clone());
        map.insert(3 as u32, version_3);

        let mut version_4 = BTreeMap::new();
        version_4.insert(AiModelKey::from(1), qwen2_5.clone());
        map.insert(4 as u32, version_4);

        let mut version_5 = BTreeMap::new();
        version_5.insert(AiModelKey::from(1), mistral_24b.clone());
        version_5.insert(AiModelKey::from(2), qwen_qwq_32b.clone());
        version_5.insert(AiModelKey::from(3), dobby3_1_8b.clone());
        version_5.insert(AiModelKey::from(100), sana_1600m.clone());
        map.insert(5 as u32, version_5);

        let mut version_6 = BTreeMap::new();
        version_6.insert(AiModelKey::from(1), deepseek_deepseek_thinking.clone());
        version_6.insert(AiModelKey::from(2), deepseek_deepseek_non_thinking.clone());
        version_6.insert(AiModelKey::from(3), dobby3_1_8b.clone());
        version_6.insert(AiModelKey::from(100), sana_1600m.clone());
        map.insert(6 as u32, version_6);

        // Free for future releases...
    
        map
    }
}