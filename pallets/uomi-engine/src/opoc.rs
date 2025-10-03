use codec::Encode;
use frame_support::{ pallet_prelude::{ DispatchError, DispatchResult }, traits::Randomness };
use pallet_ipfs::types::{ UsableFromBlockNumber, ExpirationBlockNumber };
use pallet_ipfs::MinExpireDuration;
use sp_core::U256;
use sp_std::{ collections::btree_map::BTreeMap, vec, vec::Vec };

use crate::{
    consts::{MAX_INPUTS_MANAGED_PER_BLOCK, MAX_REQUEST_RETRIES}, ipfs::IpfsInterface, types::{ BlockNumber, Data, RequestId }, Config, Event, Inputs, OpocErrors, NodesOpocL0Inferences, NodesOutputs, OpocTimeouts, NodesWorks, OpocAssignment, OpocBlacklist, OpocLevel, Outputs, Pallet
};

// Helper trait imports for accessing staking internals
use pallet_staking::Pallet as Staking;
use sp_staking::EraIndex;

impl<T: Config> Pallet<T> {
    // Build an exclude list starting from provided seeds and including
    // any validators already assigned to the given request. Ensures uniqueness.
    fn opoc_build_exclude_with_assigned(
        request_id: &RequestId,
        mut seeds: Vec<T::AccountId>,
    ) -> Vec<T::AccountId> {
        for (assigned_validator, _) in OpocAssignment::<T>::iter_prefix(*request_id) {
            if !seeds.contains(&assigned_validator) {
                seeds.push(assigned_validator);
            }
        }
        seeds
    }

    // OPoC entry point
    pub fn opoc_run(current_block: BlockNumber) -> Result<
        (
            BTreeMap<T::AccountId, bool>, // opoc_blacklist_operations
            BTreeMap<(RequestId, T::AccountId), (BlockNumber, OpocLevel)>, // opoc_assignment_operations
            BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>, // nodes_works_operations
            BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>, // opoc_timeouts_operations
            BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>, // opoc_errors_operations
            BTreeMap<RequestId, (Data, u32, u32, U256)>, // outputs_operations (added nft_id)
        ),
        DispatchError
    > {
        let mut opoc_blacklist_operations = BTreeMap::<T::AccountId, bool>::new();
        let mut opoc_assignment_operations = BTreeMap::<
            (RequestId, T::AccountId),
            (BlockNumber, OpocLevel)
        >::new();
        let mut nodes_works_operations = BTreeMap::<T::AccountId, BTreeMap<RequestId, bool>>::new();
        let mut opoc_timeouts_operations = BTreeMap::<RequestId, BTreeMap<T::AccountId, bool>>::new();
        let mut opoc_errors_operations = BTreeMap::<RequestId, BTreeMap<T::AccountId, bool>>::new();
    let mut outputs_operations = BTreeMap::<RequestId, (Data, u32, u32, U256)>::new();

        let ipfs_min_expire_duration = U256::from(MinExpireDuration::get());

        let inputs = Inputs::<T>::iter().collect::<Vec<_>>();
        for (
            request_id,
            (
                block_number,
                _address,
                nft_id,
                nft_required_consensus,
                _nft_execution_max_time,
                nft_file_cid,
                _input_data,
                input_file_cid,
            ),
        ) in inputs.iter().take(MAX_INPUTS_MANAGED_PER_BLOCK) {
            let opoc_assignments_of_level_0 = 1 as usize;
            let opoc_assignments_of_level_1 = nft_required_consensus.as_u32() as usize;

            // If the nft_file_cid is not usable, we skip the request to wait it to be usable
            // NOTE: This case should never happen because the check of the nft_file_cid is done on run_request before accepting the request
            if !nft_file_cid.is_empty() {
                let (nft_file_cid_expiration_block_number, nft_file_cid_usable_from_block_number) =
                    match T::IpfsPallet::get_cid_status(nft_file_cid) {
                        Ok((expiration_block_number, usable_from_block_number)) =>
                            (expiration_block_number, usable_from_block_number),
                        Err(error) => {
                            log::error!(
                                "Failed to get status of nft file cid {:?}. error: {:?}",
                                nft_file_cid,
                                error
                            );
                            continue;
                        }
                    };
                if
                    nft_file_cid_expiration_block_number != ExpirationBlockNumber::zero() &&
                    (block_number + ipfs_min_expire_duration) > (nft_file_cid_expiration_block_number)  // + 1 just to be sure
                {
                    continue;
                }
                if nft_file_cid_usable_from_block_number == UsableFromBlockNumber::zero() {   
                    continue;
                }
                if nft_file_cid_usable_from_block_number > current_block {
                    continue;
                }
            }

            // If the input_file_cid is not usable, we skip the request to wait it to be usable
            if !input_file_cid.is_empty() {
                let (
                    input_file_cid_expiration_block_number,
                    input_file_cid_usable_from_block_number,
                ) = match T::IpfsPallet::get_cid_status(input_file_cid) {
                    Ok((expiration_block_number, usable_from_block_number)) =>
                        (expiration_block_number, usable_from_block_number),
                    Err(error) => {
                        log::error!(
                            "Failed to get status of input file cid {:?}. error: {:?}",
                            input_file_cid,
                            error
                        );
                        continue;
                    }
                };
                if
                    input_file_cid_expiration_block_number != ExpirationBlockNumber::zero() &&
                    (block_number + ipfs_min_expire_duration) > (input_file_cid_expiration_block_number + 1) // + 1 just to be sure
                {    
                    continue;
                }
                if input_file_cid_usable_from_block_number == UsableFromBlockNumber::zero() {
                    continue;
                }
                if input_file_cid_usable_from_block_number > current_block {
                    continue;
                }
            }

            let opoc_assignment_count = OpocAssignment::<T>::iter_prefix(*request_id).count();

            match opoc_assignment_count {
                0 => {
                    // No assignments for input, so we need to assign it to a validator for opoc level 0
                    match
                        Self::opoc_assignment(
                            &mut opoc_blacklist_operations,
                            &mut opoc_assignment_operations,
                            &mut nodes_works_operations,
                            &request_id,
                            &current_block,
                            OpocLevel::Level0,
                            1,
                            vec![],
                            true
                        )
                    {
                        Err(error) => {
                            log::error!(
                                "Failed to assign request to a random validator for OPoC level 0. error: {:?}",
                                error
                            );
                        }
                        _ => (),
                    }
                }
                x if x == opoc_assignments_of_level_0 => {
                    // One assignment for input, so we need to check the output of the first validator and assign the input to validators for opoc level 1
                    let (output, validators_not_completed, validators_in_timeout) =
                        Self::opoc_get_outputs(&request_id, &current_block)?;

                    // Continue if validators_not_completed is not empty (wait next block to check again)
                    if validators_not_completed.len() > 0 {
                        continue;
                    }

                    // Manage timeout if validators_in_timeout is not empty (remove assignment from validator, register timeout, re-assign to another validator)
                    if validators_in_timeout.len() > 0 {
                        let validator = validators_in_timeout[0].clone();

                        // Deassign the request from the validator
                        match
                            Self::opoc_deassignment_per_timeout(
                                &mut opoc_blacklist_operations,
                                &mut opoc_assignment_operations,
                                &mut opoc_timeouts_operations,
                                &mut nodes_works_operations,
                                &request_id,
                                &validator
                            )
                        {
                            Err(error) => {
                                log::error!(
                                    "Failed to deassign request from validator of OPoC level 0 for timeout. error: {:?}",
                                    error
                                );
                                // NOTE: This case should not happen, but if it does, we need to handle it is some way...
                            }
                            _ =>(),
                        }

                        // Build an exclude list: include the timed-out validator, any currently assigned validators for this
                        // request, and any validators that already produced an output (answered). This avoids reassigning an
                        // already-answered or already-assigned node when the validator pool is small.
                        let validators_to_exclude = Self::opoc_build_exclude_with_assigned(
                            &request_id,
                            vec![validator.clone()]
                        );


                        // Reassign the request to another validator
                        match
                            Self::opoc_assignment(
                                &mut opoc_blacklist_operations,
                                &mut opoc_assignment_operations,
                                &mut nodes_works_operations,
                                &request_id,
                                &current_block,
                                OpocLevel::Level0,
                                1,
                                validators_to_exclude,
                                true
                            )
                        {
                            Err(error) => {
                                log::error!(
                                    "Failed to assign request to a random validator for OPoC level 0 after timeout. error: {:?}",
                                    error
                                );
                            }
                            _ => (),
                        }

                        continue;
                    }

                    // Load validator and output of the validator
                    let validator = output.keys().next().unwrap().clone();
                    let final_output = output.get(&validator).unwrap();

                    // Manage final_output equal to Data::default(); in this case we need to deassign the request from the validator and assign it to another validator for a limited number of retries
                    if final_output == &Data::default() {
                        let number_of_retries = Self::opoc_timeouts_operations_count(
                            &opoc_timeouts_operations,
                            &request_id,
                        );

                        if number_of_retries + 1 >= MAX_REQUEST_RETRIES { // +1 because we consider the current retry
                            // Clean all timeouts for the request
                            Self::opoc_timeouts_operations_clean(
                                &mut opoc_timeouts_operations,
                                &mut opoc_blacklist_operations,
                                &request_id
                            );

                            // Deassign the request from the validator per completion
                            match
                                Self::opoc_deassignment_per_completed(
                                    &mut nodes_works_operations,
                                    &validator,
                                    &request_id
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to deassign request from validator of OPoC level 0 for completion. error: {:?}",
                                        error
                                    );
                                    // NOTE: This case should not happen, but if it does, we need to handle it is some way...
                                }
                                _ => (),
                            }

                            // Complete the request with Data::default()
                            let executions = 0 as u32;
                            match
                                Self::opoc_complete(
                                    &mut outputs_operations,
                                    &request_id,
                                    &final_output,
                                    &executions,
                                    &executions,
                                    &nft_id
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to complete request at OPoC level 0 per max retries. error: {:?}",
                                        error
                                    );
                                }
                                _ => (),
                            }
                        } else {
                            // Deassign the request from the validator
                            match
                                Self::opoc_deassignment_per_timeout(
                                    &mut opoc_blacklist_operations,
                                    &mut opoc_assignment_operations,
                                    &mut opoc_timeouts_operations,
                                    &mut nodes_works_operations,
                                    &request_id,
                                    &validator
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to deassign request from validator of OPoC level 0 for timeout. error: {:?}",
                                        error
                                    );
                                    // NOTE: This case should not happen, but if it does, we need to handle it is some way...
                                }
                                _ => (),
                            }

                            // Build exclude list to avoid reassigning the same or already-answered validators
                            let validators_to_exclude = Self::opoc_build_exclude_with_assigned(
                                &request_id,
                                vec![validator.clone()]
                            );
                            

                            // Reassign the request to another validator
                            match
                                Self::opoc_assignment(
                                    &mut opoc_blacklist_operations,
                                    &mut opoc_assignment_operations,
                                    &mut nodes_works_operations,
                                    &request_id,
                                    &current_block,
                                    OpocLevel::Level0,
                                    1,
                                    validators_to_exclude,
                                    true
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to assign request to a random validator for OPoC level 0 after timeout. error: {:?}",
                                        error
                                    );
                                }
                                _ => (),
                            }
                        }
                        continue;
                    }

                    // Manage completed request from validator
                    match
                        Self::opoc_deassignment_per_completed(
                            &mut nodes_works_operations,
                            &validator,
                            &request_id
                        )
                    {
                        Err(error) => {
                            log::error!(
                                "Failed to deassign request from validator of OPoC level 0 for completion. error: {:?}",
                                error
                            );
                            // NOTE: This case should not happen, but if it does, we need to handle it is some way...
                        }
                        _ => (),
                    }

                    if opoc_assignments_of_level_1 > 1 {
                        // When we have a minimum consensus of 2, we need to assign the request to other validators
                        // Assign the request to validators for opoc level 1
                        // Build exclude list to avoid assigning to validator(s) that already handled this request
                        let validators_to_exclude = Self::opoc_build_exclude_with_assigned(
                            &request_id,
                            vec![validator.clone()]
                        );
                    

                        match
                            Self::opoc_assignment(
                                &mut opoc_blacklist_operations,
                                &mut opoc_assignment_operations,
                                &mut nodes_works_operations,
                                &request_id,
                                &current_block,
                                OpocLevel::Level1,
                                (opoc_assignments_of_level_1 as u32) - 1,
                                validators_to_exclude,
                                false
                            )
                        {
                            Err(error) => {
                                log::error!(
                                    "Failed to assign request to random validators for OPoC level 1. error: {:?}",
                                    error
                                );
                            }
                            _ => (),
                        }
                    } else {
                        // When we do not require consensus, we can close the request with only one execution
                        let executions = 1 as u32;
                        match
                            Self::opoc_complete(
                                &mut outputs_operations,
                                &request_id,
                                &final_output,
                                &executions,
                                &executions,
                                &nft_id
                            )
                        {
                            Err(error) => {
                                log::error!(
                                    "Failed to complete request at OPoC level 0. error: {:?}",
                                    error
                                );
                            }
                            _ => (),
                        }
                    }
                }
                x if x == opoc_assignments_of_level_1 => {
                    // Opoc level 1 + 1 assignments for input, so we need to check the output of the validators of opoc level 1 and choose if needs opoc level 2
                    let (output, validators_not_completed, validators_in_timeout) =
                        Self::opoc_get_outputs(&request_id, &current_block)?;

                    // Manage timouts if validators_in_timeout is not empty (remove assignment from validators, register timeout, re-assign to other validators)
                    if validators_in_timeout.len() > 0 {
                        for validator in validators_in_timeout.iter() {
                            // Deassign the request from the validator
                            match
                                Self::opoc_deassignment_per_timeout(
                                    &mut opoc_blacklist_operations,
                                    &mut opoc_assignment_operations,
                                    &mut opoc_timeouts_operations,
                                    &mut nodes_works_operations,
                                    &request_id,
                                    &validator
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to deassign request from validator of OPoC level 1 for timeout. error: {:?}",
                                        error
                                    );
                                    // NOTE: This case should not happen, but if it does, we need to handle it is some way...
                                }
                                _ => (),
                            }
                        }

                        //create a vec with the validators to exclude from output keys and validators_not_completed to avoid reassigning the request to the same validators
                        let mut validators_to_exclude = Vec::<T::AccountId>::new();
                        for validator in validators_not_completed.iter() {
                            validators_to_exclude.push(validator.clone());
                        }
                        output.keys().for_each(|validator| {
                            validators_to_exclude.push(validator.clone());
                        });

                        // Reassign the request to other validators
                        match
                            Self::opoc_assignment(
                                &mut opoc_blacklist_operations,
                                &mut opoc_assignment_operations,
                                &mut nodes_works_operations,
                                &request_id,
                                &current_block,
                                OpocLevel::Level1,
                                validators_in_timeout.len() as u32,
                                validators_to_exclude,
                                false
                            )
                        {
                            Err(error) => {
                                log::error!(
                                    "Failed to assign request to random validators for OPoC level 1 after timeout. error: {:?}",
                                    error
                                );
                            }
                            _ => (),
                        }

                        continue;
                    }

                    // Continue if validators_not_completed is not empty (wait next block to check again)
                    if validators_not_completed.len() > 0 {
                        continue;
                    }

                    // Manage presence of outputs with Data::default(); in this case we need to deassign the request from the validator and assign it to another validator for a limited number of retries
                    let validators_with_empty_output = output
                        .iter()
                        .filter(|(_, output)| output == &&Data::default())
                        .map(|(validator, _)| validator.clone())
                        .collect::<Vec<T::AccountId>>();
                    if validators_with_empty_output.len() > 0 {
                        let number_of_retries = Self::opoc_timeouts_operations_count(
                            &opoc_timeouts_operations,
                            &request_id,
                        );

                        if number_of_retries + validators_with_empty_output.len() as u32 >= MAX_REQUEST_RETRIES {
                            // Clean all timeouts for the request
                            Self::opoc_timeouts_operations_clean(
                                &mut opoc_timeouts_operations,
                                &mut opoc_blacklist_operations,
                                &request_id
                            );

                            // Deassign the request from all validators per completion
                            for validator in output.keys() {
                                match
                                    Self::opoc_deassignment_per_completed(
                                        &mut nodes_works_operations,
                                        &validator,
                                        &request_id
                                    )
                                {
                                    Err(error) => {
                                        log::error!(
                                            "Failed to deassign request from validator of OPoC level 1 for completion. error: {:?}",
                                            error
                                        );
                                        // NOTE: This case should not happen, but if it does, we need to handle it is some way...
                                    }
                                    _ => (),
                                }
                            }

                            // Complete the request with Data::default()
                            let executions = 0 as u32;
                            match
                                Self::opoc_complete(
                                    &mut outputs_operations,
                                    &request_id,
                                    &Data::default(),
                                    &executions,
                                    &executions,
                                    &nft_id
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to complete request at OPoC level 1 per max retries. error: {:?}",
                                        error
                                    );
                                }
                                _ => (),
                            }
                        } else {
                            // Deassign the request from the validators with empty output
                            for validator in validators_with_empty_output.iter() {
                                match
                                    Self::opoc_deassignment_per_timeout(
                                        &mut opoc_blacklist_operations,
                                        &mut opoc_assignment_operations,
                                        &mut opoc_timeouts_operations,
                                        &mut nodes_works_operations,
                                        &request_id,
                                        &validator
                                    )
                                {
                                    Err(error) => {
                                        log::error!(
                                            "Failed to deassign request from validator of OPoC level 1 for timeout. error: {:?}",
                                            error
                                        );
                                        // NOTE: This case should not happen, but if it does, we need to handle it is some way...
                                    }
                                    _ => (),
                                }
                            }


                            // Build an exclude list: include the timed-out validator, any currently assigned validators for this
                            // request, and any validators that already produced an output (answered). This avoids reassigning an
                            // already-answered or already-assigned node when the validator pool is small.
                            let validators_to_exclude = Self::opoc_build_exclude_with_assigned(
                                &request_id,
                                validators_with_empty_output.clone()
                            );
                           

                            // Reassign the request to other validators
                            match
                                Self::opoc_assignment(
                                    &mut opoc_blacklist_operations,
                                    &mut opoc_assignment_operations,
                                    &mut nodes_works_operations,
                                    &request_id,
                                    &current_block,
                                    OpocLevel::Level1,
                                    validators_with_empty_output.len() as u32,
                                    validators_to_exclude,
                                    false
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to assign request to random validators for OPoC level 1 after timeout. error: {:?}",
                                        error
                                    );
                                }
                                _ => (),
                            }
                        }

                        continue;
                    }

                    // For every key in output do Self::opoc_deassignment_per_completed
                    for validator in output.keys() {
                        match
                            Self::opoc_deassignment_per_completed(
                                &mut nodes_works_operations,
                                &validator,
                                &request_id
                            )
                        {
                            Err(error) => {
                                log::error!(
                                    "Failed to deassign request from validator of OPoC level 1 for completion. error: {:?}",
                                    error
                                );
                                // NOTE: This case should not happen, but if it does, we need to handle it is some way...
                            }
                            _ => (),
                        }
                    }

                    // check if every outputs are the same
                    let mut output_values = output.values();
                    let first_output = output_values.next().unwrap();

                    if output_values.all(|output| output == first_output) {
                        let output_values_len = output.len() as u32;

                        match
                            Self::opoc_complete(
                                &mut outputs_operations,
                                &request_id,
                                &first_output,
                                &output_values_len,
                                &output_values_len,
                                &nft_id
                            )
                        {
                            Err(error) => {
                                log::error!(
                                    "Failed to complete request at OPoC level 1. error: {:?}",
                                    error
                                );
                            }
                            _ => (),
                        }
                    } else {
                        let mut validators_to_exclude = Vec::<T::AccountId>::new();
                        output.keys().for_each(|validator| {
                            validators_to_exclude.push(validator.clone());
                        });

                        // BACKUP OLD CODE: is possible that some validators to exclude are not in the active validators list so we take less validators than expected
                        // let validators_active_count = Self::get_active_validators_count();
                        // let number_of_validators = validators_active_count - (validators_to_exclude.len() as u32);

                        // NEW CODE
                        let active_validators = Self::get_active_validators();
                        let active_validators_without_exclude = active_validators
                            .into_iter()
                            .filter(|account_id| !validators_to_exclude.contains(account_id))
                            .collect::<Vec<T::AccountId>>();

                        // TO CHECK: QUI STIAMO PRENDENDO number_of_validators NON COME 2/3+1 DELLA CHAIN, MA 2/3+1 DEI NODI DELLA CHAIN TOLTI QUELLI CHE HANNO GIA ESEGUITO LA RICHIESTA
                        // DA CAPIRE SE E CORRETTO O MENO
                        let number_of_validators = active_validators_without_exclude.len() as u32;
                        let number_of_validators = (number_of_validators * 2 / 3) + 1;
                        
                        // Assign the request to validators for opoc level 2 to all validators
                        match
                            Self::opoc_assignment(
                                &mut opoc_blacklist_operations,
                                &mut opoc_assignment_operations,
                                &mut nodes_works_operations,
                                &request_id,
                                &current_block,
                                OpocLevel::Level2,
                                number_of_validators,
                                validators_to_exclude,
                                false
                            )
                        {
                            Err(error) => {
                                log::error!(
                                    "Failed to assign request to all validators for OPoC level 2. error: {:?}",
                                    error
                                );
                            }
                            _ => (),
                        }
                    }
                }
                x if x > opoc_assignments_of_level_1 => {
                    let (output, validators_not_completed, validators_in_timeout) =
                        Self::opoc_get_outputs(&request_id, &current_block)?;

                    // If validators_not_completed is not empty, wait next block to check again
                    if validators_not_completed.len() > 0 {
                        continue;
                    }

                    // If some validators are in timeout, remove the assignment from them, register the timeout
                    if validators_in_timeout.len() > 0 {
                        for validator in validators_in_timeout.iter() {
                            // Deassign the request from the validator
                            match
                                Self::opoc_deassignment_per_timeout(
                                    &mut opoc_blacklist_operations,
                                    &mut opoc_assignment_operations,
                                    &mut opoc_timeouts_operations,
                                    &mut nodes_works_operations,
                                    &request_id,
                                    &validator
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to deassign request from validator of OPoC level 2 for timeout. error: {:?}",
                                        error
                                    );
                                }
                                _ => (),
                            }
                        }
                    }

                    // Filter output by removing the records with Data::default() as value and deassign per timeout the validators
                    let mut filtered_output = BTreeMap::<T::AccountId, Data>::new();
                    for (validator, output) in output.iter() {
                        if output != &Data::default() {
                            filtered_output.insert(validator.clone(), output.clone());
                        } else {
                            match
                                Self::opoc_deassignment_per_timeout(
                                    &mut opoc_blacklist_operations,
                                    &mut opoc_assignment_operations,
                                    &mut opoc_timeouts_operations,
                                    &mut nodes_works_operations,
                                    &request_id,
                                    &validator
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to deassign request from validator of OPoC level 2 for timeout. error: {:?}",
                                        error
                                    );
                                }
                                _ => (),
                            }
                        }
                    }

                    let mut value_counts: BTreeMap<&Data, usize> = BTreeMap::new();

                    // Count occurrences of each value except for Data::default()
                    for value in filtered_output.values() {
                        *value_counts.entry(value).or_insert(0) += 1;
                    }

                    // Store the max value before converting to Option
                    let (max_value, _) = value_counts
                        .iter()
                        .max_by_key(|&(_, count)| count)
                        .expect("Should have at least one value");

                    let output_completed = Some((*max_value).clone());

                    // loop the output
                    filtered_output.iter().for_each(|(validator, output)| {
                        if Some(output) != output_completed.as_ref() {
                            match
                                Self::opoc_deassignment_per_invalid_output(
                                    &mut opoc_blacklist_operations,
                                    &mut opoc_assignment_operations,
                                    &mut opoc_errors_operations,
                                    &mut nodes_works_operations,
                                    &request_id,
                                    &validator
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to deassign request from validator of OPoC level 2 for invalid output. error: {:?}",
                                        error
                                    );
                                }
                                _ => (),
                            }
                        } else {
                            match
                                Self::opoc_deassignment_per_completed(
                                    &mut nodes_works_operations,
                                    &validator,
                                    &request_id
                                )
                            {
                                Err(error) => {
                                    log::error!(
                                        "Failed to deassign request from validator of OPoC level 2 for completion. error: {:?}",
                                        error
                                    );
                                }
                                _ => (),
                            }
                        }
                    });

                    let output_values_len = filtered_output.len() as u32;

                    let consensus_output = output_completed.as_ref().unwrap();
                    let output_consensus_len = value_counts
                        .get(consensus_output)
                        .unwrap()
                        .clone() as u32;

                    match
                        Self::opoc_complete(
                            &mut outputs_operations,
                            &request_id,
                            &consensus_output,
                            &output_values_len,
                            &output_consensus_len,
                            &nft_id
                        )
                    {
                        Err(error) => {
                            log::error!(
                                "Failed to complete request at OPoC level 2. error: {:?}",
                                error
                            );
                        }
                        _ => (),
                    }
                }
                _ => {
                    // Collect diagnostics to help debug why we reached an unexpected state
                    let mut assignments: Vec<(T::AccountId, (BlockNumber, OpocLevel))> = Vec::new();
                    for (validator, (expiration, level)) in OpocAssignment::<T>::iter_prefix(request_id) {
                        assignments.push((validator.clone(), (expiration.clone(), level)));
                    }

                    let mut timeouts: Vec<T::AccountId> = Vec::new();
                    for (validator, is_timeout) in OpocTimeouts::<T>::iter_prefix(request_id) {
                        if is_timeout {
                            timeouts.push(validator.clone());
                        }
                    }

                    let mut errors: Vec<T::AccountId> = Vec::new();
                    for (validator, is_error) in OpocErrors::<T>::iter_prefix(request_id) {
                        if is_error {
                            errors.push(validator.clone());
                        }
                    }

                    let mut outputs_keys: Vec<T::AccountId> = Vec::new();
                    for (validator, _output) in NodesOutputs::<T>::iter_prefix(request_id) {
                        outputs_keys.push(validator.clone());
                    }

                    log::error!(
                        "Found an unexpected number of opoc assignments for request ID: {:?}. diagnostics: assignments={:?}, timeouts={:?}, errors={:?}, outputs_keys={:?}, required_consensus={:?}",
                        request_id,
                        assignments,
                        timeouts,
                        errors,
                        outputs_keys,
                        opoc_assignments_of_level_1
                    );

                    // Fail the request to avoid it staying forever in a half-assigned state.
                    // Use Data::default() as the output and treat as 0 executions so cleanup will run in opoc_store_operations.
                    let executions = 0 as u32;
                    match Self::opoc_complete(
                        &mut outputs_operations,
                        &request_id,
                        &Data::default(),
                        &executions,
                        &executions,
                        &nft_id
                    ) {
                        Err(error) => {
                            log::error!(
                                "Failed to complete request at OPoC unexpected branch for request {:?}. error: {:?}",
                                request_id,
                                error
                            );
                        }
                        _ => {
                            log::warn!(
                                "Request {:?} moved to failed completion (Data::default()) due to unexpected opoc assignment state",
                                request_id
                            );
                        }
                    }
                }
            }
        }

        Ok((
            opoc_blacklist_operations,
            opoc_assignment_operations,
            nodes_works_operations,
            opoc_timeouts_operations,
            opoc_errors_operations,
            outputs_operations,
        ))
    }

    pub fn opoc_assignment(
        opoc_blacklist_operations: &mut BTreeMap<T::AccountId, bool>,
        opoc_assignment_operations: &mut BTreeMap<(RequestId, T::AccountId), (BlockNumber, OpocLevel)>,
        nodes_works_operations: &mut BTreeMap<T::AccountId, BTreeMap<U256, bool>>,
        request_id: &RequestId,
        current_block: &BlockNumber,
        opoc_level: OpocLevel,
        validators_amount: u32,
        validators_to_exclude: Vec<T::AccountId>,
        first_free: bool
    ) -> Result<(), DispatchError> {
        let random_validators = match
            Self::opoc_assignment_get_random_validators(
                opoc_blacklist_operations,
                nodes_works_operations,
                U256::from(validators_amount),
                first_free,
                validators_to_exclude
            )
        {
            Ok(validators) => validators,
            Err(error) => {
                return Err(error);
            }
        };

        for validator in random_validators {
            let is_blacklisted = Self::opoc_blacklist_operations_check(
                opoc_blacklist_operations,
                &validator
            );

            // if black listed, remove the validator from the list of validators
            if is_blacklisted {
                Self::opoc_blacklist_operations_remove(opoc_blacklist_operations, &validator);
            }

            // increment the number of works of the validator
            Self::opoc_nodes_works_operations_add(nodes_works_operations, &validator, &request_id);

            // calculate expiration_block_number after the add of the request
            let works_execution_max_time_sum =
                Self::opoc_nodes_works_operations_sum_execution_max_time(
                    nodes_works_operations,
                    &validator
                );
            let expiration_block_number = current_block + works_execution_max_time_sum;

            // assign the request to the validator
            Self::opoc_assignment_operations_add(
                opoc_assignment_operations,
                &request_id,
                &validator,
                &expiration_block_number, 
                opoc_level,
            );
        }

        Ok(())
    }

    pub fn opoc_store_operations(
        operations: (
            BTreeMap<T::AccountId, bool>, // opoc_blacklist_operations
            BTreeMap<(RequestId, T::AccountId), (BlockNumber, OpocLevel)>, // opoc_assignment_operations
            BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>, // nodes_works_operations
            BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>, // opoc_timeouts_operations
            BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>, // opoc_errors_operations
            BTreeMap<U256, (Data, u32, u32, U256)>, // outputs_operations with nft_id
        )
    ) -> Result<(), DispatchError> {
        // get operations to do
        let (
            opoc_blacklist_operations,
            opoc_assignment_operations,
            nodes_works_operations,
            opoc_timeouts_operations,
            opoc_errors_operations,
            outputs_operations,
        ) = operations;

        // set opoc_blacklist_operations
        for (account_id, is_blacklisted) in opoc_blacklist_operations.iter() {
            if *is_blacklisted {
                OpocBlacklist::<T>::insert(account_id, is_blacklisted);
                Self::deposit_event(Event::OpocBlacklistAdd { account_id: account_id.clone() });
            } else {
                OpocBlacklist::<T>::remove(account_id);
                Self::deposit_event(Event::OpocBlacklistRemove { account_id: account_id.clone() });
            }
        }

        // set opoc_assignment_operations
        for (
            (request_id, account_id),
            (expiration_block_number, opoc_level),
        ) in opoc_assignment_operations.iter() {
            if expiration_block_number == &U256::from(0) {
                OpocAssignment::<T>::remove(request_id, account_id);
                Self::deposit_event(Event::OpocAssignmentRemove {
                    request_id: request_id.clone(),
                    account_id: account_id.clone(),
                });
            } else {
                OpocAssignment::<T>::insert(request_id, account_id, (expiration_block_number, opoc_level));
                Self::deposit_event(Event::OpocAssignmentAdd {
                    request_id: request_id.clone(),
                    account_id: account_id.clone(),
                    expiration_block_number: expiration_block_number.clone(),
                });
            }
        }

        // set nodes_works_operations
        for (account_id, requests) in nodes_works_operations.iter() {
            for (request_id, is_assigned) in requests.iter() {
                if *is_assigned {
                    NodesWorks::<T>::insert(account_id, request_id, is_assigned);
                } else {
                    NodesWorks::<T>::remove(account_id, request_id);
                }
            }
        }

        // set opoc_timeouts_operations
        for (request_id, requests) in opoc_timeouts_operations.iter() {
            for (account_id, is_assigned) in requests.iter() {
                if *is_assigned {
                    OpocTimeouts::<T>::insert(request_id, account_id, is_assigned);
                } else {
                    OpocTimeouts::<T>::remove(request_id, account_id);
                }
            }
        }

        // set opoc_errors_operations
        for (request_id, requests) in opoc_errors_operations.iter() {
            for (account_id, is_assigned) in requests.iter() {
                if *is_assigned {
                    OpocErrors::<T>::insert(request_id, account_id, is_assigned);
                } else {
                    OpocErrors::<T>::remove(request_id, account_id);
                }
            }
        }

        // set outputs_operations
        // NOTE: For every output, we need to clear other storages from data associated with the request_id
        for (
            request_id,
            (output_data, total_executions, total_consensus, nft_id),
        ) in outputs_operations.iter() {
            // insert in Outputs
            Outputs::<T>::insert(request_id, (
                output_data.clone(),
                total_executions.clone(),
                total_consensus.clone(),
                *nft_id,
            ));
            Self::deposit_event(Event::RequestCompleted {
                request_id: request_id.clone(),
                output_data: output_data.clone(),
                total_executions: total_executions.clone(),
                total_consensus: total_consensus.clone(),
            });

            // Deferred staking penalty application for timeouts:
            // We moved the reset of staking era reward points from the moment a timeout is recorded
            // to the moment the request is finalized. This ensures we only slash rewards once we're
            // sure about the request outcome and avoid penalizing during in-flight reassignment cycles.
            // Requirement summary:
            // 1. Apply only to validators that timed out (OpocTimeouts == true for this request).
            // 2. A later valid output does NOT cancel the penalty (once timed out, still penalized at completion).
            // 3. TODO (open decision): Whether to skip this on failed (Data::default()) completions. Probably not, so this is ok for now
            for (account_id, is_timeout) in OpocTimeouts::<T>::iter_prefix(request_id) {
                if is_timeout {
                    // Best-effort; failure shouldn't abort OPoC logic.
                    if let Err(e) = Self::reset_validator_current_era_points(&account_id) {
                        log::error!(
                            "Failed to reset staking points for validator {:?} on completed request {:?}: {:?}",
                            account_id,
                            request_id,
                            e
                        );
                    }
                }
            }
            // remove from Inputs
            Inputs::<T>::remove(request_id);
            // remove all assignments from OpocAssignment
            for (account_id, _) in OpocAssignment::<T>::iter_prefix(request_id) {
                OpocAssignment::<T>::remove(request_id, account_id);
            }
            // remove all outputs from NodesOutputs
            for (account_id, _) in NodesOutputs::<T>::iter_prefix(request_id) {
                NodesOutputs::<T>::remove(request_id, account_id);
            }
            // remove all inferences from NodesOpocL0Inferences
            for (account_id, _) in NodesOpocL0Inferences::<T>::iter_prefix(request_id) {
                NodesOpocL0Inferences::<T>::remove(request_id, account_id);
            }
        }

        Ok(())
    }

    pub fn opoc_assignment_get_random_validators(
        opoc_blacklist_operations: &BTreeMap<T::AccountId, bool>,
        nodes_works_operations: &BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>,
        number: U256,
        first_free: bool,
        validators_to_exclude: Vec<T::AccountId>
    ) -> Result<Vec<T::AccountId>, DispatchError> {
        let number_usize = number.low_u64() as usize;

        // Get active validators excluding specified ones
        let validators: Vec<T::AccountId> = Self::get_active_validators()
            .into_iter()
            .filter(|account_id| !validators_to_exclude.contains(account_id)) // filter out the validators to exclude
            .collect();

        // TEMPORARY MOD FOR TURING TESTNET: We remove from the validators list nodes that are blacklisted
        let validators: Vec<T::AccountId> = validators
            .into_iter()
            .filter(|account_id| !Self::opoc_blacklist_operations_check(opoc_blacklist_operations, account_id))
            .collect();
    
        // Get potential validators based on first_free flag
        let potential_validators: Vec<T::AccountId> = if first_free {
            let free_validators: Vec<T::AccountId> = validators
                .iter()
                .filter(
                    |account_id| Self::opoc_nodes_works_operations_count(
                        nodes_works_operations, 
                        account_id
                    ) == 0
                )
                .cloned()
                .collect();
                
            if free_validators.len() >= number_usize {
                free_validators
            } else {
                validators
            }
        } else {
            validators
        };
    
        // Check if we have enough validators
        let validator_count = potential_validators.len();
        if validator_count < number_usize {
            return Err(DispatchError::Other("Not enough validators"));
        }
    
        // Get random seed
        let random_seed = T::Randomness::random(&b"validator_selection"[..]);
        let random_bytes = random_seed.0.encode();

        let mut selected_validators = Vec::with_capacity(number_usize);
        let mut used_indices = Vec::new();
        
        // Modified random selection logic
        let mut current_byte_index = 0;
        let bytes_per_selection = 4.min(random_bytes.len() / number_usize);
    
        for _ in 0..number_usize {
            if current_byte_index + bytes_per_selection > random_bytes.len() {
                // If we run out of random bytes, create a new selection using existing bytes
                current_byte_index = 0;
            }
    
            // Create random value from available bytes
            let random_slice = &random_bytes[current_byte_index..current_byte_index + bytes_per_selection];
            let random_value = U256::from_little_endian(random_slice);
            
            let mut index = (random_value % U256::from(validator_count)).low_u64() as usize;
            
            // Find next unused index
            let mut attempts = 0;
            while used_indices.contains(&index) {
                index = (index + 1) % validator_count;
                attempts += 1;
                if attempts >= validator_count {
                    return Err(DispatchError::Other("Failed to find unique validator index"));
                }
            }
            
            used_indices.push(index);
            if let Some(validator) = potential_validators.get(index) {
                selected_validators.push(validator.clone());
            }
            
            current_byte_index += bytes_per_selection;
        }
    
        // Verify we selected enough validators
        if selected_validators.len() < number_usize {
            return Err(DispatchError::Other("Failed to select enough unique validators"));
        }
    
        Ok(selected_validators)
    }

    fn opoc_deassignment_per_invalid_output(
        opoc_blacklist_operations: &mut BTreeMap<T::AccountId, bool>,
        opoc_assignment_operations: &mut BTreeMap<(RequestId, T::AccountId), (BlockNumber, OpocLevel)>,
        opoc_errors_operations: &mut BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>,
        nodes_works_operations: &mut BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>,
        request_id: &RequestId,
        validator: &T::AccountId
    ) -> Result<(), DispatchError> {
        // Decrease the number of works of the validator
        Self::opoc_nodes_works_operations_remove(nodes_works_operations, validator, request_id);
        // Remove the request from the OpocAssignment storage
        Self::opoc_assignment_operations_remove(opoc_assignment_operations, request_id, validator);
        // Increment the number of errors of the validator
        Self::opoc_errors_operations_add(opoc_errors_operations, validator, request_id);
        // Set the validator as blacklisted
        Self::opoc_blacklist_operations_add(opoc_blacklist_operations, validator);

        Ok(())
    }

    fn opoc_deassignment_per_timeout(
        opoc_blacklist_operations: &mut BTreeMap<T::AccountId, bool>,
        opoc_assignment_operations: &mut BTreeMap<(RequestId, T::AccountId), (BlockNumber, OpocLevel)>,
        opoc_timeouts_operations: &mut BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>,
        nodes_works_operations: &mut BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>,
        request_id: &RequestId,
        validator: &T::AccountId
    ) -> Result<(), DispatchError> {
        // Decrease the number of works of the validator
        Self::opoc_nodes_works_operations_remove(nodes_works_operations, validator, request_id);
        // Remove the request from the OpocAssignment storage
        Self::opoc_assignment_operations_remove(opoc_assignment_operations, request_id, validator);
        // Increment the number of timeouts of the validator
        Self::opoc_timeouts_operations_add(opoc_timeouts_operations, validator, request_id);
        // Set the validator as blacklisted
        Self::opoc_blacklist_operations_add(opoc_blacklist_operations, validator);


        Ok(())
    }

    fn opoc_deassignment_per_completed(
        nodes_works_operations: &mut BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>,
        validator: &T::AccountId,
        request_id: &RequestId
    ) -> Result<(), DispatchError> {
        // Decrease the number of works of the validator
        Self::opoc_nodes_works_operations_remove(nodes_works_operations, validator, request_id);

        Ok(())
    }

    // This function is used to get informations about the execution of a request by the validators that has an assignment.
    // It take the request_id and the current_block as input and return:
    // - A BTreeMap with the validator as key and the output as value
    // - A vector with the validators that have not responded to the request and are not in timeout
    // - A vector with the validators that are in timeout
    fn opoc_get_outputs(
        request_id: &RequestId,
        current_block: &BlockNumber
    ) -> Result<
        (BTreeMap<T::AccountId, Data>, Vec<T::AccountId>, Vec<T::AccountId>),
        DispatchError
    > {
        let mut outputs = BTreeMap::<T::AccountId, Data>::new();
        let mut validators_not_completed = Vec::<T::AccountId>::new();
        let mut validators_in_timeout = Vec::<T::AccountId>::new();

        let opoc_assignments = OpocAssignment::<T>::iter_prefix(*request_id);
        for (validator, (expiration_block_number, _opoc_level)) in opoc_assignments {
            // Check if the validator has responded to the request
            // IMPORTANT: The check is done by iterating over the outputs of the request_id and checking if the validator is in the outputs BTreeMap
            // because the validator could have written the output as an empty value, so the output is empty but the validator has responded.
            let is_validator_output =
                NodesOutputs::<T>
                    ::iter_prefix(*request_id)
                    .find(|(account_id, _output_data)| account_id == &validator) != None;

            // If the validator has responded, add the output to the outputs BTreeMap and continue
            if is_validator_output {
                let node_output = NodesOutputs::<T>::get(*request_id, validator.clone());
                outputs.insert(validator.clone(), node_output);
                continue;
            }

            // Check if the validator is in timeout
            let timeout = current_block.clone() > expiration_block_number;
            if timeout {
                validators_in_timeout.push(validator.clone());
            } else {
                validators_not_completed.push(validator.clone());
            }
        }

        Ok((outputs, validators_not_completed, validators_in_timeout))
    }

    fn opoc_blacklist_operations_check(
        opoc_blacklist_operations: &BTreeMap<T::AccountId, bool>,
        validator: &T::AccountId
    ) -> bool {
        match opoc_blacklist_operations.get(&validator) {
            Some(&blacklisted) => blacklisted,
            None => {
                let blacklisted = OpocBlacklist::<T>::get(&validator);
                blacklisted
            }
        }
    }

    fn opoc_blacklist_operations_add(
        opoc_blacklist_operations: &mut BTreeMap<T::AccountId, bool>,
        validator: &T::AccountId
    ) -> bool {
        opoc_blacklist_operations.insert(validator.clone(), true);
        true
    }

    fn opoc_blacklist_operations_remove(
        opoc_blacklist_operations: &mut BTreeMap<T::AccountId, bool>,
        validator: &T::AccountId
    ) -> bool {
        opoc_blacklist_operations.insert(validator.clone(), false);
        true
    }

    fn opoc_assignment_operations_add(
        opoc_assignment_operations: &mut BTreeMap<(RequestId, T::AccountId), (BlockNumber, OpocLevel)>,
        request_id: &RequestId,
        validator: &T::AccountId,
        expiration_block_number: &BlockNumber,
        opoc_level: OpocLevel
    ) -> bool {
        opoc_assignment_operations.insert(
            (request_id.clone(), validator.clone()),
            (expiration_block_number.clone(), opoc_level)
        );
        true
    }

    fn opoc_assignment_operations_remove(
        opoc_assignment_operations: &mut BTreeMap<(RequestId, T::AccountId), (BlockNumber, OpocLevel)>,
        request_id: &RequestId,
        validator: &T::AccountId
    ) -> bool {
        opoc_assignment_operations.insert((request_id.clone(), validator.clone()), (U256::from(0), OpocLevel::Level0));
        true
    }

    fn opoc_nodes_works_operations_count(
        nodes_works_operations: &BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>,
        validator: &T::AccountId
    ) -> u32 {
        let works_count_storage = NodesWorks::<T>::iter_prefix(validator).count() as u32;
        let works_count_operations = match nodes_works_operations.get(&validator) {
            Some(works) => {
                //count only if true
                works
                    .iter()
                    .filter(|(_request_id, &is_work)| is_work)
                    .count() as u32
            }
            None => 0 as u32,
        };

        works_count_storage + works_count_operations
    }

    fn opoc_nodes_works_operations_sum_execution_max_time(
        nodes_works_operations: &BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>,
        validator: &T::AccountId
    ) -> U256 {
        let mut request_ids = Vec::<U256>::new();

        // Loop NodesWorks storage and take all the request_ids of the validator
        NodesWorks::<T>::iter_prefix(validator).for_each(|(request_id, _)| {
            request_ids.push(request_id);
        });

        // Loop nodes_works_operations and take all the request_ids of the validator with is_work = true
        // remove all the request_ids on the request_ids vector with is_work = false
        let works = match nodes_works_operations.get(&validator) {
            Some(works) => works.clone(),
            None => BTreeMap::<U256, bool>::new(),
        };
        works.iter().for_each(|(request_id, &is_work)| {
            if is_work {
                request_ids.push(request_id.clone());
            } else {
                request_ids.retain(|&x| x != *request_id);
            }
        });

        // Make request_ids to contain only unique values
        request_ids.sort();
        request_ids.dedup();

        // Calculate the sum of the execution_max_time of the request_ids by reading the Inputs storage
        let mut sum = U256::from(0);
        for request_id in request_ids.iter() {
            let (
                _block_number,
                _address,
                _nft_id,
                _nft_required_consensus,
                nft_execution_max_time,
                _nft_file_cid,
                _input_data,
                _input_file_cid,
            ) = Inputs::<T>::get(request_id);
            sum += nft_execution_max_time;
        }

        sum
    }

    fn opoc_nodes_works_operations_add(
        nodes_works_operations: &mut BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>,
        validator: &T::AccountId,
        request_id: &RequestId
    ) -> bool {
        //add the request_id to the works of the validator
        match nodes_works_operations.get(&validator) {
            Some(works) => {
                let mut works = works.clone();
                works.insert(request_id.clone(), true);
                nodes_works_operations.insert(validator.clone(), works);
                true
            }
            None => {
                let mut works = BTreeMap::<U256, bool>::new();
                works.insert(request_id.clone(), true);
                nodes_works_operations.insert(validator.clone(), works);
                true
            }
        }
    }

    fn opoc_nodes_works_operations_remove(
        nodes_works_operations: &mut BTreeMap<T::AccountId, BTreeMap<RequestId, bool>>,
        validator: &T::AccountId,
        request_id: &RequestId
    ) -> bool {
        match nodes_works_operations.get(&validator) {
            Some(works) => {
                let mut works = works.clone();
                works.insert(request_id.clone(), false);
                nodes_works_operations.insert(validator.clone(), works);
                true
            }
            None => {
                //should set to false for the validator
                let mut works = BTreeMap::<U256, bool>::new();
                works.insert(request_id.clone(), false);
                nodes_works_operations.insert(validator.clone(), works);
                true
            }
        }
    }

    fn opoc_errors_operations_add(
        opoc_errors_operations: &mut BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>,
        validator: &T::AccountId,
        request_id: &RequestId
    ) -> bool {
        //add the request_id to the errors of the validator
        match opoc_errors_operations.get(&request_id) {
            Some(errors) => {
                let mut errors = errors.clone();
                errors.insert(validator.clone(), true);
                opoc_errors_operations.insert(request_id.clone(), errors);
                true
            }
            None => {
                let mut errors = BTreeMap::<T::AccountId, bool>::new();
                errors.insert(validator.clone(), true);
                opoc_errors_operations.insert(request_id.clone(), errors);
                true
            }
        }
    }

    fn opoc_timeouts_operations_add(
        opoc_timeouts_operations: &mut BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>,
        validator: &T::AccountId,
        request_id: &RequestId
    ) -> bool {
        //add the request_id to the timeouts of the validator
        match opoc_timeouts_operations.get(&request_id) {
            Some(timeouts) => {
                let mut timeouts = timeouts.clone();
                timeouts.insert(validator.clone(), true);
                opoc_timeouts_operations.insert(request_id.clone(), timeouts);
                true
            }
            None => {
                let mut timeouts = BTreeMap::<T::AccountId, bool>::new();
                timeouts.insert(validator.clone(), true);
                opoc_timeouts_operations.insert(request_id.clone(), timeouts);
                true
            }
        }
    }

    // This function is used to get the number of timeouts of a request_id by checking the storage and the operations
    // NOTE: It should avoid to consider twice the same timeout stored both in the storage and in the operations
    fn opoc_timeouts_operations_count(
        opoc_timeouts_operations: &BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>,
        request_id: &RequestId
    ) -> u32 {
        let mut timeouts_per_account: Vec<T::AccountId> = Vec::new();

        let opoc_timeouts_operations_for_request_id = match opoc_timeouts_operations.get(request_id) {
            Some(timeouts) => timeouts.clone(),
            None => BTreeMap::<T::AccountId, bool>::new(),
        };
        for (validator, &is_timeout) in opoc_timeouts_operations_for_request_id.iter() {
            if is_timeout && !timeouts_per_account.contains(validator) {
                timeouts_per_account.push(validator.clone());
            }
        }

        let storage_timeouts_for_request_id = OpocTimeouts::<T>::iter_prefix(request_id);
        for (validator, is_timeout) in storage_timeouts_for_request_id {
            if is_timeout && !timeouts_per_account.contains(&validator) {
                timeouts_per_account.push(validator.clone());
            }
        }

        timeouts_per_account.len() as u32
    }

    // This function is used to clean all the timeouts stored for a specific request_id
    // NOTE: It should remove all the timeouts stored in opoc_timeouts_operations, then it should add on opoc_timeouts_operations all the timeouts stored in OpocTimeouts with false value
    fn opoc_timeouts_operations_clean(
        opoc_timeouts_operations: &mut BTreeMap<RequestId, BTreeMap<T::AccountId, bool>>,
        opoc_blacklist_operations: &mut BTreeMap<T::AccountId, bool>,
        request_id: &RequestId
    ) -> bool {
        let mut accounts_restored: Vec<T::AccountId> = Vec::new();

        // remove all the timeouts stored in opoc_timeouts_operations
        if let Some(timeouts) = opoc_timeouts_operations.get(request_id) {
            for (validator, _is_timeout) in timeouts.iter() {
                accounts_restored.push(validator.clone());
            }
        }
        opoc_timeouts_operations.remove(request_id);

        // add on opoc_timeouts_operations all the timeouts stored in OpocTimeouts with false value
        let storage_timeouts_for_request_id = OpocTimeouts::<T>::iter_prefix(request_id);
        let mut timeouts = BTreeMap::<T::AccountId, bool>::new();
        for (validator, _is_timeout) in storage_timeouts_for_request_id {
            timeouts.insert(validator.clone(), false);
            accounts_restored.push(validator.clone());
        }
        opoc_timeouts_operations.insert(request_id.clone(), timeouts);

        // remove the accounts restored from the opoc blacklist operations 
        for account in accounts_restored {
            Self::opoc_blacklist_operations_remove(opoc_blacklist_operations, &account);
        }

        true
    }

    fn opoc_complete(
    outputs_operations: &mut BTreeMap<RequestId, (Data, u32, u32, U256)>,
        request_id: &RequestId,
        output: &Data,
        total_executions: &u32,
        total_consensus: &u32,
        nft_id: &U256
    ) -> DispatchResult {
        outputs_operations.insert(request_id.clone(), (
            output.clone(),
            *total_executions,
            *total_consensus,
            *nft_id,
        ));
        Ok(())
    }
}

impl<T: Config> Pallet<T> {
    // Zero out the current era points for a validator (prevent reward payout). Idempotent.
    pub(crate) fn reset_validator_current_era_points(validator: &T::AccountId) -> Result<(), &'static str> {
        // Get current era; if staking not yet started, skip
        let current_era = match <pallet_staking::CurrentEra<T>>::get() { Some(e) => e, None => return Ok(()) };
        // Fetch era points structure (always exists after era start) and mutate in place.
        let mut era_points = <pallet_staking::ErasRewardPoints<T>>::get(current_era);
        if let Some(points_entry) = era_points.individual.get_mut(validator) {
            if *points_entry > 0 { *points_entry = 0; }
            era_points.total = era_points.individual.values().copied().sum();
            <pallet_staking::ErasRewardPoints<T>>::insert(current_era, era_points);
            <crate::pallet::ProcessedOpocTimeoutEraResets<T>>::insert(current_era, validator, ());
        }
        Ok(())
    }

    // Get the list of ProcessedOpocTimeoutEraResets for the current era and zero out the validator points
    pub(crate) fn reset_validators_current_era_points_for_current_era() -> Result<(), &'static str> {
        // Get current era; if staking not yet started, skip
        let current_era = match <pallet_staking::CurrentEra<T>>::get() { Some(e) => e, None => return Ok(())  };
        let processed_validators: Vec<T::AccountId> = <crate::pallet::ProcessedOpocTimeoutEraResets<T>>::iter_prefix(current_era)
            .map(|(validator, _)| validator).collect();
        for validator in processed_validators {
            Self::reset_validator_current_era_points(&validator)?;
            log::info!("Reset staking points for validator {:?} in era {:?}", validator, current_era);
        }
        Ok(())
    }
}
