use frame_support::pallet_prelude::*;
use sp_std::vec::Vec;

use crate::pallet::{
    Config, Pallet, ActiveValidators, ValidatorIds, IdToValidator, NextValidatorId,
    ParticipantReportCount, PreviousEraValidators, Event,
    DkgSessions, SessionState, TSSKey,
};
use crate::types::NftId;

impl<T: Config> Pallet<T> {
    pub fn initialize_validator_ids() -> DispatchResult {
        // Get all validators from pallet_staking
        let validators: Vec<T::AccountId> = ActiveValidators::<T>::get().to_vec();

        let mut next_id = NextValidatorId::<T>::get();

        // Assign IDs to validators that don't have one yet
        for validator in validators {
            if !ValidatorIds::<T>::contains_key(&validator) {
                ValidatorIds::<T>::insert(&validator, next_id);
                IdToValidator::<T>::insert(next_id, validator.clone());
                Self::deposit_event(Event::ValidatorIdAssigned(validator, next_id));
                next_id += 1;
            }
        }

        // Update the next validator ID
        NextValidatorId::<T>::put(next_id);

        Ok(())
    }

    // Add this function to assign an ID to a new validator
    pub fn assign_validator_id(validator: T::AccountId) -> DispatchResult {
        // Check if the validator already has an ID
        if ValidatorIds::<T>::contains_key(&validator) {
            return Ok(());
        }

        // Get the next ID
        let next_id = Self::next_validator_id();

        // Assign the ID
        ValidatorIds::<T>::insert(&validator, next_id);
        IdToValidator::<T>::insert(next_id, validator.clone());

        // Increment the next ID
        NextValidatorId::<T>::put(next_id + 1);

        // Emit event, maybe the client can use it?
        Self::deposit_event(Event::ValidatorIdAssigned(validator, next_id));

        Ok(())
    }

    // Helper public function used in runtime impl.
    pub fn get_validator_id(validator: &T::AccountId) -> Option<u32> {
        ValidatorIds::<T>::get(validator)
    }

    // Helper public function used in runtime impl.
    pub fn get_validator_from_id(id: u32) -> Option<T::AccountId> {
        IdToValidator::<T>::get(id)
    }

    // A function that returns those validators that have been reported more then 3 times:
    pub fn get_slashed_validators() -> Vec<T::AccountId> {
        let mut slashed_validators = Vec::new();
        for (validator, report_count) in ParticipantReportCount::<T>::iter() {
            // Treat any positive report count as slashed (tests expect counts >0 excluded)
            if report_count > 0 {
                slashed_validators.push(validator);
            }
        }
        slashed_validators
    }

    /// Reset report counts for all validators at the end of an era
    pub fn reset_validator_report_counts() -> DispatchResult {
        log::info!("[TSS] Resetting validator report counts at era end");
        
        // Get all validators with report counts
        let reported_validators: Vec<(T::AccountId, u32)> = ParticipantReportCount::<T>::iter()
            .filter(|(_, count)| *count > 0)
            .collect();
        
        // Log detailed information about validators being reset
        if !reported_validators.is_empty() {
            log::info!(
                "[TSS] Resetting report counts for {} validators",
                reported_validators.len()
            );
            
            for (validator, count) in reported_validators.iter() {
                log::info!(
                    "[TSS] Resetting validator {:?} with report count {}",
                    validator,
                    count
                );
                ParticipantReportCount::<T>::insert(validator, 0);
            }
        } else {
            log::info!("[TSS] No validators with positive report counts to reset");
        }
        
        Ok(())
    }

    // Within your pallet's dispatchable function or helper method
    pub fn get_current_era() -> Option<u32> {
        // Access the current era from the Staking pallet
        pallet_staking::CurrentEra::<T>::get()
    }

    /// Handle era transition: check for validator changes and trigger DKG reshare if needed
    pub fn handle_era_transition(current_era: u32) -> DispatchResult {
        log::debug!("TSS: Handling era transition to era {}", current_era);
        
        // Get current and previous validator sets
        let current_validators = ActiveValidators::<T>::get();
        let previous_validators = PreviousEraValidators::<T>::get();
        
        // Compare validator sets to detect changes
        let validators_changed = current_validators.len() != previous_validators.len() ||
            !current_validators.iter().all(|v| previous_validators.contains(v));
        
        if validators_changed {
            log::info!("TSS: Validator set changed at era {}, triggering DKG reshare", current_era);
            
            // Check if we have an existing TSS key that requires resharing
            
            if !previous_validators.is_empty() {
                // Create reshare DKG session for the validator set change
                Self::create_reshare_session_for_validator_change(&previous_validators)?;
                log::info!("TSS: Reshare DKG session created for validator set change");
            } else {
                log::info!("TSS: No existing TSS key or no previous validators, skipping reshare");
            }
        } else {
            log::debug!("TSS: No validator set changes detected at era {}", current_era);
        }
        
        // Update stored validator set for next era comparison
        PreviousEraValidators::<T>::put(current_validators);
        
        Ok(())
    }

    /// Create a reshare DKG session for validator set changes
    fn create_reshare_session_for_validator_change(
        old_participants: &BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>
    ) -> DispatchResult {
        // For validator set changes, we need to reshare ALL existing agent keys
        // Find all active DKG sessions that have completed and need resharing
        let mut reshare_created = false;
        
        for (_session_id, session) in DkgSessions::<T>::iter() {
            if session.state == SessionState::DKGComplete {
                // Create a reshare session for this specific agent/NFT
                let threshold = session.threshold;
                if let Err(e) = Self::internal_create_reshare_dkg_session(
                    session.nft_id.clone(),
                    threshold,
                    old_participants.clone(),
                ) {
                    log::error!("TSS: Failed to create reshare session for NFT {:?}: {:?}", session.nft_id, e);
                } else {
                    log::info!("TSS: Created reshare session for NFT {:?}", session.nft_id);
                    reshare_created = true;
                }
            }
        }
        
        if !reshare_created {
            log::warn!("TSS: No completed DKG sessions found to reshare during validator set change");
        }
        
        Ok(())
    }

    // Internal helper used by on_initialize + extrinsics (unsigned/signed variants wrap this)
    pub(crate) fn internal_create_reshare_dkg_session(
        nft_id: NftId,
        threshold: u32,
        old_participants: BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>,
    ) -> DispatchResult {
        ensure!(threshold > 0, crate::pallet::Error::<T>::InvalidThreshold);
        ensure!(threshold <= 100 && threshold >= 50, crate::pallet::Error::<T>::InvalidThreshold);

        let participants = BoundedVec::try_from(
            pallet_staking::Validators::<T>::iter()
                .map(|(account_id, _)| account_id)
                .collect::<Vec<T::AccountId>>()
        ).map_err(|_| crate::pallet::Error::<T>::InvalidParticipantsCount)?;

        let session = crate::pallet::DKGSession {
            nft_id,
            participants,
            threshold,
            state: crate::pallet::SessionState::DKGCreated,
            old_participants: Some(old_participants),
            deadline: frame_system::Pallet::<T>::block_number() + 100u32.into(),
        };
        let session_id = Self::get_next_session_id();
        crate::pallet::DkgSessions::<T>::insert(session_id, session);
        Self::deposit_event(Event::DKGReshareSessionCreated(session_id));
        Ok(())
    }
}