use frame_support::pallet_prelude::*;
use frame_system::offchain::{Signer, SendUnsignedTransaction};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_std::vec::Vec;

use crate::pallet::{
    Config, DkgSessions, Event, NextSessionId, Pallet, ParticipantReportCount, 
    ReportedParticipants, SessionState, AggregatedPublicKeys, Error,
};
use crate::payloads::{ReportParticipantsPayload, SubmitDKGResultPayload};
use crate::types::SessionId;

impl<T: Config> Pallet<T> {
    pub fn get_next_session_id() -> SessionId {
        let session_id = Self::next_session_id();
        NextSessionId::<T>::put(session_id + 1);
        session_id
    }

    pub fn check_expired_sessions(n: BlockNumberFor<T>) -> DispatchResult {
        // Fetch all the sessions in progress and verify if they are still valid or deadline has passed
        let mut sessions_to_remove = Vec::new();
        for (session_id, session) in DkgSessions::<T>::iter() {
            // Check if the session is in progress and if the deadline has passed
            if session.state <= SessionState::DKGInProgress {
                let deadline = session.deadline;
                if n >= deadline {
                    sessions_to_remove.push(session_id);
                }
            }
        }
        
        for session_id in sessions_to_remove {
            Pallet::<T>::update_report_count(session_id).ok();
            Pallet::<T>::deposit_event(Event::DKGFailed(session_id));
            DkgSessions::<T>::remove(session_id);
        }

        Ok(())
    }

    pub fn update_report_count(session_id: SessionId) -> DispatchResult {
        // Get the session
        let session =
            DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

        // First set the session state to DKGFailed
        DkgSessions::<T>::mutate(session_id, |session| {
            if let Some(s) = session {
                s.state = SessionState::DKGFailed;
            }
        });

        // Get the total number of participants in the session
        let total_participants = session.participants.len();

        // Iterate over all reported participants for this session
        for (_reporter, reported_list) in ReportedParticipants::<T>::iter_prefix(session_id) {
            // Iterate over each reported participant
            for reported_participant in reported_list.iter() {
                // Count how many times this participant has been reported
                let mut report_count = 0;
                for (_, inner_reported_list) in
                    ReportedParticipants::<T>::iter_prefix(session_id)
                {
                    if inner_reported_list.contains(reported_participant) {
                        report_count += 1;
                    }
                }

                // Calculate the threshold for reporting (2/3 of total participants)
                let reporting_threshold = (total_participants * 2) / 3;

                // Check if the participant has been reported by more than 2/3 of the participants
                if report_count == reporting_threshold {
                    // Increment the report count for this participant
                    let current_count = ParticipantReportCount::<T>::get(reported_participant);
                    ParticipantReportCount::<T>::insert(
                        reported_participant,
                        current_count + 1,
                    );
                }
            }
        }
        Ok(())
    }

    pub fn report_participants(id: SessionId, reported_participants: Vec<[u8; 32]>) {
        log::info!(
            "[TSS] Reporting participants... {:?}",
            reported_participants
        );
        // Create a transaction to submit
        let signer = Signer::<T, <T as crate::pallet::Config>::AuthorityId>::all_accounts();

        if !signer.can_sign() {
            log::error!("TSS: No accounts available to sign report_participant");
            return;
        }
        let reported_participants_bounded = BoundedVec::try_from(
            reported_participants
                .iter()
                .map(|x| T::AccountId::decode(&mut &x[..]).unwrap())
                .collect::<Vec<T::AccountId>>(),
        )
        .unwrap();
        log::info!("[TSS] Sending.... {:?}", reported_participants_bounded);

        // Send unsigned transaction with signed payload
        let _ = signer.send_unsigned_transaction(
            |acct| ReportParticipantsPayload::<T> {
                session_id: id,
                reported_participants: reported_participants_bounded.clone(),
                public: acct.public.clone(),
            },
            |payload, signature| crate::pallet::Call::report_participant { payload, signature },
        );
        log::info!("[TSS] Reported participants");
    }

    // cast_vote_on_dkg_result is called by each validator and created. This function will sign the payload
    // and call submit_dkg_result with the signature
    pub fn cast_vote_on_dkg_result(
        session_id: SessionId,
        aggregated_key: Vec<u8>,
    ) -> DispatchResult {
        let aggregated_key = BoundedVec::try_from(aggregated_key)
            .map_err(|_| Error::<T>::InvalidParticipantsCount)?;
        
        // Check if the session exists
        let session =
            DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

        // Check if the session is in progress
        ensure!(
            session.state <= SessionState::DKGInProgress,
            Error::<T>::InvalidSessionState
        );

        // Create a transaction to submit
        let signer = Signer::<T, <T as crate::pallet::Config>::AuthorityId>::all_accounts();

        if !signer.can_sign() {
            log::error!("TSS: No accounts available to sign cast_vote_on_dkg_result");
            return Err(Error::<T>::KeyUpdateFailed.into());
        }

        // Send unsigned transaction with signed payload
        let _ = signer.send_unsigned_transaction(
            |acct| SubmitDKGResultPayload::<T> {
                session_id,
                public_key: aggregated_key.clone(),
                public: acct.public.clone(),
            },
            |payload, signature| crate::pallet::Call::submit_dkg_result { payload, signature },
        );

        Ok(())
    }

    pub fn finalize_dkg_session(
        session_id: SessionId,
        aggregated_key: Vec<u8>,
    ) -> DispatchResult {

        let aggregated_key = BoundedVec::try_from(aggregated_key)
            .map_err(|_| Error::<T>::InvalidParticipantsCount)?;
        
        // Check if the session exists and is in the correct state
        let session =
            DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

        ensure!(
            session.state == SessionState::DKGInProgress,
            Error::<T>::InvalidSessionState
        );

        // Update the session state to DKGComplete
        DkgSessions::<T>::mutate(session_id, |session| {
            if let Some(s) = session {
                s.state = SessionState::DKGComplete;
            }
        });

        // Store the aggregated public key
        AggregatedPublicKeys::<T>::insert(session_id, aggregated_key.clone());

        // Emit event with the session ID and aggregated key
        Self::deposit_event(Event::DKGCompleted(session_id, aggregated_key));

        Ok(())
    }
}