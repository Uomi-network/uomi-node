use frame_support::pallet_prelude::*;
use frame_system::offchain::{Signer, SendUnsignedTransaction};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_std::vec::Vec;

use crate::pallet::{
    Config, DkgSessions, Event, NextSessionId, Pallet, ParticipantReportCount,
    ReportedParticipants, SessionState, AggregatedPublicKeys, Error,
};
use crate::{ProposedPublicKeys};
use crate::types::{NftId};
use crate::payloads::{ReportParticipantsPayload, SubmitDKGResultPayload, CompleteResharePayload};
use crate::types::SessionId;

impl<T: Config> Pallet<T> {
    pub fn get_next_session_id() -> SessionId {
        let session_id = Self::next_session_id();
        NextSessionId::<T>::put(session_id + 1);
        session_id
    }

    pub fn check_expired_sessions(n: BlockNumberFor<T>) -> DispatchResult {
        // Collect sessions whose deadline expired (state still not finalized)
        // IMPORTANT: Use BTreeMap for deterministic iteration order.
        // DkgSessions::iter() order depends on trie key hashing which can differ
        // between native and WASM, causing events in different order → state divergence.
        let sessions_to_remove: sp_std::collections::btree_map::BTreeMap<SessionId, NftId> =
            DkgSessions::<T>::iter()
                .filter(|(_, session)| session.state <= SessionState::DKGInProgress && n >= session.deadline)
                .map(|(session_id, session)| (session_id, session.nft_id.clone()))
                .collect();
        // Remove them & GC any residual ProposedPublicKeys for their NFT
        for (session_id, nft_id) in sessions_to_remove {
            Pallet::<T>::update_report_count(session_id).ok();
            // Emit explicit expiration event (reuse DKGFailed event for backward compat if needed)
            Pallet::<T>::deposit_event(Event::DKGExpired(session_id));
            DkgSessions::<T>::remove(session_id);
            // GC: clear any partial DKG result votes for this NFT (deadline reached, session aborted)
            let _ = ProposedPublicKeys::<T>::clear_prefix(nft_id, u32::MAX, None);
        }
        Ok(())
    }

    pub fn update_report_count(session_id: SessionId) -> DispatchResult {
        // Get the session
        let session =
            DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

    // First set the session state to DKGFailed (protocol failure path)
        DkgSessions::<T>::mutate(session_id, |session| {
            if let Some(s) = session {
                s.state = SessionState::DKGFailed;
            }
        });

        // Get the total number of participants in the session
        let total_participants = session.participants.len();

        // IMPORTANT: Collect ReportedParticipants into a BTreeMap for deterministic iteration order.
        // StorageDoubleMap::iter_prefix() order depends on trie key hashing which can differ
        // between native and WASM execution, causing state divergence.
        let all_reports: sp_std::collections::btree_map::BTreeMap<T::AccountId, _> =
            ReportedParticipants::<T>::iter_prefix(session_id).collect();

        // Build a deduplicated set of all reported participants and count how many
        // distinct reporters flagged each one. Use BTreeSet for deterministic ordering.
        let mut participant_report_counts = sp_std::collections::btree_map::BTreeMap::<T::AccountId, usize>::new();
        for (_reporter, reported_list) in all_reports.iter() {
            for reported_participant in reported_list.iter() {
                // Count how many distinct reporters flagged this participant
                let mut report_count = 0;
                for (_, inner_reported_list) in all_reports.iter() {
                    if inner_reported_list.contains(reported_participant) {
                        report_count += 1;
                    }
                }
                participant_report_counts.insert(reported_participant.clone(), report_count);
            }
        }

        // Calculate the threshold for reporting (2/3 of total participants)
        let reporting_threshold = (total_participants * 2) / 3;

        // Increment report count ONCE per participant that meets the threshold
        for (reported_participant, report_count) in participant_report_counts.iter() {
            if *report_count == reporting_threshold {
                let current_count = ParticipantReportCount::<T>::get(reported_participant);
                ParticipantReportCount::<T>::insert(
                    reported_participant,
                    current_count + 1,
                );
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
        log::debug!("[TSS] Sending.... {:?}", reported_participants_bounded);

        // Send unsigned transaction with signed payload
        let _ = signer.send_unsigned_transaction(
            |acct| ReportParticipantsPayload::<T> {
                session_id: id,
                reported_participants: reported_participants_bounded.clone(),
                public: acct.public.clone(),
            },
            |payload, signature| crate::pallet::Call::report_participant { payload, signature },
        );
        log::debug!("[TSS] Reported participants");
    }


    pub fn submit_reshare_result(session_id: SessionId) -> DispatchResult {
       
        // Create a transaction to submit
        let signer = Signer::<T, <T as crate::pallet::Config>::AuthorityId>::all_accounts();

        if !signer.can_sign() {
            log::error!("[TSS]: No accounts available to sign cast_vote_on_dkg_result");
            return Err(Error::<T>::KeyUpdateFailed.into());
        }

        log::debug!("[TSS] Sending unsigned transaction for DKG result...");

        // Send unsigned transaction with signed payload
        let _ = signer.send_unsigned_transaction(
            |acct| CompleteResharePayload::<T> {
                session_id,
                public: acct.public.clone(),
            },
            |payload, signature| crate::pallet::Call::complete_reshare_session_unsigned { payload, signature },
        );

        log::debug!("[TSS] DKG result submitted successfully.");

        Ok(())
    }


    // cast_vote_on_dkg_result is called by each validator and created. This function will sign the payload
    // and call submit_dkg_result with the signature
    pub fn cast_vote_on_dkg_result(
        session_id: SessionId,
        aggregated_key: Vec<u8>,
    ) -> DispatchResult {
        log::debug!("[TSS] Casting vote on DKG result for session_id: {:?}...", session_id);
        let aggregated_key = BoundedVec::try_from(aggregated_key)
            .map_err(|_| Error::<T>::InvalidParticipantsCount)?;
        
        // Check if the session exists
        let session =
            DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

        log::debug!("[TSS] Current session state: {:?}", session.state);
        // Check if the session is in progress
        ensure!(
            session.state <= SessionState::DKGInProgress,
            Error::<T>::InvalidSessionState
        );

        // Create a transaction to submit
        let signer = Signer::<T, <T as crate::pallet::Config>::AuthorityId>::all_accounts();

        if !signer.can_sign() {
            log::error!("[TSS]: No accounts available to sign cast_vote_on_dkg_result");
            return Err(Error::<T>::KeyUpdateFailed.into());
        }

        log::debug!("[TSS] Sending unsigned transaction for DKG result...");

        // Send unsigned transaction with signed payload
        let _ = signer.send_unsigned_transaction(
            |acct| SubmitDKGResultPayload::<T> {
                session_id,
                public_key: aggregated_key.clone(),
                public: acct.public.clone(),
            },
            |payload, signature| crate::pallet::Call::submit_dkg_result { payload, signature },
        );

        log::debug!("[TSS] DKG result submitted successfully.");

        Ok(())
    }

    pub fn finalize_dkg_session_internal(
        session_id: SessionId,
        aggregated_key: Vec<u8>,
    ) -> DispatchResult {

        let aggregated_key = BoundedVec::try_from(aggregated_key)
            .map_err(|_| Error::<T>::InvalidParticipantsCount)?;
        
        // Check if the session exists and is in the correct state
        let session =
            DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

        ensure!(
            session.state <= SessionState::DKGInProgress,
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

    // Supersede any older completed DKG sessions for same NFT
        // IMPORTANT: Collect into BTreeMap for deterministic iteration order.
        if let Some(current_session) = DkgSessions::<T>::get(session_id) {
            let to_supersede: sp_std::collections::btree_map::BTreeMap<_, _> =
                DkgSessions::<T>::iter()
                    .filter(|(id, s)| *id != session_id && s.nft_id == current_session.nft_id && s.state == SessionState::DKGComplete)
                    .collect();
            for (other_id, mut other_session) in to_supersede {
                other_session.state = SessionState::DKGSuperseded;
                DkgSessions::<T>::insert(other_id, other_session);
                Pallet::<T>::deposit_event(Event::DKGSuperseded(other_id));
            }
            // GC ProposedPublicKeys votes now that final key chosen
            let _ = ProposedPublicKeys::<T>::clear_prefix(current_session.nft_id, u32::MAX, None);
        }

        // Emit event with the session ID and aggregated key
        Self::deposit_event(Event::DKGCompleted(session_id, aggregated_key));

        Ok(())
    }
}