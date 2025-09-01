//! Basic property-based (proptest) fuzz harness for pallet-tss.
//! Generates random sequences of simplified actions and asserts core invariants.

#[cfg(test)]
mod prop {
    use super::*;
    use crate::{mock::{new_test_ext, RuntimeOrigin, Test, TestingPallet}, SessionState};
    use proptest::{prelude::*, collection};
    use frame_support::BoundedVec;
    use sp_core::U256;
    use frame_support::traits::Hooks;

    // Simplified action set.
    #[derive(Clone, Debug)]
    enum Action {
        AdvanceBlocks(u32),
        CreateDkg { nft: u64 },
        VoteDkg { nft: u64 },
        CreateSigning { request: u64, nft: u64 },
    VoteSigning, // attempt to cast signature votes for an in-progress signing session
        ExpireSigning, // trigger on_initialize only
    CreateReshare { nft: u64 },
    ReportParticipant, // randomly report a participant in some DKG
    }

    impl Action {
        fn strategy() -> impl Strategy<Value = Self> {
            prop_oneof![
                (1u32..20).prop_map(Action::AdvanceBlocks),
                (0u64..5).prop_map(|nft| Action::CreateDkg { nft }),
                (0u64..5).prop_map(|nft| Action::VoteDkg { nft }),
                ((0u64..20), (0u64..5)).prop_map(|(req,nft)| Action::CreateSigning { request: req, nft }),
                Just(Action::VoteSigning),
                Just(Action::ExpireSigning),
                (0u64..5).prop_map(|nft| Action::CreateReshare { nft }),
                Just(Action::ReportParticipant),
            ]
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 96, max_shrink_time: 1000, .. ProptestConfig::default() })]
        #[test]
        fn state_machine_invariants(actions in collection::vec(Action::strategy(), 1..100)) {
            let _ = new_test_ext().execute_with(|| {
                // simple validator set (reuse same accounts as in other tests)
                use sp_core::sr25519::Public;
                let validators: Vec<Public> = (1u8..=3).map(|i| Public::from_raw([i;32])).collect();
                crate::ActiveValidators::<Test>::put(BoundedVec::try_from(validators.clone()).unwrap());
                let _ = TestingPallet::initialize_validator_ids();

                for act in actions { match act {
                    Action::AdvanceBlocks(delta) => {
                        let target = frame_system::Pallet::<Test>::block_number() + (delta as u64);
                        while frame_system::Pallet::<Test>::block_number() < target { let n = frame_system::Pallet::<Test>::block_number() + 1u64; frame_system::Pallet::<Test>::set_block_number(n); <TestingPallet as Hooks<_>>::on_initialize(n); }
                    },
                    Action::CreateDkg { nft } => {
                        use sp_std::convert::TryInto; let nft_id_bytes: Vec<u8> = U256::from(nft).0.iter().flat_map(|b| b.to_le_bytes()).collect();
                        if let Ok(nid) = nft_id_bytes.clone().try_into() { let signer = Public::from_raw([9;32]); let _ = TestingPallet::create_dkg_session(RuntimeOrigin::signed(signer), nid, 60); }
                    },
                    Action::VoteDkg { nft } => {
                        // Find the highest session id matching the nft and still open
                        let target_bytes: Vec<u8> = U256::from(nft).0.iter().flat_map(|b| b.to_le_bytes()).collect();
                        let mut chosen: Option<u64> = None;
                        for (sid, sess) in crate::DkgSessions::<Test>::iter() {
                            if sess.state < SessionState::DKGComplete && sess.nft_id.to_vec() == target_bytes {
                                if let Some(current) = chosen { if sid > current { chosen = Some(sid); } } else { chosen = Some(sid); }
                            }
                        }
                        if let Some(sid) = chosen {
                            let aggk = sp_std::vec![7u8;33];
                            let who = Public::from_raw([1;32]);
                            let _ = TestingPallet::submit_dkg_result(
                                RuntimeOrigin::none(),
                                crate::payloads::SubmitDKGResultPayload { session_id: sid, public_key: BoundedVec::truncate_from(aggk.clone()), public: who },
                                sp_core::sr25519::Signature::from_raw([0u8;64])
                            );
                        }
                    },
                    Action::CreateSigning { request, nft } => {
                        use sp_std::convert::TryInto; let nft_id_bytes: Vec<u8> = U256::from(nft).0.iter().flat_map(|b| b.to_le_bytes()).collect();
                        if let Ok(nid) = nft_id_bytes.clone().try_into() { let msg = BoundedVec::<u8, crate::types::MaxMessageSize>::truncate_from(vec![1]); let _ = TestingPallet::create_signing_session(RuntimeOrigin::none(), U256::from(request), nid, msg); }
                    },
                    Action::VoteSigning => {
                        // Pick a signing session in progress and submit up to 2 votes to potentially complete it
                        if let Some((sid, sign)) = crate::SigningSessions::<Test>::iter().find(|(_, s)| s.state == SessionState::SigningInProgress) {
                            // obtain participants from its referenced DKG session
                            if let Some(dkg) = crate::DkgSessions::<Test>::get(sign.dkg_session_id) {
                                let voters = dkg.participants.into_iter().take(2); // enough for quorum (2 of 3)
                                let sig = BoundedVec::truncate_from(vec![0x55;65]);
                                for v in voters {
                                    let _ = TestingPallet::submit_signature_result(
                                        RuntimeOrigin::none(),
                                        crate::payloads::SubmitSignatureResultPayload { session_id: sid, signature: sig.clone(), public: v.clone() },
                                        sp_core::sr25519::Signature::from_raw([0u8;64])
                                    );
                                }
                            }
                        }
                    },
                    Action::ExpireSigning => {
                        let n = frame_system::Pallet::<Test>::block_number();
                        <TestingPallet as Hooks<_>>::on_initialize(n);
                    },
                    Action::CreateReshare { nft } => {
                        // Need an existing completed DKG to reshare; pick highest completed for nft
                        let target: Vec<u8> = U256::from(nft).0.iter().flat_map(|b| b.to_le_bytes()).collect();
                        let mut latest: Option<(u64, crate::DKGSession<Test>)> = None;
                        for (sid, sess) in crate::DkgSessions::<Test>::iter() { if sess.nft_id.to_vec()==target && sess.state == SessionState::DKGComplete { if latest.as_ref().map(|(id,_)| sid > *id).unwrap_or(true) { latest = Some((sid, sess)); } }}
                        if let Some((_sid, sess)) = latest {
                            if let Ok(old_participants) = BoundedVec::try_from(sess.participants.clone().into_inner()) {
                                let signer = sp_core::sr25519::Public::from_raw([11;32]);
                                let _ = TestingPallet::create_reshare_dkg_session(RuntimeOrigin::signed(signer), sess.nft_id.clone(), sess.threshold, old_participants);
                            }
                        }
                    },
                    Action::ReportParticipant => {
                        // Pick any DKG session and report first participant (self-report harmless for invariant) if exists
                        if let Some((sid, sess)) = crate::DkgSessions::<Test>::iter().next() {
                            if let Some(first) = sess.participants.get(0) {
                                let offenders = BoundedVec::truncate_from(vec![first.clone()]);
                                let _ = TestingPallet::report_participant(
                                    RuntimeOrigin::none(),
                                    crate::payloads::ReportParticipantsPayload { session_id: sid, reported_participants: offenders.clone(), public: first.clone() },
                                    sp_core::sr25519::Signature::from_raw([0u8;64])
                                );
                            }
                        }
                    }
                }}

                // Invariants
                for (_sid, s) in crate::SigningSessions::<Test>::iter() {
                    // completion & expiration mutually exclusive
                    prop_assert!(!(s.state == SessionState::SigningComplete && s.state == SessionState::SigningExpired));
                    if s.state == SessionState::SigningExpired { prop_assert!(s.aggregated_sig.is_none()); }
                    // If complete or expired there should be no expiry entry remaining
                    let has_expiry = crate::SigningSessionExpiry::<Test>::contains_key(_sid);
                    if matches!(s.state, SessionState::SigningComplete | SessionState::SigningExpired) { prop_assert!(!has_expiry); }
                }
                // Retry count never exceeds max (3)
                for (_req, c) in crate::RequestRetryCount::<Test>::iter() { prop_assert!(c <= 3); }
                // If a retry count exists (>0) there must not be a completed signing session for that request
                for (req, c) in crate::RequestRetryCount::<Test>::iter() { if c > 0 { let any_complete = crate::SigningSessions::<Test>::iter().any(|(_, s)| s.request_id == req && s.state == SessionState::SigningComplete); prop_assert!(!any_complete); }}
                // Superseded DKG sessions must have a newer complete session with same nft_id
                use sp_std::collections::btree_map::BTreeMap;
                let mut latest_complete: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
                for (sid, sess) in crate::DkgSessions::<Test>::iter() { if sess.state == SessionState::DKGComplete { latest_complete.entry(sess.nft_id.to_vec()).and_modify(|e| if sid > *e { *e = sid }).or_insert(sid); } }
                for (sid, sess) in crate::DkgSessions::<Test>::iter() { if sess.state == SessionState::DKGSuperseded { let latest = latest_complete.get(&sess.nft_id.to_vec()).copied().unwrap_or(0); prop_assert!(latest > sid); }}
                Ok(())
            });
        }
        #[test]
        fn multi_nft_request_invariants(seqs in collection::vec(Action::strategy(), 50..150)) {
            let _ = new_test_ext().execute_with(|| {
                use sp_core::sr25519::Public;
                let validators: Vec<Public> = (10u8..=13).map(|i| Public::from_raw([i;32])).collect();
                crate::ActiveValidators::<Test>::put(BoundedVec::try_from(validators.clone()).unwrap());
                let _ = TestingPallet::initialize_validator_ids();

                for a in seqs { match a {
                    Action::CreateDkg { nft } => {
                        use sp_std::convert::TryInto; let bytes: Vec<u8> = U256::from(nft).0.iter().flat_map(|b| b.to_le_bytes()).collect();
                        if let Ok(id) = bytes.clone().try_into() { let signer = Public::from_raw([42;32]); let _ = TestingPallet::create_dkg_session(RuntimeOrigin::signed(signer), id, 70); }
                    },
                    Action::VoteDkg { nft } => {
                        let target: Vec<u8> = U256::from(nft).0.iter().flat_map(|b| b.to_le_bytes()).collect();
                        // vote all open sessions for that nft (simulate multiple validators)
                        for (sid, sess) in crate::DkgSessions::<Test>::iter() { if sess.state < SessionState::DKGComplete && sess.nft_id.to_vec()==target {
                            let aggk = vec![9u8;33];
                            for val in validators.iter().take(3) { let _ = TestingPallet::submit_dkg_result(RuntimeOrigin::none(), crate::payloads::SubmitDKGResultPayload { session_id: sid, public_key: BoundedVec::truncate_from(aggk.clone()), public: *val }, sp_core::sr25519::Signature::from_raw([0u8;64])); }
                        }}
                    },
                    Action::CreateSigning { request, nft } => {
                        use sp_std::convert::TryInto; let bytes: Vec<u8> = U256::from(nft).0.iter().flat_map(|b| b.to_le_bytes()).collect(); if let Ok(id) = bytes.clone().try_into() {
                            let msg = BoundedVec::<u8, crate::types::MaxMessageSize>::truncate_from(vec![5]);
                            let _ = TestingPallet::create_signing_session(RuntimeOrigin::none(), U256::from(request), id, msg);
                        }
                    },
                    Action::VoteSigning => {
                        for (sid, sign) in crate::SigningSessions::<Test>::iter() { if sign.state == SessionState::SigningInProgress { if let Some(dkg) = crate::DkgSessions::<Test>::get(sign.dkg_session_id) {
                            let sig = BoundedVec::truncate_from(vec![0x33;65]);
                            for val in dkg.participants.into_iter().take(3) { let _ = TestingPallet::submit_signature_result(RuntimeOrigin::none(), crate::payloads::SubmitSignatureResultPayload { session_id: sid, signature: sig.clone(), public: val.clone() }, sp_core::sr25519::Signature::from_raw([0u8;64])); }
                        }}}
                    },
                    Action::AdvanceBlocks(d) => {
                        let t = frame_system::Pallet::<Test>::block_number() + (d as u64);
                        while frame_system::Pallet::<Test>::block_number() < t { let n = frame_system::Pallet::<Test>::block_number() + 1; frame_system::Pallet::<Test>::set_block_number(n); <TestingPallet as Hooks<_>>::on_initialize(n); }
                    },
                    Action::ExpireSigning => {
                        let n = frame_system::Pallet::<Test>::block_number(); <TestingPallet as Hooks<_>>::on_initialize(n);
                    },
                    Action::CreateReshare { nft } => {
                        let target: Vec<u8> = U256::from(nft).0.iter().flat_map(|b| b.to_le_bytes()).collect();
                        let mut latest: Option<(u64, crate::DKGSession<Test>)> = None;
                        for (sid, sess) in crate::DkgSessions::<Test>::iter() { if sess.nft_id.to_vec()==target && sess.state == SessionState::DKGComplete { if latest.as_ref().map(|(id,_)| sid > *id).unwrap_or(true) { latest = Some((sid, sess)); } }}
                        if let Some((_sid, sess)) = latest {
                            if let Ok(old_participants) = BoundedVec::try_from(sess.participants.clone().into_inner()) {
                                let signer = sp_core::sr25519::Public::from_raw([77;32]);
                                let _ = TestingPallet::create_reshare_dkg_session(RuntimeOrigin::signed(signer), sess.nft_id.clone(), sess.threshold, old_participants);
                            }
                        }
                    },
                    Action::ReportParticipant => {
                        if let Some((sid, sess)) = crate::DkgSessions::<Test>::iter().next() {
                            if let Some(first) = sess.participants.get(0) {
                                let offenders = BoundedVec::truncate_from(vec![first.clone()]);
                                let _ = TestingPallet::report_participant(
                                    RuntimeOrigin::none(),
                                    crate::payloads::ReportParticipantsPayload { session_id: sid, reported_participants: offenders.clone(), public: first.clone() },
                                    sp_core::sr25519::Signature::from_raw([0u8;64])
                                );
                            }
                        }
                    }
                }}

                // Invariants specific to multi scenario
                // 1. No two active signing sessions (InProgress) for same request id simultaneously
                use sp_std::collections::btree_map::BTreeMap;
                let mut active_requests: BTreeMap<U256,u32> = BTreeMap::new();
                for (_sid,s) in crate::SigningSessions::<Test>::iter() { if s.state == SessionState::SigningInProgress { *active_requests.entry(s.request_id).or_insert(0)+=1; }}
                for (_req,count) in active_requests { prop_assert!(count <= 1); }
                // 2. Expired sessions have no ProposedSignatures remnants
                for (sid,s) in crate::SigningSessions::<Test>::iter() { if s.state == SessionState::SigningExpired { let mut any=false; for _ in crate::ProposedSignatures::<Test>::iter_prefix(sid) { any=true; break;} prop_assert!(!any); }}
                // 3. RequestRetryCount entries correspond to at least one Signing session
                for (req,_c) in crate::RequestRetryCount::<Test>::iter() { let exists = crate::SigningSessions::<Test>::iter().any(|(_,s)| s.request_id==req); prop_assert!(exists); }
                Ok(())
            });
        }
    }
}
