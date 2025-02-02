use crate::{mock::*, pallet, DKGSession, DkgSessions, Error, Event, NextSessionId};
use frame_support::{assert_ok, assert_noop};
use frame_system::RawOrigin;

use rand::{Rng, thread_rng};

fn create_test_account() -> AccountId {
    let mut rng = thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    AccountId::from_raw(seed)
}

// SANITY CHECK, DONT REMOVE
#[test]
fn test_simple_assert_ok() {
    new_test_ext().execute_with(|| {
        // Call a function that is expected to return Ok(())
        assert_ok!(dummy_function());
    });
}
fn dummy_function() -> frame_support::pallet_prelude::DispatchResult {
    Ok(())
}


#[test]
fn test_get_next_session_id() {
    new_test_ext().execute_with(|| {

        // Initial check (optional, depends on your mock setup)
        assert_eq!(TestingPallet::next_session_id(), 0, "Initial session ID should be 0");

        // Call get_next_session_id and check the returned values
        assert_eq!(TestingPallet::get_next_session_id(), 0, "First call should return 0");
        assert_eq!(TestingPallet::get_next_session_id(), 1, "Second call should return 1");
        assert_eq!(TestingPallet::get_next_session_id(), 2, "Third call should return 2");

        // Check the storage value of NextSessionId after the calls
        assert_eq!(TestingPallet::next_session_id(), 3, "NextSessionId in storage should be 3");
    });
}
#[test]

#[test]
fn test_dkg_start_session() {
    new_test_ext().execute_with(|| {
        // 1. Assert initial state (optional, but good practice)
        assert_eq!(DkgSessions::<Test>::iter_keys().count(), 0, "Initial DkgSessions count should be 0");


        let participant_1 = create_test_account();
        let participant_2 = create_test_account();

        let session_id = TestingPallet::next_session_id();
        

        let ret = TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account()), 
            vec![1].try_into().unwrap(),
            vec![participant_1, participant_2], 
            1);
        assert_ok!(ret);

        assert_eq!(DkgSessions::<Test>::iter_keys().count(), 1, "DkgSessions count should be 1 after starting a session");


        let session = TestingPallet::get_dkg_session(session_id).unwrap();

        assert_eq!(session.threshold,1);
        assert_eq!(session.participants.iter().count(), 2);
        assert_eq!(session.state, pallet::SessionState::DKGInProgress);
    });
}
#[test]
fn test_create_dkg_session_errors() {
    new_test_ext().execute_with(|| {
        let participant_1 = create_test_account();
        let participant_2 = create_test_account();
        let participant_3 = create_test_account();
        
        // Test empty participants list
        assert_noop!(
            TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(participant_1),
                vec![1].try_into().unwrap(),
                vec![],
                1
            ),
            Error::<Test>::InvalidParticipantsCount
        );

        // Test threshold greater than participants count
        assert_noop!(
            TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(participant_1),
                vec![1].try_into().unwrap(),
                vec![participant_1, participant_2],
                3
            ),
            Error::<Test>::InvalidThreshold
        );

        // Test threshold of zero
        assert_noop!(
            TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(participant_1),
                vec![1].try_into().unwrap(),
                vec![participant_1, participant_2],
                0
            ),
            Error::<Test>::InvalidThreshold
        );

        // Test duplicate participants
        assert_noop!(
            TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(participant_1),
                vec![1].try_into().unwrap(),
                vec![participant_1, participant_1],
                1
            ),
            Error::<Test>::DuplicateParticipant
        );
    });
}
