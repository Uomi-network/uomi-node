use crate::{mock::*, pallet, DkgSessions};
use frame_support::assert_ok;


// Helper function to create test account
fn create_test_account() -> AccountId {
    let seed = [0u8; 32];
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
fn test_dkg_start_session() {
    new_test_ext().execute_with(|| {
        // 1. Assert initial state (optional, but good practice)
        assert_eq!(DkgSessions::<Test>::iter_keys().count(), 0, "Initial DkgSessions count should be 0");

        let session_id = TestingPallet::next_session_id();
        

        let ret = TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account()), 
            vec![1].try_into().unwrap(),
            60);
        assert_ok!(ret);

        assert_eq!(DkgSessions::<Test>::iter_keys().count(), 1, "DkgSessions count should be 1 after starting a session");


        let session = TestingPallet::get_dkg_session(session_id).unwrap();

        assert_eq!(session.threshold, 60);
        assert_eq!(session.participants.iter().count(), 0);
        assert_eq!(session.state, pallet::SessionState::DKGCreated);
    });
}
#[test]
fn test_create_dkg_session_errors() {
    new_test_ext().execute_with(|| {
        let participant_1 = create_test_account();
        let participant_2 = create_test_account();
        let participant_3 = create_test_account();
        
        
    });
}
