use std::sync::Arc;

use crate::{
    mock::*, pallet, types::MaxNumberOfShares, DkgSessions, UpdateValidatorsPayload,
    CRYPTO_KEY_TYPE,
};
use frame_support::{assert_ok, traits::OffchainWorker};
use sp_core::{
    offchain::{
        testing::{TestOffchainExt, TestTransactionPoolExt},
        OffchainDbExt, OffchainWorkerExt, TransactionPoolExt,
    },
    sr25519::{self, Signature},
    Pair,
};
use sp_keystore::{testing::MemoryKeystore, Keystore, KeystoreExt};
use sp_runtime::{BoundedVec, Perbill};

// Helper function to create test account
fn create_test_account(seed: Option<[u8; 32]>) -> AccountId {
    let seed = seed.unwrap_or([0u8; 32]);
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
        assert_eq!(
            TestingPallet::next_session_id(),
            0,
            "Initial session ID should be 0"
        );

        // Call get_next_session_id and check the returned values
        assert_eq!(
            TestingPallet::get_next_session_id(),
            0,
            "First call should return 0"
        );
        assert_eq!(
            TestingPallet::get_next_session_id(),
            1,
            "Second call should return 1"
        );
        assert_eq!(
            TestingPallet::get_next_session_id(),
            2,
            "Third call should return 2"
        );

        // Check the storage value of NextSessionId after the calls
        assert_eq!(
            TestingPallet::next_session_id(),
            3,
            "NextSessionId in storage should be 3"
        );
    });
}

#[test]
fn test_dkg_start_session() {
    new_test_ext().execute_with(|| {
        // 1. Assert initial state (optional, but good practice)
        assert_eq!(
            DkgSessions::<Test>::iter_keys().count(),
            0,
            "Initial DkgSessions count should be 0"
        );

        let session_id = TestingPallet::next_session_id();

        let ret = TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            60,
        );
        assert_ok!(ret);

        assert_eq!(
            DkgSessions::<Test>::iter_keys().count(),
            1,
            "DkgSessions count should be 1 after starting a session"
        );

        let session = TestingPallet::get_dkg_session(session_id).unwrap();

        assert_eq!(session.threshold, 60);
        assert_eq!(session.participants.iter().count(), 0);
        assert_eq!(session.state, pallet::SessionState::DKGCreated);
    });
}
#[test]
fn test_create_dkg_session_errors() {
    new_test_ext().execute_with(|| {
        let participant_1 = create_test_account(Some([1u8; 32]));
        let participant_2 = create_test_account(Some([2u8; 32]));
        let participant_3 = create_test_account(Some([3u8; 32]));

        // Test with invalid threshold (0)
        let result = TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(participant_1.clone()),
            vec![1].try_into().unwrap(),
            0,
        );
        assert_eq!(result, Err(pallet::Error::<Test>::InvalidThreshold.into()));

        // Test with invalid threshold (101)
        let result = TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(participant_2.clone()),
            vec![1].try_into().unwrap(),
            101,
        );
        assert_eq!(result, Err(pallet::Error::<Test>::InvalidThreshold.into()));

        // Test with invalid threshold (49)
        let result = TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(participant_3.clone()),
            vec![1].try_into().unwrap(),
            49,
        );
        assert_eq!(result, Err(pallet::Error::<Test>::InvalidThreshold.into()));
    });
}

#[test]
fn test_create_reshare_dkg_session() {
    new_test_ext().execute_with(|| {
        // 1. Assert initial state (optional, but good practice)
        assert_eq!(
            DkgSessions::<Test>::iter_keys().count(),
            0,
            "Initial DkgSessions count should be 0"
        );

        let session_id = TestingPallet::next_session_id();
        let old_participants: BoundedVec<AccountId, MaxNumberOfShares> = vec![
            create_test_account(Some([1u8; 32])),
            create_test_account(Some([2u8; 32])),
        ]
        .try_into()
        .unwrap();

        let ret = TestingPallet::create_reshare_dkg_session(
            RuntimeOrigin::signed(create_test_account(Some([3u8; 32]))),
            vec![1].try_into().unwrap(),
            60,
            old_participants.clone(),
        );
        assert_ok!(ret);

        assert_eq!(
            DkgSessions::<Test>::iter_keys().count(),
            1,
            "DkgSessions count should be 1 after starting a session"
        );

        let session = TestingPallet::get_dkg_session(session_id).unwrap();

        assert_eq!(session.threshold, 60);
        assert_eq!(session.participants.iter().count(), 0);
        assert_eq!(session.state, pallet::SessionState::DKGCreated);
        assert_eq!(session.old_participants.unwrap(), old_participants);
    });
}

#[test]
fn test_create_reshare_dkg_session_errors() {
    new_test_ext().execute_with(|| {
        let participant_1 = create_test_account(Some([1u8; 32]));
        let participant_2 = create_test_account(Some([2u8; 32]));
        let participant_3 = create_test_account(Some([3u8; 32]));
        let old_participants: BoundedVec<AccountId, MaxNumberOfShares> = vec![
            create_test_account(Some([1u8; 32])),
            create_test_account(Some([2u8; 32])),
        ]
        .try_into()
        .unwrap();

        // Test with invalid threshold (0)
        let result = TestingPallet::create_reshare_dkg_session(
            RuntimeOrigin::signed(participant_1.clone()),
            vec![1].try_into().unwrap(),
            0,
            old_participants.clone(),
        );
        assert_eq!(result, Err(pallet::Error::<Test>::InvalidThreshold.into()));

        // Test with invalid threshold (101)
        let result = TestingPallet::create_reshare_dkg_session(
            RuntimeOrigin::signed(participant_2.clone()),
            vec![1].try_into().unwrap(),
            101,
            old_participants.clone(),
        );
        assert_eq!(result, Err(pallet::Error::<Test>::InvalidThreshold.into()));

        // Test with invalid threshold (49)
        let result = TestingPallet::create_reshare_dkg_session(
            RuntimeOrigin::signed(participant_3.clone()),
            vec![1].try_into().unwrap(),
            49,
            old_participants.clone(),
        );
        assert_eq!(result, Err(pallet::Error::<Test>::InvalidThreshold.into()));
    });
}

#[test]
fn test_submit_dkg_result() {
    new_test_ext().execute_with(|| {
        // Create a DKG session first
        let session_id = TestingPallet::next_session_id();
        assert_ok!(TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            60
        ));

        // Check that the session was created
        assert!(TestingPallet::get_dkg_session(session_id).is_some());

        // Submit the DKG result
        let aggregated_key = [1u8; 32];
        let submitter = create_test_account(None);
        let mut session = TestingPallet::get_dkg_session(session_id).unwrap();
        session.participants.try_push(submitter.clone()).unwrap();
        DkgSessions::<Test>::insert(session_id, session);

        assert_ok!(TestingPallet::submit_dkg_result(
            RuntimeOrigin::signed(submitter.clone()),
            session_id,
            BoundedVec::truncate_from(aggregated_key.to_vec())
        ));

        // Check that the session state was updated
        let updated_session = TestingPallet::get_dkg_session(session_id).unwrap();
        assert_eq!(updated_session.state, pallet::SessionState::DKGComplete);
    });
}

#[test]
fn test_submit_dkg_result_errors() {
    new_test_ext().execute_with(|| {
        // Create a DKG session first
        let session_id = TestingPallet::next_session_id();
        assert_ok!(TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            60
        ));

        // Check that the session was created
        assert!(TestingPallet::get_dkg_session(session_id).is_some());

        // Submit the DKG result with an unauthorized participant
        let aggregated_key = [1u8; 32];
        let unauthorized_submitter = create_test_account(None);
        assert_eq!(
            TestingPallet::submit_dkg_result(
                RuntimeOrigin::signed(unauthorized_submitter.clone()),
                session_id,
                BoundedVec::truncate_from(aggregated_key.to_vec())
            ),
            Err(pallet::Error::<Test>::UnauthorizedParticipation.into())
        );

        // Submit the DKG result with a non-existent session
        assert_eq!(
            TestingPallet::submit_dkg_result(
                RuntimeOrigin::signed(create_test_account(None)),
                session_id + 1,
                BoundedVec::truncate_from(aggregated_key.to_vec())
            ),
            Err(pallet::Error::<Test>::DkgSessionNotFound.into())
        );
    });
}

#[test]
fn test_create_signing_session() {
    new_test_ext().execute_with(|| {
        // Create a DKG session first
        let dkg_session_id = TestingPallet::next_session_id();
        assert_ok!(TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            60
        ));

        // Check that the DKG session was created
        assert!(TestingPallet::get_dkg_session(dkg_session_id).is_some());

        // Create a signing session
        let message = BoundedVec::<u8, _>::try_from(vec![1, 2, 3]).unwrap();
        assert_ok!(TestingPallet::create_signing_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            message.clone()
        ));

        // Check that the signing session was created
        let signing_session_id = TestingPallet::next_session_id() - 1;
        assert!(TestingPallet::get_signing_session(signing_session_id).is_some());

        // Check the signing session details
        let signing_session = TestingPallet::get_signing_session(signing_session_id).unwrap();
        assert_eq!(signing_session.dkg_session_id, dkg_session_id);
        assert_eq!(signing_session.message, message);
        assert_eq!(
            signing_session.state,
            pallet::SessionState::SigningInProgress
        );
    });
}

#[test]
fn test_create_signing_session_errors() {
    new_test_ext().execute_with(|| {
        // Create a DKG session first
        let dkg_session_id = TestingPallet::next_session_id();
        assert_ok!(TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            60
        ));

        // Check that the DKG session was created
        assert!(TestingPallet::get_dkg_session(dkg_session_id).is_some());

        // Create a signing session with a non-existent DKG session ID
        let message = BoundedVec::<u8, _>::try_from(vec![1, 2, 3]).unwrap();
        assert_eq!(
            TestingPallet::create_signing_session(
                RuntimeOrigin::signed(create_test_account(None)),
                vec![2].try_into().unwrap(),
                message.clone()
            ),
            Err(pallet::Error::<Test>::DkgSessionNotFound.into())
        );
    });
}

#[test]
fn test_submit_aggregated_signature() {
    new_test_ext().execute_with(|| {
        // generate a test ECDSA KeyPair
        let keypair = sp_core::ecdsa::Pair::from_seed_slice(&[37; 32]).unwrap();
        let message = BoundedVec::<u8, _>::try_from(vec![1, 2, 3]).unwrap();

        let signature = keypair.sign(&message[..]);
        let aggregated_key = keypair.public().0;

        // Create a DKG session first
        let dkg_session_id = TestingPallet::next_session_id();
        assert_ok!(TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            60
        ));

        // Submit the DKG result
        // let aggregated_key = [1u8; 33];
        let submitter = create_test_account(None);
        let mut session = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
        session.participants.try_push(submitter.clone()).unwrap();
        DkgSessions::<Test>::insert(dkg_session_id, session);

        assert_ok!(TestingPallet::submit_dkg_result(
            RuntimeOrigin::signed(submitter.clone()),
            dkg_session_id,
            BoundedVec::truncate_from(aggregated_key.to_vec())
        ));

        // Create a signing session
        assert_ok!(TestingPallet::create_signing_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            message.clone()
        ));

        // Get the signing session ID
        let signing_session_id = TestingPallet::next_session_id() - 1;

        // Submit the aggregated signature (valid signature)
        // let signature = [1u8; 65];
        assert_ok!(TestingPallet::submit_aggregated_signature(
            RuntimeOrigin::signed(create_test_account(None)),
            signing_session_id,
            BoundedVec::truncate_from(signature.0.to_vec())
        ));

        // Check that the signing session state was updated
        let updated_session = TestingPallet::get_signing_session(signing_session_id).unwrap();
        assert_eq!(updated_session.state, pallet::SessionState::SigningComplete);
        assert_eq!(
            updated_session.aggregated_sig.unwrap(),
            BoundedVec::<u8, MaxNumberOfShares>::truncate_from(signature.0.to_vec())
        );
    });
}

#[test]
fn test_submit_aggregated_signature_errors() {
    new_test_ext().execute_with(|| {
        // Create a DKG session first
        let dkg_session_id = TestingPallet::next_session_id();
        assert_ok!(TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            60
        ));

        // Submit the DKG result
        let aggregated_key = [1u8; 33];
        let submitter = create_test_account(None);
        let mut session = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
        session.participants.try_push(submitter.clone()).unwrap();
        DkgSessions::<Test>::insert(dkg_session_id, session);

        assert_ok!(TestingPallet::submit_dkg_result(
            RuntimeOrigin::signed(submitter.clone()),
            dkg_session_id,
            BoundedVec::truncate_from(aggregated_key.to_vec())
        ));

        // Create a signing session
        let message = BoundedVec::<u8, _>::try_from(vec![1, 2, 3]).unwrap();
        assert_ok!(TestingPallet::create_signing_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            message.clone()
        ));

        // Get the signing session ID
        let signing_session_id = TestingPallet::next_session_id() - 1;

        // Submit an invalid signature (all zeros)
        let invalid_signature = [0u8; 65];
        assert_eq!(
            TestingPallet::submit_aggregated_signature(
                RuntimeOrigin::signed(create_test_account(None)),
                signing_session_id,
                BoundedVec::truncate_from(invalid_signature.to_vec())
            ),
            Err(pallet::Error::<Test>::InvalidSignature.into())
        );

        // Submit to a non-existent signing session
        assert_eq!(
            TestingPallet::submit_aggregated_signature(
                RuntimeOrigin::signed(create_test_account(None)),
                signing_session_id + 1,
                BoundedVec::truncate_from(invalid_signature.to_vec())
            ),
            Err(pallet::Error::<Test>::SigningSessionNotFound.into())
        );
    });
}

#[test]
fn test_signing_session_lifecycle() {
    new_test_ext().execute_with(|| {
        // generate a test ECDSA KeyPair
        let keypair = sp_core::ecdsa::Pair::from_seed_slice(&[37; 32]).unwrap();
        let message = BoundedVec::<u8, _>::try_from(vec![1, 2, 3]).unwrap();

        let signature = keypair.sign(&message[..]);
        let aggregated_key = keypair.public().0;

        // Create a DKG session first
        let dkg_session_id = TestingPallet::next_session_id();
        assert_ok!(TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            60
        ));

        // Submit the DKG result
        let submitter = create_test_account(None);
        let mut session = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
        session.participants.try_push(submitter.clone()).unwrap();
        DkgSessions::<Test>::insert(dkg_session_id, session);

        assert_ok!(TestingPallet::submit_dkg_result(
            RuntimeOrigin::signed(submitter.clone()),
            dkg_session_id,
            BoundedVec::truncate_from(aggregated_key.to_vec())
        ));

        // Create a signing session
        assert_ok!(TestingPallet::create_signing_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            message.clone()
        ));

        // Get the signing session ID
        let signing_session_id = TestingPallet::next_session_id() - 1;

        // Submit the aggregated signature (valid signature)
        assert_ok!(TestingPallet::submit_aggregated_signature(
            RuntimeOrigin::signed(create_test_account(None)),
            signing_session_id,
            BoundedVec::truncate_from(signature.0.to_vec())
        ));

        // Check that the signing session state was updated
        let updated_session = TestingPallet::get_signing_session(signing_session_id).unwrap();
        assert_eq!(updated_session.state, pallet::SessionState::SigningComplete);
        assert_eq!(
            updated_session.aggregated_sig.unwrap(),
            BoundedVec::<u8, MaxNumberOfShares>::truncate_from(signature.0.to_vec())
        );
    });
}

#[test]
fn test_update_validators() {
    new_test_ext().execute_with(|| {
        // Initialize validator IDs
        assert_ok!(TestingPallet::initialize_validator_ids());

        // Get the initial number of validators
        let initial_validators_count = TestingPallet::active_validators().len();

        // Create some test accounts to be validators
        let validator1 = create_test_account(Some([1u8; 32]));
        let validator2 = create_test_account(Some([2u8; 32]));
        let validator3 = create_test_account(Some([3u8; 32]));

        let submitter = create_test_account(Some([4u8; 32]));

        // Create a payload with the new validators
        let new_validators = vec![validator1.clone(), validator2.clone(), validator3.clone()];
        let payload = UpdateValidatorsPayload::<Test> {
            validators: new_validators.clone(),
            public: submitter,
        };

        // Update the validators
        assert_ok!(TestingPallet::update_validators(
            RuntimeOrigin::none(),
            payload,
            Signature::from_raw([0u8; 64])
        ));

        // Check if the validators were updated
        let updated_validators = TestingPallet::active_validators();
        assert_eq!(updated_validators.len(), new_validators.len());
        assert!(updated_validators.contains(&validator1));
        assert!(updated_validators.contains(&validator2));
        assert!(updated_validators.contains(&validator3));

        // Check if the validator IDs were assigned
        assert!(TestingPallet::validator_ids(&validator1).is_some());
        assert!(TestingPallet::validator_ids(&validator2).is_some());
        assert!(TestingPallet::validator_ids(&validator3).is_some());

        // Check if the next validator ID was updated
        assert_eq!(
            TestingPallet::next_validator_id(),
            initial_validators_count as u32 + new_validators.len() as u32 + 1
        );
    });
}

#[test]
fn test_assign_validator_id() {
    new_test_ext().execute_with(|| {
        TestingPallet::initialize_validator_ids().unwrap();

        // Create a test account to be a validator
        let validator = create_test_account(Some([1u8; 32]));

        // Assign an ID to the validator
        assert_ok!(TestingPallet::assign_validator_id(validator.clone()));

        // Check if the validator ID was assigned
        assert!(TestingPallet::validator_ids(&validator).is_some());

        // Check if the ID to validator mapping was updated
        let validator_id = TestingPallet::validator_ids(&validator).unwrap();
        assert_eq!(
            TestingPallet::id_to_validator(validator_id).unwrap(),
            validator
        );

        // Check if the next validator ID was updated
        assert_eq!(TestingPallet::next_validator_id(), 2);

        // Assign another ID to the same validator (should not change anything)
        assert_ok!(TestingPallet::assign_validator_id(validator.clone()));

        // Check if the validator ID is still the same
        assert_eq!(
            TestingPallet::validator_ids(&validator).unwrap(),
            validator_id
        );

        // Check if the next validator ID is still the same
        assert_eq!(TestingPallet::next_validator_id(), 2);
    });
}

#[test]
fn test_offchain_worker_validator_updates() {
    let mut ext = new_test_ext();

    let (offchain, _state) = TestOffchainExt::new();
    let (pool, pool_state) = TestTransactionPoolExt::new();

    ext.register_extension(OffchainDbExt::new(offchain.clone()));
    ext.register_extension(OffchainWorkerExt::new(offchain));
    ext.register_extension(TransactionPoolExt::new(pool));

    // Create and register keystore
    let keystore = Arc::new(MemoryKeystore::new());
    let public_key = keystore
        .sr25519_generate_new(CRYPTO_KEY_TYPE, None)
        .unwrap();

    // Create some test accounts to be validators
    let validator1 = create_test_account(Some([1u8; 32]));
    let validator2 = create_test_account(Some([2u8; 32]));
    let validator3 = create_test_account(Some([3u8; 32]));

    let payload = UpdateValidatorsPayload {
        validators: vec![validator1.clone(), validator2.clone(), validator3.clone()],
        public: create_test_account(None),
    };

    let sig_vec: [u8; 64] = keystore
        .sign_with(CRYPTO_KEY_TYPE, sr25519::CRYPTO_ID, &public_key, &[1, 2, 3])
        .unwrap()
        .unwrap()[..]
        .try_into()
        .unwrap();
    let signature = Signature::from_raw(sig_vec);
    ext.register_extension(KeystoreExt(keystore));

    ext.execute_with(|| {
        System::set_block_number(10);

        // Initialize validator IDs
        assert_ok!(TestingPallet::initialize_validator_ids());

        // Get the initial number of validators
        let initial_validators_count = TestingPallet::active_validators().len();

        let prefs = pallet_staking::ValidatorPrefs {
            commission: Perbill::from_percent(5), // 5% commission
            blocked: false,                       // Not blocked
        };

        // Add the validators to the staking pallet
        pallet_staking::Validators::<Test>::insert(validator1.clone(), prefs.clone());
        pallet_staking::Validators::<Test>::insert(validator2.clone(), prefs.clone());
        pallet_staking::Validators::<Test>::insert(validator3.clone(), prefs.clone());

        println!(
            "Pool state before offchain worker: {:?}",
            pool_state.read().transactions
        );

        // Run the offchain worker
        TestingPallet::offchain_worker(10u32.into());
        match TestingPallet::update_validators(
            RuntimeOrigin::none(),
            payload.clone(),
            signature.clone(),
        ) {
            Ok(_) => {
                println!("Success ok")
            }
            Err(_) => {
                println!("update_validators failed")
            }
        }
        // Advance to next block
        System::set_block_number(11);

        println!(
            "Next Validator ID is: {:?}",
            TestingPallet::next_validator_id()
        );

        // Check if the validator IDs were assigned
        assert!(TestingPallet::validator_ids(&validator1).is_some());
        assert!(TestingPallet::validator_ids(&validator2).is_some());
        assert!(TestingPallet::validator_ids(&validator3).is_some());

        // Check if the next validator ID was updated
        assert_eq!(
            TestingPallet::next_validator_id(),
            initial_validators_count as u32 + 3 + 1
        );

        // Check if the active validators were updated
        let updated_validators = TestingPallet::active_validators();
        assert_eq!(updated_validators.len(), 3);
        assert!(updated_validators.contains(&validator1));
        assert!(updated_validators.contains(&validator2));
        assert!(updated_validators.contains(&validator3));
    });
}

#[test]
fn test_get_validator_id() {
    new_test_ext().execute_with(|| {
        // Initialize validator IDs
        assert_ok!(TestingPallet::initialize_validator_ids());

        // Create a test account to be a validator
        let validator = create_test_account(Some([1u8; 32]));

        // Assign an ID to the validator
        assert_ok!(TestingPallet::assign_validator_id(validator.clone()));

        // Get the validator ID
        let validator_id = TestingPallet::get_validator_id(&validator).unwrap();

        // Check if the validator ID is correct
        assert_eq!(validator_id, 1);
    });
}

#[test]
fn test_get_validator_from_id() {
    new_test_ext().execute_with(|| {
        // Initialize validator IDs
        assert_ok!(TestingPallet::initialize_validator_ids());

        // Create a test account to be a validator
        let validator = create_test_account(Some([1u8; 32]));

        // Assign an ID to the validator
        assert_ok!(TestingPallet::assign_validator_id(validator.clone()));

        // Get the validator ID
        let validator_id = TestingPallet::get_validator_id(&validator).unwrap();

        // Get the validator from the ID
        let retrieved_validator = TestingPallet::get_validator_from_id(validator_id).unwrap();

        // Check if the retrieved validator is correct
        assert_eq!(retrieved_validator, validator);
    });
}

#[test]
fn test_validator_id_assignment_and_retrieval() {
    new_test_ext().execute_with(|| {
        // Initialize validator IDs
        assert_ok!(TestingPallet::initialize_validator_ids());

        // Create some test accounts to be validators
        let validator1 = create_test_account(Some([1u8; 32]));
        let validator2 = create_test_account(Some([2u8; 32]));
        let validator3 = create_test_account(Some([3u8; 32]));

        // Assign IDs to the validators
        assert_ok!(TestingPallet::assign_validator_id(validator1.clone()));
        assert_ok!(TestingPallet::assign_validator_id(validator2.clone()));
        assert_ok!(TestingPallet::assign_validator_id(validator3.clone()));

        // Retrieve the validator IDs
        let validator1_id = TestingPallet::get_validator_id(&validator1).unwrap();
        let validator2_id = TestingPallet::get_validator_id(&validator2).unwrap();
        let validator3_id = TestingPallet::get_validator_id(&validator3).unwrap();

        // Check if the IDs are correct
        assert_eq!(validator1_id, 1);
        assert_eq!(validator2_id, 2);
        assert_eq!(validator3_id, 3);

        // Retrieve the validators from their IDs
        let retrieved_validator1 = TestingPallet::get_validator_from_id(validator1_id).unwrap();
        let retrieved_validator2 = TestingPallet::get_validator_from_id(validator2_id).unwrap();
        let retrieved_validator3 = TestingPallet::get_validator_from_id(validator3_id).unwrap();

        // Check if the retrieved validators are correct
        assert_eq!(retrieved_validator1, validator1);
        assert_eq!(retrieved_validator2, validator2);
        assert_eq!(retrieved_validator3, validator3);
    });
}
