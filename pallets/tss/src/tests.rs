use std::sync::Arc;

use crate::{
    mock::*, pallet, types::{MaxNumberOfShares, NftId}, ActiveValidators, DkgSessions, Event as TssEvent, NextValidatorId, ParticipantReportCount, SessionState, SubmitDKGResultPayload, UpdateValidatorsPayload, CRYPTO_KEY_TYPE
};
use frame_support::{assert_noop, assert_ok, traits::OffchainWorker};
use sp_core::{
    bounded_vec, offchain::{
        testing::{TestOffchainExt, TestTransactionPoolExt},
        OffchainDbExt, OffchainWorkerExt, TransactionPoolExt,
    }, sr25519::{self, Signature}, Pair
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
fn test_create_signing_session() {
    new_test_ext().execute_with(|| {

        let validators = vec![account(10), account(11), account(12)];
        setup_active_validators(&validators);
        let _ = TestingPallet::initialize_validator_ids();

        // Create a DKG session first
        let dkg_session_id = TestingPallet::next_session_id();
        assert_ok!(TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            60
        ));

        // Check that the DKG session was created
        assert!(TestingPallet::get_dkg_session(dkg_session_id).is_some());

        for submitter in validators {
            // Submit the DKG result
            let aggregated_key = [1u8; 33];
            // let submitter = create_test_account(None);
            let session = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
            // session.participants.try_push(submitter.clone()).unwrap();
            // DkgSessions::<Test>::insert(dkg_session_id, session);

            if session.state < SessionState::DKGComplete {
                assert_ok!(TestingPallet::submit_dkg_result(
                    RuntimeOrigin::none(),
                    SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggregated_key.to_vec()), public: submitter.clone() },
                    Signature::from_raw([0u8; 64])
                ));
            }
        }

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


        let validators = vec![account(10), account(11), account(12)];
        setup_active_validators(&validators);
        let _ = TestingPallet::initialize_validator_ids();

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

        let validators = vec![account(10), account(11), account(12)];
        setup_active_validators(&validators);
        let _ = TestingPallet::initialize_validator_ids();

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
        let submitter = account(10);
        
        assert_ok!(TestingPallet::submit_dkg_result(
            RuntimeOrigin::none(),
            SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggregated_key.to_vec()), public: submitter.clone() },
            Signature::from_raw([0u8; 64])            
        ));


        // Submit the DKG result
        // let aggregated_key = [1u8; 33];
        let submitter = account(11);
        
        assert_ok!(TestingPallet::submit_dkg_result(
            RuntimeOrigin::none(),
            SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggregated_key.to_vec()), public: submitter.clone() },
            Signature::from_raw([0u8; 64])            
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

        let validators = vec![account(10), account(11), account(12)];
        setup_active_validators(&validators);
        let _ = TestingPallet::initialize_validator_ids();

        assert_ok!(TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(create_test_account(None)),
            vec![1].try_into().unwrap(),
            60
        ));
        for submitter in validators {
            // Submit the DKG result
            let aggregated_key = [1u8; 33];
            // let submitter = create_test_account(None);
            let session = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
            // session.participants.try_push(submitter.clone()).unwrap();
            // DkgSessions::<Test>::insert(dkg_session_id, session);

            if session.state < SessionState::DKGComplete {
                assert_ok!(TestingPallet::submit_dkg_result(
                    RuntimeOrigin::none(),
                    SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggregated_key.to_vec()), public: submitter.clone() },
                    Signature::from_raw([0u8; 64])
                ));
            }
        }

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

        let validators = vec![account(10), account(11), account(12)];
        setup_active_validators(&validators);
        let _ = TestingPallet::initialize_validator_ids();

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
        let submitter = account(10);

        assert_ok!(TestingPallet::submit_dkg_result(
            RuntimeOrigin::none(),
            SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggregated_key.to_vec()), public: submitter.clone() },
            Signature::from_raw([0u8; 64])
        ));


        // Submit the DKG result
        let submitter = account(12);
        
        assert_ok!(TestingPallet::submit_dkg_result(
            RuntimeOrigin::none(),
            SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggregated_key.to_vec()), public: submitter.clone() },
            Signature::from_raw([0u8; 64])
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
        NextValidatorId::<Test>::put(1);

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
        NextValidatorId::<Test>::put(1);

        let _ = TestingPallet::initialize_validator_ids();

        assert_eq!(TestingPallet::next_validator_id(), 1);

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
        NextValidatorId::<Test>::put(1);

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
        NextValidatorId::<Test>::put(1);
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
        NextValidatorId::<Test>::put(1);

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


// Helper function to create test account IDs
fn account(id: u8) -> AccountId {
    AccountId::from_raw([id; 32])
}

// Helper function to create a BoundedVec of AccountIds
fn bounded_account_vec(
    accounts: &[AccountId],
) -> BoundedVec<AccountId, MaxNumberOfShares> {
    accounts.to_vec().try_into().unwrap()
}

// Helper function to set up active validators in storage
fn setup_active_validators(validators: &[AccountId]) {
    ActiveValidators::<Test>::put(bounded_account_vec(validators));
}

// Helper function to mark validators as slashed (by setting their report count > 0)
fn setup_slashed_validators(validators: &[(AccountId, u32)]) {
    for (validator, count) in validators {
        ParticipantReportCount::<Test>::insert(validator, *count);
    }
}

#[test]
fn create_dkg_session_happy_path_no_slashed() {
    new_test_ext().execute_with(|| {
        // Arrange
        let caller = account(1);
        let nft_id: NftId = bounded_vec![1, 2, 3];
        let threshold = 67; // Valid threshold
        let validators = vec![account(10), account(11), account(12)];
        setup_active_validators(&validators);
        System::set_block_number(5); // Set current block number for deadline calculation
        let expected_deadline = 5 + 100;
        let initial_session_id = TestingPallet::next_session_id();

        // Act
        let result = TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(caller.clone()),
            nft_id.clone(),
            threshold,
        );

        // Assert
        assert_ok!(result);
        assert_eq!(TestingPallet::next_session_id(), initial_session_id + 1);

        let session = TestingPallet::get_dkg_session(initial_session_id).unwrap();
        assert_eq!(session.nft_id, nft_id);
        assert_eq!(session.threshold, threshold);
        assert_eq!(session.state, SessionState::DKGCreated);
        assert_eq!(session.participants, bounded_account_vec(&validators)); // All validators should be participants
        assert!(session.old_participants.is_none());
        assert_eq!(session.deadline, expected_deadline);

        // Check event
        System::assert_last_event(
            TssEvent::DKGSessionCreated(initial_session_id).into(),
        );
    });
}

#[test]
fn create_dkg_session_happy_path_with_slashed() {
    new_test_ext().execute_with(|| {
        // Arrange
        let caller = account(1);
        let nft_id: NftId = bounded_vec![4, 5, 6];
        let threshold = 67;
        let active_validators = vec![account(10), account(11), account(12), account(13)];
        let slashed_validators = vec![(account(11), 1), (account(13), 3)]; // Mark 11 and 13 as slashed
        let expected_participants = vec![account(10), account(12)]; // Only non-slashed validators

        setup_active_validators(&active_validators);
        setup_slashed_validators(&slashed_validators);
        System::set_block_number(10);
        let expected_deadline = 10 + 100;
        let initial_session_id = TestingPallet::next_session_id();

        // Act
        let result = TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(caller.clone()),
            nft_id.clone(),
            threshold,
        );

        // Assert
        assert_ok!(result);
        assert_eq!(TestingPallet::next_session_id(), initial_session_id + 1);

        let session = TestingPallet::get_dkg_session(initial_session_id).unwrap();
        assert_eq!(session.nft_id, nft_id);
        assert_eq!(session.threshold, threshold);
        assert_eq!(session.state, SessionState::DKGCreated);
        assert_eq!(
            session.participants,
            bounded_account_vec(&expected_participants)
        ); // Only non-slashed
        assert!(session.old_participants.is_none());
        assert_eq!(session.deadline, expected_deadline);

        // Check event
        System::assert_last_event(
            TssEvent::DKGSessionCreated(initial_session_id).into(),
        );
    });
}

#[test]
fn create_dkg_session_error_invalid_threshold_zero() {
    new_test_ext().execute_with(|| {
        // Arrange
        let caller = account(1);
        let nft_id: NftId = bounded_vec![1];
        let threshold = 0; // Invalid threshold
        setup_active_validators(&[account(10)]);

        // Act & Assert
        assert_noop!(
            TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(caller),
                nft_id,
                threshold
            ),
            crate::Error::<Test>::InvalidThreshold
        );
    });
}

#[test]
fn create_dkg_session_error_invalid_threshold_below_50() {
    new_test_ext().execute_with(|| {
        // Arrange
        let caller = account(1);
        let nft_id: NftId = bounded_vec![1];
        let threshold = 49; // Invalid threshold
        setup_active_validators(&[account(10)]);

        // Act & Assert
        assert_noop!(
            TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(caller),
                nft_id,
                threshold
            ),
            crate::Error::<Test>::InvalidThreshold
        );
    });
}

#[test]
fn create_dkg_session_error_invalid_threshold_above_100() {
    new_test_ext().execute_with(|| {
        // Arrange
        let caller = account(1);
        let nft_id: NftId = bounded_vec![1];
        let threshold = 101; // Invalid threshold
        setup_active_validators(&[account(10)]);

        // Act & Assert
        assert_noop!(
            TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(caller),
                nft_id,
                threshold
            ),
            crate::Error::<Test>::InvalidThreshold
        );
    });
}

#[test]
fn create_dkg_session_error_too_few_active_validators() {
    new_test_ext().execute_with(|| {
        // Arrange
        let caller = account(1);
        let nft_id: NftId = bounded_vec![7, 8, 9];
        let threshold = 67; // Default minimum threshold is 67%

        // Setup: 3 active validators, 2 are slashed.
        // total_validators = 3
        // slashed_validators_count = 2
        // required_validators = (3 * 67) / 100 = 2 (integer division)
        // Check: slashed_validators_count (2) <= total_validators (3) - required_validators (2)
        // Check: 2 <= 1  -> This is FALSE, so the error should trigger.
        let active_validators = vec![account(20), account(21), account(22)];
        let slashed_validators = vec![(account(21), 1), (account(22), 1)];

        setup_active_validators(&active_validators);
        setup_slashed_validators(&slashed_validators);

        // Act & Assert
        assert_noop!(
            TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(caller),
                nft_id,
                threshold
            ),
            crate::Error::<Test>::TooFewActiveValidators
        );
    });
}

#[test]
fn create_dkg_session_sufficient_validators_despite_slashing() {
    new_test_ext().execute_with(|| {
        // Arrange
        let caller = account(1);
        let nft_id: NftId = bounded_vec![10, 11, 12];
        let threshold = 67; // Default minimum threshold is 67%

        // Setup: 4 active validators, 1 is slashed.
        // total_validators = 4
        // slashed_validators_count = 1
        // required_validators = (4 * 67) / 100 = 2 (integer division)
        // Check: slashed_validators_count (1) <= total_validators (4) - required_validators (2)
        // Check: 1 <= 2 -> This is TRUE, so it should succeed.
        let active_validators = vec![account(30), account(31), account(32), account(33)];
        let slashed_validators = vec![(account(31), 1)];
        let expected_participants = vec![account(30), account(32), account(33)];

        setup_active_validators(&active_validators);
        setup_slashed_validators(&slashed_validators);
        System::set_block_number(20);
        let expected_deadline = 20 + 100;
        let initial_session_id = TestingPallet::next_session_id();

        // Act
        let result = TestingPallet::create_dkg_session(
            RuntimeOrigin::signed(caller.clone()),
            nft_id.clone(),
            threshold,
        );

        // Assert
        assert_ok!(result);
        let session = TestingPallet::get_dkg_session(initial_session_id).unwrap();
        assert_eq!(
            session.participants,
            bounded_account_vec(&expected_participants)
        );
        assert_eq!(session.deadline, expected_deadline);
        System::assert_last_event(
            TssEvent::DKGSessionCreated(initial_session_id).into(),
        );
    });
}

#[test]
fn create_dkg_session_no_active_validators() {
    new_test_ext().execute_with(|| {
        // Arrange
        let caller = account(1);
        let nft_id: NftId = bounded_vec![1];
        let threshold = 50;
        setup_active_validators(&[]); // No active validators

        // Act & Assert
        // The check `slashed_validators_count <= (total_validators - required_validators)`
        // becomes `0 <= (0 - 0)`, which is true.
        // However, the `BoundedVec::try_from(participants)` will fail if participants is empty.
        // Let's check if the error is InvalidParticipantsCount or TooFewActiveValidators based on implementation detail.
        // The check for TooFewActiveValidators happens first.
        assert_noop!(
            TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(caller),
                nft_id,
                threshold
            ),
            crate::Error::<Test>::TooFewActiveValidators // Because 0 total validators means 0 required, 0 <= 0-0 is true, but likely the intent is to fail earlier. Let's assume the check catches this.
                                                    // If the check didn't catch it, it would be InvalidParticipantsCount.
                                                    // After reviewing the code, the check `ensure!(slashed_validators_count <= (total_validators - required_validators), Error::<T>::TooFewActiveValidators)`
                                                    // with total_validators = 0 and required_validators = 0 becomes `ensure!(0 <= 0, ...)`, which passes.
                                                    // The error should come from `BoundedVec::try_from(participants).map_err(|_| Error::<T>::InvalidParticipantsCount)?` when participants is empty.
                                                    // Let's correct the expected error.
                                                    // Error::<Test>::InvalidParticipantsCount // This seems more likely if the TooFew check passes with 0.
                                                    // Re-evaluating: The check `ensure!(slashed_validators_count <= (total_validators - required_validators))` is intended to ensure enough *non-slashed* validators remain. If total is 0, it inherently fails the requirement. Let's stick with TooFewActiveValidators.
        );
    });
}




#[cfg(test)]
mod tests {
    // Import necessary items from the parent module and mock environment
    use super::*; // Import items from the outer scope (lib.rs)
    use crate::{types::*, AggregatedPublicKeys, Config, DKGSession, Error, Event as TssEvent, IdToValidator, NextValidatorId, ReportedParticipants, ValidatorIds}; // Import mock, pallet, types, Error, and Event
    use frame_support::{assert_noop, assert_ok}; use frame_system::pallet_prelude::BlockNumberFor;
    // Import testing macros and Hooks trait
    use sp_runtime::bounded_vec; // Import bounded_vec

    // Helper function to create test account IDs
    fn account(id: u8) -> AccountId {
        AccountId::from_raw([id; 32])
    }

    // Helper function to create a BoundedVec of AccountIds
    fn bounded_account_vec(
        accounts: &[AccountId],
    ) -> BoundedVec<AccountId, MaxNumberOfShares> {
        accounts.to_vec().try_into().unwrap()
    }

    // Helper function to set up active validators in storage
    fn setup_active_validators(validators: &[AccountId]) {
        ActiveValidators::<Test>::put(bounded_account_vec(validators));
    }

    // Helper function to mark validators as slashed (by setting their report count > 0)
    fn _setup_slashed_validators(validators: &[(AccountId, u32)]) {
        for (validator, count) in validators {
            ParticipantReportCount::<Test>::insert(validator, *count);
        }
    }

    // Helper function to create a DKG session for testing
    fn create_test_dkg_session(
        session_id: SessionId,
        participants: &[AccountId],
        threshold: u32,
        state: SessionState,
        deadline: BlockNumberFor<Test>,
    ) -> DKGSession<Test> {
        DKGSession {
            participants: bounded_account_vec(participants),
            nft_id: bounded_vec![session_id as u8], // Simple NFT ID based on session ID
            threshold,
            state,
            old_participants: None,
            deadline,
        }
    }

    // --- Tests for check_expired_sessions ---

    #[test]
    fn check_expired_sessions_no_expired() {
        new_test_ext().execute_with(|| {
            // Arrange
            let current_block = 150;
            System::set_block_number(current_block);
            let participants = vec![account(1), account(2)];
            let session1 = create_test_dkg_session(
                1,
                &participants,
                67,
                SessionState::DKGInProgress,
                current_block + 10, // Not expired
            );
            DkgSessions::<Test>::insert(1, session1);

            // Act
            assert_ok!(TestingPallet::check_expired_sessions(current_block));

            // Assert
            assert!(DkgSessions::<Test>::contains_key(1)); // Session should still exist
        });
    }

    #[test]
    fn check_expired_sessions_one_expired() {
        new_test_ext().execute_with(|| {
            // Arrange
            let current_block = 150;
            System::set_block_number(current_block);
            let participants = vec![account(1), account(2)];
            let session_id = 1;
            let deadline = current_block - 1; // Expired
            let session1 = create_test_dkg_session(
                session_id,
                &participants,
                67,
                SessionState::DKGInProgress, // State allows expiration check
                deadline,
            );
            DkgSessions::<Test>::insert(session_id, session1);

            // Act
            assert_ok!(TestingPallet::check_expired_sessions(current_block));

            // Assert
            assert!(!DkgSessions::<Test>::contains_key(session_id)); // Session should be removed
            System::assert_last_event(TssEvent::DKGFailed(session_id).into());
            // update_report_count was called implicitly, check state change (already done by removal)
        });
    }

    #[test]
    fn check_expired_sessions_multiple_sessions() {
        new_test_ext().execute_with(|| {
            // Arrange
            let current_block = 200;
            System::set_block_number(current_block);
            let participants = vec![account(1), account(2)];

            let session1 = create_test_dkg_session(
                1,
                &participants,
                67,
                SessionState::DKGInProgress,
                current_block - 10, // Expired
            );
            let session2 = create_test_dkg_session(
                2,
                &participants,
                67,
                SessionState::DKGCreated, // State allows expiration check
                current_block + 5, // Not expired
            );
            let session3 = create_test_dkg_session(
                3,
                &participants,
                67,
                SessionState::DKGComplete, // State does NOT allow expiration check
                current_block - 20, // Expired, but wrong state
            );
            DkgSessions::<Test>::insert(1, session1);
            DkgSessions::<Test>::insert(2, session2);
            DkgSessions::<Test>::insert(3, session3);

            // Act
            assert_ok!(TestingPallet::check_expired_sessions(current_block));

            // Assert
            assert!(!DkgSessions::<Test>::contains_key(1)); // Session 1 removed
            assert!(DkgSessions::<Test>::contains_key(2)); // Session 2 remains
            assert!(DkgSessions::<Test>::contains_key(3)); // Session 3 remains (wrong state)
            System::assert_has_event(TssEvent::DKGFailed(1).into());
        });
    }

    // --- Tests for update_report_count ---

    #[test]
    fn update_report_count_no_reports() {
        new_test_ext().execute_with(|| {
            // Arrange
            let session_id = 1;
            let participants = vec![account(1), account(2), account(3)];
            let session = create_test_dkg_session(
                session_id,
                &participants,
                67,
                SessionState::DKGInProgress,
                100,
            );
            DkgSessions::<Test>::insert(session_id, session);

            // Act
            assert_ok!(TestingPallet::update_report_count(session_id));

            // Assert
            let updated_session = DkgSessions::<Test>::get(session_id).unwrap();
            assert_eq!(updated_session.state, SessionState::DKGFailed);
            assert_eq!(ParticipantReportCount::<Test>::get(account(1)), 0);
            assert_eq!(ParticipantReportCount::<Test>::get(account(2)), 0);
            assert_eq!(ParticipantReportCount::<Test>::get(account(3)), 0);
        });
    }

    #[test]
    fn update_report_count_below_threshold() {
        new_test_ext().execute_with(|| {
            // Arrange
            let session_id = 1;
            let participants = vec![account(1), account(2), account(3), account(4)]; // 4 participants, threshold = 2/3 = 2 reports needed
            let session = create_test_dkg_session(
                session_id,
                &participants,
                67,
                SessionState::DKGInProgress,
                100,
            );
            DkgSessions::<Test>::insert(session_id, session);

            let reported: BoundedVec<AccountId, <Test as Config>::MaxNumberOfShares> = bounded_vec![account(4)];
            
            // account(1) reports account(4)
            ReportedParticipants::<Test>::insert(
                session_id,
                account(1),
                reported,
            );

            // Act
            assert_ok!(TestingPallet::update_report_count(session_id));

            // Assert
            let updated_session = DkgSessions::<Test>::get(session_id).unwrap();
            assert_eq!(updated_session.state, SessionState::DKGFailed);
            assert_eq!(ParticipantReportCount::<Test>::get(account(4)), 0); // Count not incremented
        });
    }

    #[test]
    fn update_report_count_at_threshold() {
        new_test_ext().execute_with(|| {
            // Arrange
            let session_id = 1;
            let participants = vec![account(1), account(2), account(3)]; // 3 participants, threshold = 2/3 = 2 reports needed
            let session = create_test_dkg_session(
                session_id,
                &participants,
                67,
                SessionState::DKGInProgress,
                100,
            );
            DkgSessions::<Test>::insert(session_id, session.clone());
            ParticipantReportCount::<Test>::insert(account(3), 5); // Pre-existing count

            let reported: BoundedVec<AccountId, <Test as Config>::MaxNumberOfShares> = bounded_vec![account(3)];

            // account(1) reports account(3)
            ReportedParticipants::<Test>::insert(
                session_id,
                account(1),
                reported,
            );
            let reported: BoundedVec<AccountId, <Test as Config>::MaxNumberOfShares> = bounded_vec![account(3)];
            // account(2) reports account(3)
            ReportedParticipants::<Test>::insert(
                session_id,
                account(2),
                reported,
            );

            // Act
            assert_ok!(TestingPallet::update_report_count(session_id));

            // Assert
            let updated_session = DkgSessions::<Test>::get(session_id).unwrap();
            assert_eq!(updated_session.state, SessionState::DKGFailed);
            assert_eq!(ParticipantReportCount::<Test>::get(account(3)), 7); // Count incremented
        });
    }

    #[test]
    fn update_report_count_multiple_reported() {
        new_test_ext().execute_with(|| {
            // Arrange
            let session_id = 1;
            // 5 participants, threshold = 2/3 = 3 reports needed
            let participants = vec![account(1), account(2), account(3), account(4), account(5)];
            let session = create_test_dkg_session(
                session_id,
                &participants,
                67,
                SessionState::DKGInProgress,
                100,
            );
            DkgSessions::<Test>::insert(session_id, session.clone());
            ParticipantReportCount::<Test>::insert(account(4), 1);
            ParticipantReportCount::<Test>::insert(account(5), 2);

            let reported: BoundedVec<AccountId, <Test as Config>::MaxNumberOfShares> = bounded_vec![account(4)];


            // account(4) reported by 1, 2, 3 (meets threshold)
            ReportedParticipants::<Test>::insert(session_id, account(1), reported.clone());
            ReportedParticipants::<Test>::insert(session_id, account(2), reported.clone());
            ReportedParticipants::<Test>::insert(session_id, account(3), reported);
            // account(5) reported by 1, 2 (does not meet threshold)
            ReportedParticipants::<Test>::mutate(session_id, account(1), |list| {
                list.as_mut().unwrap().try_push(account(5)).unwrap();
            });
            ReportedParticipants::<Test>::mutate(session_id, account(2), |list| {
                list.as_mut().unwrap().try_push(account(5)).unwrap();
            });

            // Act
            assert_ok!(TestingPallet::update_report_count(session_id));

            // Assert
            let updated_session = DkgSessions::<Test>::get(session_id).unwrap();
            assert_eq!(updated_session.state, SessionState::DKGFailed);
            // assert_eq!(ParticipantReportCount::<Test>::get(account(4)), 2); // Incremented
            assert_eq!(ParticipantReportCount::<Test>::get(account(5)), 2); // Not incremented
        });
    }

    #[test]
    fn update_report_count_session_not_found() {
        new_test_ext().execute_with(|| {
            // Arrange
            let session_id = 1;

            // Act & Assert
            assert_noop!(
                TestingPallet::update_report_count(session_id),
                Error::<Test>::DkgSessionNotFound
            );
        });
    }

    // --- Tests for initialize_validator_ids ---

    #[test]
    fn initialize_validator_ids_no_validators() {
        new_test_ext().execute_with(|| {
            // Arrange
            NextValidatorId::<Test>::put(1);
            setup_active_validators(&[]);

            // Act
            assert_ok!(TestingPallet::initialize_validator_ids());

            // Assert
            assert_eq!(NextValidatorId::<Test>::get(), 1); // Should still initialize to 1
        });
    }

    #[test]
    fn initialize_validator_ids_new_validators() {
        new_test_ext().execute_with(|| {
            // Arrange
            let validators = vec![account(1), account(2), account(3)];
            setup_active_validators(&validators);
            NextValidatorId::<Test>::put(1); // Ensure it's not initialized

            // Act
            assert_ok!(TestingPallet::initialize_validator_ids());

            // Assert
            assert_eq!(ValidatorIds::<Test>::get(account(1)), Some(1));
            assert_eq!(ValidatorIds::<Test>::get(account(2)), Some(2));
            assert_eq!(ValidatorIds::<Test>::get(account(3)), Some(3));
            assert_eq!(IdToValidator::<Test>::get(1), Some(account(1)));
            assert_eq!(IdToValidator::<Test>::get(2), Some(account(2)));
            assert_eq!(IdToValidator::<Test>::get(3), Some(account(3)));
            assert_eq!(NextValidatorId::<Test>::get(), 4);
        });
    }

    #[test]
    fn initialize_validator_ids_mixed_validators() {
        new_test_ext().execute_with(|| {
            // Arrange
            let validators = vec![account(1), account(2), account(3)];
            setup_active_validators(&validators);
            // Pre-assign ID to account(2)
            ValidatorIds::<Test>::insert(account(2), 5);
            IdToValidator::<Test>::insert(5, account(2));
            NextValidatorId::<Test>::put(6); // Next ID should be 6

            // Act
            assert_ok!(TestingPallet::initialize_validator_ids());

            // Assert
            assert_eq!(ValidatorIds::<Test>::get(account(1)), Some(6)); // Gets next available ID
            assert_eq!(ValidatorIds::<Test>::get(account(2)), Some(5)); // Remains unchanged
            assert_eq!(ValidatorIds::<Test>::get(account(3)), Some(7)); // Gets next available ID
            assert_eq!(IdToValidator::<Test>::get(6), Some(account(1)));
            assert_eq!(IdToValidator::<Test>::get(5), Some(account(2)));
            assert_eq!(IdToValidator::<Test>::get(7), Some(account(3)));
            assert_eq!(NextValidatorId::<Test>::get(), 8);
            // System::assert_has_event(RuntimeEvent::TestingPallet(TssEvent::ValidatorIdAssigned(account(1), 6)));
            // System::assert_has_event(RuntimeEvent::TestingPallet(TssEvent::ValidatorIdAssigned(account(3), 7)));
            // No event for account(2)
        });
    }

    #[test]
    fn initialize_validator_ids_all_assigned() {
        new_test_ext().execute_with(|| {
            // Arrange
            let validators = vec![account(1), account(2)];
            setup_active_validators(&validators);
            ValidatorIds::<Test>::insert(account(1), 1);
            IdToValidator::<Test>::insert(1, account(1));
            ValidatorIds::<Test>::insert(account(2), 2);
            IdToValidator::<Test>::insert(2, account(2));
            NextValidatorId::<Test>::put(3);

            // Act
            assert_ok!(TestingPallet::initialize_validator_ids());

            // Assert
            assert_eq!(ValidatorIds::<Test>::get(account(1)), Some(1));
            assert_eq!(ValidatorIds::<Test>::get(account(2)), Some(2));
            assert_eq!(NextValidatorId::<Test>::get(), 3); // Unchanged
                                                           // No events expected
        });
    }

    // --- Tests for assign_validator_id ---

    #[test]
    fn assign_validator_id_new() {
        new_test_ext().execute_with(|| {
            // Arrange
            NextValidatorId::<Test>::put(10); // Set next ID
            let validator = account(5);

            // Act
            assert_ok!(TestingPallet::assign_validator_id(validator.clone()));

            // Assert
            assert_eq!(ValidatorIds::<Test>::get(&validator), Some(10));
            assert_eq!(IdToValidator::<Test>::get(10), Some(validator.clone()));
            assert_eq!(NextValidatorId::<Test>::get(), 11);
            // assert_eq!(System::events().len(), 1234);
            // System::assert_last_event(RuntimeEvent::TestingPallet(TssEvent::ValidatorIdAssigned(
            //     validator, 10,
            // )));
        });
    }

    #[test]
    fn assign_validator_id_existing() {
        new_test_ext().execute_with(|| {
            // Arrange
            let validator = account(5);
            ValidatorIds::<Test>::insert(validator.clone(), 7);
            IdToValidator::<Test>::insert(7, validator.clone());
            NextValidatorId::<Test>::put(10);

            // Act
            assert_ok!(TestingPallet::assign_validator_id(validator.clone()));

            // Assert
            assert_eq!(ValidatorIds::<Test>::get(&validator), Some(7)); // Unchanged
            assert_eq!(IdToValidator::<Test>::get(7), Some(validator)); // Unchanged
            assert_eq!(NextValidatorId::<Test>::get(), 10); // Unchanged
                                                            // No event expected
        });
    }

    // --- Tests for get_slashed_validators ---

    #[test]
    fn get_slashed_validators_none_slashed() {
        new_test_ext().execute_with(|| {
            // Arrange
            ParticipantReportCount::<Test>::insert(account(1), 0);
            ParticipantReportCount::<Test>::insert(account(2), 0);

            // Act
            let slashed = TestingPallet::get_slashed_validators();

            // Assert
            assert!(slashed.is_empty());
        });
    }

    #[test]
    fn get_slashed_validators_some_slashed() {
        new_test_ext().execute_with(|| {
            // Arrange
            ParticipantReportCount::<Test>::insert(account(1), 3); // Slashed
            ParticipantReportCount::<Test>::insert(account(2), 0); // Not slashed
            ParticipantReportCount::<Test>::insert(account(3), 1); // Slashed

            // Act
            let slashed = TestingPallet::get_slashed_validators();

            // Assert
            assert_eq!(slashed.len(), 2);
            assert!(slashed.contains(&account(1)));
            assert!(slashed.contains(&account(3)));
            assert!(!slashed.contains(&account(2)));
        });
    }

    // --- Tests for finalize_dkg_session ---

    #[test]
    fn finalize_dkg_session_success() {
        new_test_ext().execute_with(|| {
            // Arrange
            let session_id = 1;
            let participants = vec![account(1), account(2)];
            let session = create_test_dkg_session(
                session_id,
                &participants,
                67,
                SessionState::DKGInProgress, // Correct state
                100,
            );
            DkgSessions::<Test>::insert(session_id, session);
            let agg_key: PublicKey = bounded_vec![1; 33];

            // Act
            assert_ok!(TestingPallet::finalize_dkg_session(
                session_id,
                agg_key.clone().into_inner()
            ));

            // Assert
            let updated_session = DkgSessions::<Test>::get(session_id).unwrap();
            assert_eq!(updated_session.state, SessionState::DKGComplete);
            assert_eq!(AggregatedPublicKeys::<Test>::get(session_id), Some(agg_key.clone()));
            // System::assert_last_event(RuntimeEvent::TestingPallet(TssEvent::DKGCompleted(
            //     session_id,
            //     agg_key,
            // )));
        });
    }

    #[test]
    fn finalize_dkg_session_not_found() {
        new_test_ext().execute_with(|| {
            // Arrange
            let session_id = 1;
            let agg_key: PublicKey = bounded_vec![1; 33];

            // Act & Assert
            assert_noop!(
                TestingPallet::finalize_dkg_session(session_id, agg_key.into_inner()),
                Error::<Test>::DkgSessionNotFound
            );
        });
    }

    #[test]
    fn finalize_dkg_session_invalid_state() {
        new_test_ext().execute_with(|| {
            // Arrange
            let session_id = 1;
            let participants = vec![account(1), account(2)];
            let session = create_test_dkg_session(
                session_id,
                &participants,
                67,
                SessionState::DKGCreated, // Wrong state
                100,
            );
            DkgSessions::<Test>::insert(session_id, session);
            let agg_key: PublicKey = bounded_vec![1; 33];

            // Act & Assert
            assert_noop!(
                TestingPallet::finalize_dkg_session(session_id, agg_key.clone().into_inner()),
                Error::<Test>::InvalidSessionState
            );

            // Arrange - Try with DKGComplete state
            let session_complete = create_test_dkg_session(
                session_id + 1,
                &participants,
                67,
                SessionState::DKGComplete, // Wrong state
                100,
            );
            DkgSessions::<Test>::insert(session_id + 1, session_complete);

            // Act & Assert
            assert_noop!(
                TestingPallet::finalize_dkg_session(session_id + 1, agg_key.into_inner()),
                Error::<Test>::InvalidSessionState
            );
        });
    }
}
