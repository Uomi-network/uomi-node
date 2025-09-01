use std::sync::Arc;

use crate::{
    mock::*, pallet, types::{MaxNumberOfShares, NftId}, ActiveValidators, DkgSessions, Event as TssEvent, LastOpocRequestId, NextValidatorId, ParticipantReportCount, SessionState, SubmitDKGResultPayload, UpdateValidatorsPayload, CRYPTO_KEY_TYPE
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
use sp_core::U256;

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
                    sr25519::Signature::from_raw([0u8; 64])
                ));
            }
        }

        // Create a signing session
        let message = BoundedVec::<u8, _>::try_from(vec![1, 2, 3]).unwrap();
        assert_ok!(TestingPallet::create_signing_session(
            RuntimeOrigin::signed(create_test_account(None)),
            U256::from(1u8),
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
                U256::from(2u8),
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
            U256::from(3u8),
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
                    sr25519::Signature::from_raw([0u8; 64])
                ));
            }
        }

        // Create a signing session
        let message = BoundedVec::<u8, _>::try_from(vec![1, 2, 3]).unwrap();
        assert_ok!(TestingPallet::create_signing_session(
            RuntimeOrigin::signed(create_test_account(None)),
            U256::from(4u8),
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
            U256::from(5u64),
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
            System::assert_last_event(TssEvent::DKGExpired(session_id).into());
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
            System::assert_has_event(TssEvent::DKGExpired(1).into());
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
                RuntimeOrigin::signed(account(1)),
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
                TestingPallet::finalize_dkg_session(RuntimeOrigin::signed(account(1)), session_id, agg_key.into_inner()),
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
                TestingPallet::finalize_dkg_session(RuntimeOrigin::signed(account(1)), session_id, agg_key.clone().into_inner()),
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
                TestingPallet::finalize_dkg_session(RuntimeOrigin::signed(account(1)), session_id + 1, agg_key.into_inner()),
                Error::<Test>::InvalidSessionState
            );
        });
    }

    // --- Tests for build_chain_transaction ---

    #[test]
    fn build_chain_transaction_success() {
        new_test_ext().execute_with(|| {
            // Arrange
            let chain_id = 1; // Ethereum
            let to = "0x1111111111111111111111111111111111111111"; // 20 bytes
            let value: u64 = 1000;
            let data: [u8; 2] = [0x12, 0x34];
            let gas_limit: u64 = 21_000;
            let gas_price: u64 = 1_000_000_000; // 1 gwei
            let nonce: u64 = 0;

            // Act
            let encoded = TestingPallet::build_chain_transaction(
                chain_id,
                to,
                value,
                &data,
                gas_limit,
                gas_price,
                nonce,
            )
            .expect("should build tx");

            // Assert basic properties via RLP decoding
            let rlp = rlp::Rlp::new(&encoded);
            assert!(rlp.is_list());
            assert_eq!(rlp.item_count().unwrap(), 9, "EIP-155 legacy tx should have 9 fields");
            // nonce
            assert_eq!(rlp.val_at::<u64>(0).unwrap(), nonce);
            assert_eq!(rlp.val_at::<u64>(1).unwrap(), gas_price);
            assert_eq!(rlp.val_at::<u64>(2).unwrap(), gas_limit);
            let to_bytes: Vec<u8> = rlp.val_at(3).unwrap();
            assert_eq!(to_bytes.len(), 20);
            assert_eq!(hex::encode(&to_bytes), &to[2..]);
            assert_eq!(rlp.val_at::<u64>(4).unwrap(), value);
            let data_bytes: Vec<u8> = rlp.val_at(5).unwrap();
            assert_eq!(data_bytes, data);
            assert_eq!(rlp.val_at::<u64>(6).unwrap(), chain_id as u64);
            assert_eq!(rlp.val_at::<u8>(7).unwrap(), 0u8);
            assert_eq!(rlp.val_at::<u8>(8).unwrap(), 0u8);
        });
    }

    #[test]
    fn build_chain_transaction_unsupported_chain() {
        new_test_ext().execute_with(|| {
            // Chain ID not recognized at all
            let res = TestingPallet::build_chain_transaction(
                999_999,
                "0x1111111111111111111111111111111111111111",
                0,
                &[],
                21_000,
                1_000_000_000,
                0,
            );
            assert_eq!(res, Err("Unsupported chain ID"));
        });
    }

    #[test]
    fn build_chain_transaction_invalid_address() {
        new_test_ext().execute_with(|| {
            // Invalid address (too short)
            let res = TestingPallet::build_chain_transaction(
                1,
                "0x1234",
                0,
                &[],
                21_000,
                1_000_000_000,
                0,
            );
            assert_eq!(res, Err("Failed to build transaction"));
        });
    }
    #[test]
    fn build_actual_chain_transaction() {
        new_test_ext().execute_with(|| {
            let res = TestingPallet::build_chain_transaction(
                4386,
                "0x000000000000000000000000000000000000dead",
                10000000000000000,
                &[],
                21_000,
                30_000_000_000,
                0,
            );
            assert_eq!(res.is_ok(), true);
        });
    }

    // --- Additional tests for legacy/eip1559 helpers ---
    #[test]
    fn legacy_preimage_and_finalize_roundtrip() {
        use crate::multichain::TransactionBuilder;
        use ethereum_types::{H160, U256};
        let to = H160::from_low_u64_be(0xdeadbeefu64);
        let value = U256::from(1234u64);
        let data: Vec<u8> = vec![0x12, 0x34];
        let gas_limit = U256::from(21_000u64);
        let gas_price = U256::from(50_000_000_000u64);
        let nonce = U256::from(7u64);
        let chain_id = 1u64;
        let preimage = TransactionBuilder::legacy_preimage_rlp(
            to, value, &data, gas_limit, gas_price, nonce, chain_id,
        );
        // Ensure list length 9
        let rlp_pre = rlp::Rlp::new(&preimage);
        assert_eq!(rlp_pre.item_count().unwrap(), 9);
        // Finalize
        let r = U256::from(0x10u64);
        let s = U256::from(0x20u64);
        let recid = 1u8;
        let raw = TransactionBuilder::legacy_finalize_raw(
            to, value, &data, gas_limit, gas_price, nonce, chain_id, r, s, recid,
        );
        let rlp_raw = rlp::Rlp::new(&raw);
        assert_eq!(rlp_raw.item_count().unwrap(), 9);
        let v: U256 = rlp_raw.val_at(6).unwrap();
        assert_eq!(v, U256::from(35 + 2 * chain_id + 1));
        assert_ne!(preimage, raw, "preimage must differ from finalized raw tx");
    }

    #[test]
    fn eip1559_preimage_and_finalize_roundtrip() {
        use crate::multichain::TransactionBuilder;
        use ethereum_types::{H160, U256};
        let to = H160::from_low_u64_be(0xabcdefu64);
        let value = U256::from(1_000_000u64);
        let data: Vec<u8> = vec![];
        let gas_limit = U256::from(21000u64);
        let max_fee = U256::from(30_000_000_000u64);
        let max_priority = U256::from(1_500_000_000u64);
        let nonce = U256::from(5u64);
        let chain_id = 1u64;
        let preimage = TransactionBuilder::eip1559_preimage_bytes(
            to, value, &data, gas_limit, max_fee, max_priority, nonce, chain_id,
        );
        assert_eq!(preimage[0], 0x02); // type prefix
        let rlp_pre = rlp::Rlp::new(&preimage[1..]);
        assert_eq!(rlp_pre.item_count().unwrap(), 9);
        // Finalize
        let r = U256::from(0x55u64);
        let s = U256::from(0x66u64);
        let recid = 0u8;
        let raw = TransactionBuilder::eip1559_finalize_raw(
            to, value, &data, gas_limit, max_fee, max_priority, nonce, chain_id, r, s, recid,
        );
        assert_eq!(raw[0], 0x02);
        let rlp_raw = rlp::Rlp::new(&raw[1..]);
        assert_eq!(rlp_raw.item_count().unwrap(), 12);
        let y_parity: U256 = rlp_raw.val_at(9).unwrap();
        assert_eq!(y_parity, U256::zero());
        assert_ne!(preimage, raw, "preimage must differ from finalized raw tx");
    }

    // --- Structured action -> preimage construction tests ---

    #[test]
    fn structured_legacy_action_builds_expected_preimage() {
        use pallet_uomi_engine::Outputs as EngineOutputs; // storage alias
        use crate::multichain::TransactionBuilder;
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            let request_id = U256::from(1u8);
            let nft_id = U256::from(9u8);
            let chain_id = 1u32;
            let to = "0x1111111111111111111111111111111111111111";
            // Build JSON output with structured action (legacy)
            let json = format!(
                "{{\"actions\":[{{\"action_type\":\"transaction\",\"_trigger_policy\":\"\",\"data\":\"0x\",\"chain_id\":{},\"to\":\"{}\",\"value\":\"0x3e8\",\"gas_limit\":\"21000\",\"gas_price\":\"0x3b9aca00\",\"nonce\":\"0x0\",\"tx_type\":\"legacy\"}}],\"_response\":\"ok\"}}",
                chain_id, to
            );
            let data_bv: BoundedVec<u8, pallet_uomi_engine::MaxDataSize> = BoundedVec::try_from(json.clone().into_bytes()).unwrap();
            EngineOutputs::<Test>::insert(request_id, (data_bv, 1u32, 1u32, nft_id));

            // Process single request
            let res = TestingPallet::process_single_request(sp_core::U256::from(1u8)).expect("processing ok");
            let (_nft, maybe) = res.unwrap();
            assert_eq!(maybe.0, chain_id);
            let produced = maybe.1;

            // Build expected preimage directly
            let expected = TransactionBuilder::build_ethereum_transaction(
                to,
                1000u64,
                &[],
                21_000u64,
                1_000_000_000u64,
                0u64,
                chain_id,
            ).unwrap();
            assert_eq!(produced, expected, "constructed preimage should match builder output");
        });
    }

    #[test]
    fn structured_eip1559_action_builds_expected_preimage() {
        use crate::multichain::TransactionBuilder;
        use sp_core::U256;
    use pallet_uomi_engine::Outputs as EngineOutputs;
        new_test_ext().execute_with(|| {
            let request_id = U256::from(2u8);
            let nft_id = U256::from(10u8);
            let chain_id = 1u32;
            let to = "0x2222222222222222222222222222222222222222";
            let json = format!(
                "{{\"actions\":[{{\"action_type\":\"multi_chain_transaction\",\"_trigger_policy\":\"\",\"data\":\"0x\",\"chain_id\":{},\"to\":\"{}\",\"value\":\"0x0\",\"gas_limit\":\"21000\",\"tx_type\":\"eip1559\",\"max_fee_per_gas\":\"0x77359400\",\"max_priority_fee_per_gas\":\"0x3b9aca00\",\"nonce\":\"0x1\"}}],\"_response\":\"ok\"}}",
                chain_id, to
            );
            let data_bv: BoundedVec<u8, pallet_uomi_engine::MaxDataSize> = BoundedVec::try_from(json.clone().into_bytes()).unwrap();
            EngineOutputs::<Test>::insert(request_id, (data_bv, 1u32, 1u32, nft_id));

            let res = TestingPallet::process_single_request(sp_core::U256::from(2u8)).expect("processing ok");
            let (_nft, maybe) = res.unwrap();
            assert_eq!(maybe.0, chain_id);
            let produced = maybe.1;

            let expected = TransactionBuilder::build_eip1559_transaction(
                to,
                0u64,
                &[],
                21_000u64,
                2_000_000_000u64,      // 0x77359400 = 2 gwei
                1_000_000_000u64,      // priority fee 1 gwei
                1u64,
                chain_id,
            ).unwrap();
            assert_eq!(produced, expected, "EIP-1559 preimage mismatch");
            assert_eq!(produced[0], 0x02, "must have type prefix 0x02");
        });
    }

    #[test]
    fn structured_action_fallback_on_invalid_address() {
        use pallet_uomi_engine::Outputs as EngineOutputs;
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            let request_id = U256::from(3u8);
            let nft_id = U256::from(11u8);
            let chain_id = 1u32;
            // Invalid 'to' (too short) should trigger fallback to raw data bytes (empty in this case)
            let json = format!(
                "{{\"actions\":[{{\"action_type\":\"transaction\",\"_trigger_policy\":\"\",\"data\":\"0x010203\",\"chain_id\":{},\"to\":\"0x1234\",\"value\":\"0x0\",\"gas_limit\":\"21000\",\"gas_price\":\"0x3b9aca00\",\"nonce\":\"0x0\"}}],\"_response\":\"ok\"}}",
                chain_id
            );
            let raw_vec = vec![1u8,2u8,3u8];
            let data_bv: BoundedVec<u8, pallet_uomi_engine::MaxDataSize> = BoundedVec::try_from(json.clone().into_bytes()).unwrap();
            EngineOutputs::<Test>::insert(request_id, (data_bv, 1u32, 1u32, nft_id));
            let res = TestingPallet::process_single_request(sp_core::U256::from(3u8)).expect("processing ok");
            let (_nft, maybe) = res.unwrap();
            assert_eq!(maybe.0, chain_id);
            assert_eq!(maybe.1, raw_vec, "Should fallback to provided raw data when address invalid");
        });
    }

    #[test]
    fn structured_eip1559_default_data_action_builds_expected_preimage() {
        use pallet_uomi_engine::Outputs as EngineOutputs;
        use crate::multichain::TransactionBuilder;
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            let request_id = U256::from(2u8);
            let nft_id = U256::from(10u8);
            let chain_id = 4386u32;
            let to = "0x000000000000000000000000000000000000dead";
            let json = format!(
                "{{\"actions\":[{{\"action_type\":\"multi_chain_transaction\",\"data\":\"0x\",\"chain_id\":{},\"to\":\"{}\",\"value\":\"0x0\"}}],\"response\":\"ok\"}}",
                chain_id, to
            );


            let data_bv: BoundedVec<u8, pallet_uomi_engine::MaxDataSize> = BoundedVec::try_from(json.clone().into_bytes()).unwrap();
            EngineOutputs::<Test>::insert(request_id, (data_bv, 1u32, 1u32, nft_id));

            let res = TestingPallet::process_single_request(sp_core::U256::from(2u8)).expect("processing ok");
            let (_nft, maybe) = res.unwrap();
            assert_eq!(maybe.0, chain_id);
            let produced = maybe.1;

            let expected = TransactionBuilder::build_eip1559_transaction(
                to,
                0u64,
                &[],
                25_000u64, // updated default gas limit from dynamic estimation placeholder
                1_000_000_000,      // max fee 1 gwei
                1_000_000_000u64,   // priority fee 1 gwei
                0u64,
                chain_id,
            ).unwrap();
            assert_eq!(produced, expected, "EIP-1559 preimage mismatch");
            assert_eq!(produced[0], 0x02, "must have type prefix 0x02");
        });
    }

    #[test]
    fn structured_action_malformed_hex_data_graceful_fallback() {
        use pallet_uomi_engine::Outputs as EngineOutputs;
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            let request_id = U256::from(50u8);
            let nft_id = U256::from(77u8);
            let chain_id = 1u32;
            // Malformed hex: odd length + invalid 'g' character
            let json = format!(
                "{{\"actions\":[{{\"action_type\":\"transaction\",\"data\":\"0x1g2\",\"chain_id\":{},\"to\":\"0x1111111111111111111111111111111111111111\",\"value\":\"0x0\"}}]}}",
                chain_id
            );
            let data_bv: BoundedVec<u8, pallet_uomi_engine::MaxDataSize> = BoundedVec::try_from(json.clone().into_bytes()).unwrap();
            EngineOutputs::<Test>::insert(request_id, (data_bv, 1u32, 1u32, nft_id));
            let res = TestingPallet::process_single_request(sp_core::U256::from(50u8)).expect("processing ok");
            let (_nft, maybe) = res.unwrap();
            assert_eq!(maybe.0, chain_id);
            // Malformed hex should decode to empty vec (log warning) then used as raw data or for tx build failure fallback.
            // Address is valid so builder tries; since data empty allowed, preimage should not be empty length 0 but a valid preimage (legacy default)
            assert!(!maybe.1.is_empty(), "Should have produced a preimage despite malformed data hex (decoded to empty)");
        });
    }
    #[test]
    fn opoc_iteration_from_zero_u256() {
        use pallet_uomi_engine::Outputs as EngineOutputs;
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            // Ensure starting point
            LastOpocRequestId::<Test>::put(U256::zero());
            for id in 1u8..=5u8 { 
                let req_id = U256::from(id);
                let nft_id = U256::from(100u64 + id as u64);
                let json = format!("{{\"actions\":[{{\"action_type\":\"multi_chain_transaction\",\"data\":\"0x\",\"chain_id\":1}}]}}" );
                let data_bv: BoundedVec<u8, pallet_uomi_engine::MaxDataSize> = BoundedVec::try_from(json.into_bytes()).unwrap();
                EngineOutputs::<Test>::insert(req_id, (data_bv, 1u32, 1u32, nft_id));
            }
            let (map, last) = TestingPallet::process_opoc_requests().expect("should process");
            assert_eq!(map.len(), 5, "Should collect five requests with data");
            // Implementation advances last_processed through up to 5 IDs whether or not outputs exist
            assert_eq!(last, U256::from(5u8), "Last processed should reflect full scan window (5 IDs)");
            assert!(map.keys().max().unwrap() == &U256::from(5u8));
        });
    }

    #[test]
    fn opoc_iteration_large_u256_boundary() {
        use pallet_uomi_engine::Outputs as EngineOutputs;
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            // Set last id near 2^40 boundary to ensure we don't truncate
            let start = U256::from(1u128 << 40); // large value
            LastOpocRequestId::<Test>::put(start);
            let next = start + U256::one();
            let nft_id = U256::from(999u64);
            let json = "{\"actions\":[{\"action_type\":\"multi_chain_transaction\",\"data\":\"0x\",\"chain_id\":4386}] }".to_string();
            let data_bv: BoundedVec<u8, pallet_uomi_engine::MaxDataSize> = BoundedVec::try_from(json.into_bytes()).unwrap();
            EngineOutputs::<Test>::insert(next, (data_bv, 1u32, 1u32, nft_id));
            let (map, last) = TestingPallet::process_opoc_requests().expect("should process");
            assert_eq!(map.len(), 1, "Should process exactly one large-id request with data");
            assert!(map.contains_key(&next));
            // Expect last to be start + 5 (processed scan window) because only one request was found
            assert_eq!(last, start + U256::from(1u8));
        });
    }

    #[test]
    fn opoc_iteration_no_requests() {
        use pallet_uomi_engine::Outputs as EngineOutputs;
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            // Set last id near 2^40 boundary to ensure we don't truncate
            let start = U256::from(1u128 << 40); // large value
            LastOpocRequestId::<Test>::put(start);
            let res = TestingPallet::process_opoc_requests();

            assert!(res.is_err());
            assert_eq!(res, Err("No requests to sign found"));

        });
    }

    // --- New tests for request_id based linking & dedup ---
    #[test]
    fn request_id_deduplication_and_storage() {
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            // Prepare validators & DKG session
            let validators = vec![account(10), account(11), account(12)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(1u64);
            let nft_id_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            assert_ok!(TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                nft_id_bytes.clone().try_into().unwrap(),
                60
            ));
            // Complete DKG (submit enough identical results)
            let agg_key = [2u8; 33];
            for v in &validators { 
                let session = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
                if session.state < SessionState::DKGComplete {
                    assert_ok!(TestingPallet::submit_dkg_result(
                        RuntimeOrigin::none(),
                        SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(agg_key.to_vec()), public: v.clone() },
                        sr25519::Signature::from_raw([0u8; 64])
                    ));
                }
            }
            // Build unsigned payload
            let request_id = U256::from(555u64);
            let nft_id_u256 = nft_id_u256; // same as used for DKG session
            let chain_id = 99u32;
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![9,9,9]).unwrap();
            let payload = crate::CreateSigningSessionPayload::<Test> { request_id, nft_id: nft_id_u256, chain_id, message: msg.clone(), public: account(10) };
            // First unsigned call creates session & stores request
            assert_ok!(TestingPallet::create_signing_session_unsigned(RuntimeOrigin::none(), payload.clone(), sr25519::Signature::from_raw([0u8;64])));
            let sessions_after_first: Vec<_> = crate::SigningSessions::<Test>::iter().collect();
            assert_eq!(sessions_after_first.len(), 1, "One signing session expected");
            assert!(crate::FsaTransactionRequests::<Test>::contains_key(&request_id), "Storage keyed by request_id should exist");
            // Second identical unsigned call should be idempotent (no new session)
            assert_ok!(TestingPallet::create_signing_session_unsigned(RuntimeOrigin::none(), payload, sr25519::Signature::from_raw([0u8;64])));
            let sessions_after_second: Vec<_> = crate::SigningSessions::<Test>::iter().collect();
            assert_eq!(sessions_after_second.len(), 1, "No duplicate session should be created for same request_id");
            // Ensure session carries request_id
            let (_sid, sess) = sessions_after_second[0].clone();
            assert_eq!(sess.request_id, request_id);
            assert_eq!(sess.message, msg);
        });
    }

    #[test]
    fn request_id_cleanup_after_signature_processing() {
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            // Setup DKG complete for nft_id
            let validators = vec![account(10), account(11), account(12)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(3u64);
            let nft_id_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            assert_ok!(TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                nft_id_bytes.clone().try_into().unwrap(),
                60
            ));
            let agg_key = [3u8; 33];
            for v in &validators { 
                let session = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
                if session.state < SessionState::DKGComplete {
                    assert_ok!(TestingPallet::submit_dkg_result(
                        RuntimeOrigin::none(),
                        SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(agg_key.to_vec()), public: v.clone() },
                        sr25519::Signature::from_raw([0u8; 64])
                    ));
                }
            }
            // Create unsigned signing session
            let request_id = U256::from(777u64);
            let nft_id_u256 = nft_id_u256; // reuse
            let chain_id = 7u32;
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![7]).unwrap();
            let payload = crate::CreateSigningSessionPayload::<Test> { request_id, nft_id: nft_id_u256, chain_id, message: msg.clone(), public: account(10) };
            assert_ok!(TestingPallet::create_signing_session_unsigned(RuntimeOrigin::none(), payload, sr25519::Signature::from_raw([0u8;64])));
            // Manually set aggregated signature to simulate completion
            let (sid, mut session) = crate::SigningSessions::<Test>::iter().next().unwrap();
            session.aggregated_sig = Some(BoundedVec::truncate_from(vec![1u8; 65]));
            crate::SigningSessions::<Test>::insert(sid, session.clone());
            assert!(crate::FsaTransactionRequests::<Test>::contains_key(&request_id));
            // Also ensure FsaTransactionRequests holds expected tuple shape
            let stored = crate::FsaTransactionRequests::<Test>::get(&request_id).expect("entry exists");
            assert_eq!(stored.1, chain_id);
            assert_eq!(stored.2, msg);
            // Process completed signatures, which should submit (mock) and remove storage
            assert_ok!(TestingPallet::process_completed_signatures());
            assert!(!crate::FsaTransactionRequests::<Test>::contains_key(&request_id), "Entry should be removed after processing");
        });
    }

    #[test]
    fn multiple_distinct_request_ids_same_nft_create_multiple_sessions() {
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            // Prepare validators & complete a single DKG for an nft_id
            let validators = vec![account(10), account(11), account(12)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(42u64);
            let nft_id_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let expected_nft: NftId = nft_id_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                expected_nft.clone(),
                60
            ));
            let agg_key = [5u8; 33];
            for v in &validators {
                let session = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
                if session.state < SessionState::DKGComplete {
                    assert_ok!(TestingPallet::submit_dkg_result(
                        RuntimeOrigin::none(),
                        SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(agg_key.to_vec()), public: v.clone() },
                        sr25519::Signature::from_raw([0u8; 64])
                    ));
                }
            }
            // Prepare three distinct request_ids with same nft_id
            let chain_id = 123u32;
            let requests = vec![
                (U256::from(1000u64), vec![1u8]),
                (U256::from(1001u64), vec![2u8]),
                (U256::from(1002u64), vec![3u8]),
            ];
            for (idx, (request_id, msg_vec)) in requests.iter().enumerate() {
                let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(msg_vec.clone()).unwrap();
                let payload = crate::CreateSigningSessionPayload::<Test> { request_id: *request_id, nft_id: nft_id_u256, chain_id, message: msg.clone(), public: account(10) };
                assert_ok!(TestingPallet::create_signing_session_unsigned(RuntimeOrigin::none(), payload, sr25519::Signature::from_raw([0u8;64])));
                let sessions_so_far: Vec<_> = crate::SigningSessions::<Test>::iter().collect();
                assert_eq!(sessions_so_far.len(), idx + 1, "Expected {} sessions after inserting distinct request_ids", idx + 1);
                assert!(crate::FsaTransactionRequests::<Test>::contains_key(request_id), "Storage should contain entry for new request_id");
            }
            // Final assertions
            let all_sessions: Vec<_> = crate::SigningSessions::<Test>::iter().collect();
            assert_eq!(all_sessions.len(), 3, "Exactly three signing sessions expected");
            let mut seen = sp_std::collections::btree_set::BTreeSet::new();
            for (_sid, sess) in &all_sessions { seen.insert(sess.request_id); assert_eq!(sess.nft_id, expected_nft); }
            assert_eq!(seen.len(), 3, "All request_ids must be distinct");
        });
    }

    #[test]
    fn dkg_reshare_supersedes_previous_and_signing_uses_latest() {
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            // Prepare validators & initialize
            let validators = vec![account(20), account(21), account(22), account(23)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            // Also register validators in staking pallet so reshare session picks them up
            let prefs = pallet_staking::ValidatorPrefs { commission: Perbill::from_percent(0), blocked: false };
            for v in &validators { pallet_staking::Validators::<Test>::insert(v.clone(), prefs.clone()); }
            // First DKG (record next_session_id BEFORE call; the created session will use this value)
            let first_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(900u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                nft_id.clone(),
                60
            ));
            // Sanity: session now exists
            assert!(TestingPallet::get_dkg_session(first_session_id).is_some(), "First DKG session should exist");
            // Complete first DKG
            let agg1 = [7u8; 33];
            for v in &validators {
                let s = TestingPallet::get_dkg_session(first_session_id).unwrap();
                if s.state < SessionState::DKGComplete {
                    assert_ok!(TestingPallet::submit_dkg_result(
                        RuntimeOrigin::none(),
                        SubmitDKGResultPayload { session_id: first_session_id, public_key: BoundedVec::truncate_from(agg1.to_vec()), public: v.clone() },
                        sr25519::Signature::from_raw([0u8;64])
                    ));
                }
            }
            assert_eq!(TestingPallet::get_dkg_session(first_session_id).unwrap().state, SessionState::DKGComplete);

            // Reshare (second DKG). Capture next_session_id BEFORE call again.
            let second_session_id = TestingPallet::next_session_id();
            let old_participants = TestingPallet::get_dkg_session(first_session_id).unwrap().participants.clone();
            assert_ok!(TestingPallet::create_reshare_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                nft_id.clone(),
                60,
                old_participants
            ));
            assert!(TestingPallet::get_dkg_session(second_session_id).is_some(), "Second DKG session should exist");
            // Complete second DKG
            let agg2 = [8u8; 33];
            for v in &validators {
                let s = TestingPallet::get_dkg_session(second_session_id).unwrap();
                if s.state < SessionState::DKGComplete {
                    assert_ok!(TestingPallet::submit_dkg_result(
                        RuntimeOrigin::none(),
                        SubmitDKGResultPayload { session_id: second_session_id, public_key: BoundedVec::truncate_from(agg2.to_vec()), public: v.clone() },
                        sr25519::Signature::from_raw([0u8;64])
                    ));
                }
            }
            // Old should now be marked DKGSuperseded; new is complete
            assert_eq!(TestingPallet::get_dkg_session(first_session_id).unwrap().state, SessionState::DKGSuperseded, "First DKG should be superseded");
            assert_eq!(TestingPallet::get_dkg_session(second_session_id).unwrap().state, SessionState::DKGComplete);

            // Create signing session; it must bind to second_session_id (latest complete)
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![1,2,3]).unwrap();
            assert_ok!(TestingPallet::create_signing_session(
                RuntimeOrigin::none(),
                U256::from(1u64),
                nft_id.clone(),
                msg.clone()
            ));
            let (_sign_id, sign_session) = crate::SigningSessions::<Test>::iter().next().unwrap();
            assert_eq!(sign_session.dkg_session_id, second_session_id, "Signing session should use latest completed DKG session");
        });
    }

    #[test]
    fn signing_session_expires_after_ttl() {
        use sp_core::U256;
    use sp_runtime::SaturatedConversion; // for saturated_into on BlockNumber
    use frame_support::traits::Hooks; // bring on_initialize into scope
    use crate::ProposedSignatures;
        new_test_ext().execute_with(|| {
            // Setup validators & DKG
            let validators = vec![account(30), account(31), account(32)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(1001u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                nft_id.clone(),
                60
            ));
            // Complete DKG
            let aggk = [9u8; 33];
            for v in &validators {
                let s = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
                if s.state < SessionState::DKGComplete {
                    assert_ok!(TestingPallet::submit_dkg_result(
                        RuntimeOrigin::none(),
                        SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggk.to_vec()), public: v.clone() },
                        sr25519::Signature::from_raw([0u8;64])
                    ));
                }
            }
            assert_eq!(TestingPallet::get_dkg_session(dkg_session_id).unwrap().state, SessionState::DKGComplete);

            // Create signing session at block 1
            System::set_block_number(1);
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![42]).unwrap();
            assert_ok!(TestingPallet::create_signing_session(
                RuntimeOrigin::none(),
                U256::from(888u64),
                nft_id.clone(),
                msg
            ));
            let (sid, sess) = crate::SigningSessions::<Test>::iter().next().unwrap();
            assert_eq!(sess.state, SessionState::SigningInProgress);
            let expiry = crate::SigningSessionExpiry::<Test>::get(sid).expect("expiry set");
            // Ensure expiry after block 1
            assert!(expiry > 1u32.into());

            // Insert partial signature votes to ensure GC on expiry
            ProposedSignatures::<Test>::insert(sid, 1u32, BoundedVec::truncate_from(vec![1u8;65]));
            ProposedSignatures::<Test>::insert(sid, 2u32, BoundedVec::truncate_from(vec![1u8;65]));
            assert_eq!(ProposedSignatures::<Test>::iter_prefix(sid).count(), 2);

            // Advance to just before expiry and trigger on_initialize
            let expiry_u64: u64 = expiry.saturated_into::<u64>();
            let before_expiry = expiry_u64 - 1;
            System::set_block_number(before_expiry.into());
            <TestingPallet as Hooks<_>>::on_initialize(before_expiry.into());
            assert_eq!(crate::SigningSessions::<Test>::get(sid).unwrap().state, SessionState::SigningInProgress, "Should still be in progress before expiry");

            // Advance to expiry block; should expire now
            System::set_block_number(expiry);
            <TestingPallet as Hooks<_>>::on_initialize(expiry);
            let expired_session = crate::SigningSessions::<Test>::get(sid).unwrap();
            assert_eq!(expired_session.state, SessionState::SigningExpired, "Expired signing session marked using SigningExpired state");
            assert!(crate::SigningSessionExpiry::<Test>::get(sid).is_none(), "Expiry entry cleaned up");
            assert_eq!(ProposedSignatures::<Test>::iter_prefix(sid).count(), 0, "Votes GC'd on expiry");
        });
    }

    // --- Signing retry logic tests ---
    #[test]
    fn signing_retry_creates_new_session_after_expiry() {
        use sp_core::U256;
        use frame_support::traits::Hooks;
        new_test_ext().execute_with(|| {
            let validators = vec![account(90), account(91), account(92)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            // DKG
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(12345u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(RuntimeOrigin::signed(create_test_account(None)), nft_id.clone(), 60));
            let aggk = [7u8; 33];
            for v in &validators { // finalize DKG
                let s = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
                if s.state < SessionState::DKGComplete {
                    assert_ok!(TestingPallet::submit_dkg_result(RuntimeOrigin::none(), SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggk.to_vec()), public: v.clone() }, sr25519::Signature::from_raw([0u8;64])));
                }
            }
            // First signing attempt
            System::set_block_number(10);
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![9]).unwrap();
            let request_id = U256::from(777u64);
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
            let (first_sid, _) = crate::SigningSessions::<Test>::iter().next().unwrap();
            let expiry = crate::SigningSessionExpiry::<Test>::get(first_sid).expect("expiry set");
            // Force expiry
            System::set_block_number(expiry);
            <TestingPallet as Hooks<_>>::on_initialize(expiry);
            assert_eq!(crate::SigningSessions::<Test>::get(first_sid).unwrap().state, SessionState::SigningExpired);
            // Second attempt auto allowed
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
            assert_eq!(crate::SigningSessions::<Test>::iter().count(), 2, "New signing session created after expiry");
        });
    }

    #[test]
    fn signing_retry_caps_after_max_attempts() {
        use sp_core::U256;
        use frame_support::traits::Hooks;
        new_test_ext().execute_with(|| {
            let validators = vec![account(93), account(94), account(95)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            // DKG finalize
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(223344u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(RuntimeOrigin::signed(create_test_account(None)), nft_id.clone(), 60));
            let aggk = [8u8; 33];
            for v in &validators { let s = TestingPallet::get_dkg_session(dkg_session_id).unwrap(); if s.state < SessionState::DKGComplete { assert_ok!(TestingPallet::submit_dkg_result(RuntimeOrigin::none(), SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggk.to_vec()), public: v.clone() }, sr25519::Signature::from_raw([0u8;64]))); } }
            let request_id = U256::from(888888u64);
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![1]).unwrap();
            // Perform 3 attempts (MAX=3) by expiring each
            for _ in 0..3 { // create & expire up to the max allowed attempts
                assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
                // Fetch the latest session for this request_id (highest session id)
                let (sid, _sess) = crate::SigningSessions::<Test>::iter()
                    .filter(|(_id, s)| s.request_id == request_id)
                    .max_by_key(|(id, _)| *id)
                    .expect("signing session just created");
                let expiry = crate::SigningSessionExpiry::<Test>::get(sid).expect("expiry set");
                System::set_block_number(expiry);
                <TestingPallet as Hooks<_>>::on_initialize(expiry);
                assert_eq!(crate::SigningSessions::<Test>::get(sid).unwrap().state, SessionState::SigningExpired, "attempt should expire");
            }
            // Fourth attempt should be ignored (no new session)
            let count_before = crate::SigningSessions::<Test>::iter().count();
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
            let count_after = crate::SigningSessions::<Test>::iter().count();
            assert_eq!(count_before, count_after, "No new session after retries exhausted");
        });
    }

    #[test]
    fn signing_retry_events_emitted() {
        use sp_core::U256;
        use frame_support::traits::Hooks;
        new_test_ext().execute_with(|| {
            let validators = vec![account(120), account(121), account(122)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            // DKG finalize
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(777777u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(RuntimeOrigin::signed(create_test_account(None)), nft_id.clone(), 60));
            let aggk = [11u8; 33];
            for v in &validators { let s = TestingPallet::get_dkg_session(dkg_session_id).unwrap(); if s.state < SessionState::DKGComplete { assert_ok!(TestingPallet::submit_dkg_result(RuntimeOrigin::none(), SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggk.to_vec()), public: v.clone() }, sr25519::Signature::from_raw([0u8;64]))); } }
            let request_id = U256::from(424242u64);
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![5]).unwrap();
            // First attempt (no SigningRetry event expected, only SigningSessionCreated)
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
            for ev in System::events() { assert!(!matches!(ev.event, RuntimeEvent::TestingPallet(crate::Event::SigningRetry(_,1,_))), "No SigningRetry for first attempt"); }
            System::reset_events();
            // Expire first
            let first_sid = crate::SigningSessions::<Test>::iter().next().unwrap().0;
            let expiry = crate::SigningSessionExpiry::<Test>::get(first_sid).unwrap();
            System::set_block_number(expiry);
            <TestingPallet as Hooks<_>>::on_initialize(expiry);
            // Second attempt
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
            let mut saw_second = false;
            for ev in System::events() { if matches!(ev.event, RuntimeEvent::TestingPallet(crate::Event::SigningRetry(rid, attempt, _)) if rid == request_id && attempt == 2) { saw_second = true; } }
            assert!(saw_second, "Second attempt should emit SigningRetry (attempt=2)");
            System::reset_events();
            // Expire second & third attempt then check exhausted on fourth
            for expected_attempt in 2..=3 { // we already created attempt 2
                let latest_sid = crate::SigningSessions::<Test>::iter().filter(|(_, s)| s.request_id == request_id).max_by_key(|(id, _)| *id).unwrap().0;
                let expiry_block = crate::SigningSessionExpiry::<Test>::get(latest_sid).unwrap();
                System::set_block_number(expiry_block);
                <TestingPallet as Hooks<_>>::on_initialize(expiry_block);
                if expected_attempt < 3 { // create next attempt (attempt 3)
                    assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
                    let mut saw_retry = false; let attempt_number = expected_attempt + 1; // 3
                    for ev in System::events() { if matches!(ev.event, RuntimeEvent::TestingPallet(crate::Event::SigningRetry(rid, a, _)) if rid == request_id && a == attempt_number) { saw_retry = true; } }
                    assert!(saw_retry, "Attempt {} SigningRetry event expected", attempt_number);
                    System::reset_events();
                }
            }
            // Now attempts 1,2,3 done; further call should emit SigningRetriesExhausted and no new session
            let session_count_before = crate::SigningSessions::<Test>::iter().count();
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg));
            let mut exhausted = false;
            for ev in System::events() { if matches!(ev.event, RuntimeEvent::TestingPallet(crate::Event::SigningRetriesExhausted(rid, attempts)) if rid == request_id && attempts == 3) { exhausted = true; } }
            assert!(exhausted, "SigningRetriesExhausted event expected after max attempts");
            let session_count_after = crate::SigningSessions::<Test>::iter().count();
            assert_eq!(session_count_before, session_count_after, "No new session created after exhaustion");
        });
    }

    #[test]
    fn signing_retry_counter_cleared_on_success() {
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            let validators = vec![account(96), account(97), account(98)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            // DKG finalize
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(445566u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(RuntimeOrigin::signed(create_test_account(None)), nft_id.clone(), 60));
            let aggk = [9u8; 33];
            for v in &validators { let s = TestingPallet::get_dkg_session(dkg_session_id).unwrap(); if s.state < SessionState::DKGComplete { assert_ok!(TestingPallet::submit_dkg_result(RuntimeOrigin::none(), SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggk.to_vec()), public: v.clone() }, sr25519::Signature::from_raw([0u8;64]))); } }
            let request_id = U256::from(999u64);
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![2]).unwrap();
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
            let (sid, _) = crate::SigningSessions::<Test>::iter().next().unwrap();
            // Need >= 67% of 3 validators => 2 votes
            let fake_sig = BoundedVec::truncate_from(vec![3u8;65]);
            for voter in validators.iter().take(2) { // submit two matching votes
                assert_ok!(TestingPallet::submit_signature_result(
                    RuntimeOrigin::none(),
                    crate::payloads::SubmitSignatureResultPayload { session_id: sid, signature: fake_sig.clone(), public: voter.clone() },
                    sr25519::Signature::from_raw([0u8;64])
                ));
            }
            assert_eq!(crate::SigningSessions::<Test>::get(sid).unwrap().state, SessionState::SigningComplete, "Session should complete after quorum");
            assert!(crate::RequestRetryCount::<Test>::get(request_id) == 0, "Retry counter cleared on success");
        });
    }

    #[test]
    fn end_to_end_reshare_and_retry_flow() {
        use sp_core::U256;
        use frame_support::traits::Hooks;
        new_test_ext().execute_with(|| {
            let validators = vec![account(150), account(151), account(152)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            // Register validators in staking as in other reshare tests
            let prefs = pallet_staking::ValidatorPrefs { commission: Perbill::from_percent(0), blocked: false };
            for v in &validators { pallet_staking::Validators::<Test>::insert(v.clone(), prefs.clone()); }

            // --- Initial DKG ---
            let initial_dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(2024u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(RuntimeOrigin::signed(create_test_account(None)), nft_id.clone(), 60));
            let aggk1 = [21u8;33];
            for v in &validators { let s = TestingPallet::get_dkg_session(initial_dkg_session_id).unwrap(); if s.state < SessionState::DKGComplete { assert_ok!(TestingPallet::submit_dkg_result(RuntimeOrigin::none(), SubmitDKGResultPayload { session_id: initial_dkg_session_id, public_key: BoundedVec::truncate_from(aggk1.to_vec()), public: v.clone() }, sr25519::Signature::from_raw([0u8;64]))); } }
            assert_eq!(TestingPallet::get_dkg_session(initial_dkg_session_id).unwrap().state, SessionState::DKGComplete, "Initial DKG should complete");

            // --- First signing attempt (will expire) ---
            let request_id = U256::from(1111u64);
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![42]).unwrap();
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
            let (first_signing_sid, first_signing) = crate::SigningSessions::<Test>::iter().next().unwrap();
            assert_eq!(first_signing.dkg_session_id, initial_dkg_session_id, "Signing should reference initial DKG");
            // Force expiry
            let expiry_block = crate::SigningSessionExpiry::<Test>::get(first_signing_sid).unwrap();
            System::set_block_number(expiry_block);
            <TestingPallet as Hooks<_>>::on_initialize(expiry_block);
            assert_eq!(crate::SigningSessions::<Test>::get(first_signing_sid).unwrap().state, SessionState::SigningExpired, "First signing attempt expired");

            // --- Reshare DKG (new key) ---
            // create reshare DKG (capture next_session_id BEFORE call like other tests)
            let reshare_session_id = TestingPallet::next_session_id();
            let old_participants = TestingPallet::get_dkg_session(initial_dkg_session_id).unwrap().participants.clone();
            assert_ok!(TestingPallet::create_reshare_dkg_session(RuntimeOrigin::signed(create_test_account(None)), nft_id.clone(), 60, old_participants));
            let aggk2 = [22u8;33];
            for v in &validators { let s = TestingPallet::get_dkg_session(reshare_session_id).unwrap(); if s.state < SessionState::DKGComplete { assert_ok!(TestingPallet::submit_dkg_result(RuntimeOrigin::none(), SubmitDKGResultPayload { session_id: reshare_session_id, public_key: BoundedVec::truncate_from(aggk2.to_vec()), public: v.clone() }, sr25519::Signature::from_raw([0u8;64]))); } }
            assert_eq!(TestingPallet::get_dkg_session(reshare_session_id).unwrap().state, SessionState::DKGComplete, "Reshare DKG completes");
            // Older DKG should now be superseded
            assert_eq!(TestingPallet::get_dkg_session(initial_dkg_session_id).unwrap().state, SessionState::DKGSuperseded, "Initial DKG superseded by reshare");

            // --- New signing attempt uses latest DKG ---
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
            // Fetch latest signing session for request
            let (second_signing_sid, second_signing) = crate::SigningSessions::<Test>::iter().filter(|(_, s)| s.request_id == request_id).max_by_key(|(id, _)| *id).unwrap();
            assert_eq!(second_signing.dkg_session_id, reshare_session_id, "Second signing should bind to reshare DKG");

            // Finalize signing with quorum signatures (2/3)
            let fake_sig = BoundedVec::truncate_from(vec![0xAB;65]);
            for signer in validators.iter().take(2) {
                assert_ok!(TestingPallet::submit_signature_result(RuntimeOrigin::none(), crate::payloads::SubmitSignatureResultPayload { session_id: second_signing_sid, signature: fake_sig.clone(), public: signer.clone() }, sr25519::Signature::from_raw([0u8;64])));
            }
            assert_eq!(crate::SigningSessions::<Test>::get(second_signing_sid).unwrap().state, SessionState::SigningComplete, "Second signing completes");
            assert_eq!(crate::RequestRetryCount::<Test>::get(request_id), 0, "Retry counter cleared after successful signing");
        });
    }

    #[test]
    fn signing_no_duplicate_while_in_progress() {
        use sp_core::U256;
        new_test_ext().execute_with(|| {
            let validators = vec![account(101), account(102), account(103)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = U256::from(123123u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(RuntimeOrigin::signed(create_test_account(None)), nft_id.clone(), 60));
            let aggk = [10u8; 33];
            for v in &validators { let s = TestingPallet::get_dkg_session(dkg_session_id).unwrap(); if s.state < SessionState::DKGComplete { assert_ok!(TestingPallet::submit_dkg_result(RuntimeOrigin::none(), SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggk.to_vec()), public: v.clone() }, sr25519::Signature::from_raw([0u8;64]))); } }
            let request_id = U256::from(4242u64);
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![4]).unwrap();
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
            let count_before = crate::SigningSessions::<Test>::iter().count();
            // Attempt duplicate while in progress
            assert_ok!(TestingPallet::create_signing_session(RuntimeOrigin::none(), request_id, nft_id.clone(), msg.clone()));
            let count_after = crate::SigningSessions::<Test>::iter().count();
            assert_eq!(count_before, count_after, "Duplicate in-progress prevented");
        });
    }

    #[test]
    fn dkg_proposed_public_keys_cleared_on_completion() {
        new_test_ext().execute_with(|| {
            use crate::ProposedPublicKeys;
            let validators = vec![account(40), account(41), account(42)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = sp_core::U256::from(6000u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                nft_id.clone(),
                60
            ));
            let aggk = [11u8; 33];
            for v in &validators {
                let s = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
                if s.state < SessionState::DKGComplete {
                    assert_ok!(TestingPallet::submit_dkg_result(
                        RuntimeOrigin::none(),
                        SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggk.to_vec()), public: v.clone() },
                        sr25519::Signature::from_raw([0u8;64])
                    ));
                }
            }
            assert_eq!(TestingPallet::get_dkg_session(dkg_session_id).unwrap().state, SessionState::DKGComplete);
            assert_eq!(ProposedPublicKeys::<Test>::iter_prefix(nft_id).count(), 0, "ProposedPublicKeys cleared");
        });
    }

    #[test]
    fn signing_proposed_signatures_cleared_on_completion() {
        new_test_ext().execute_with(|| {
            use crate::ProposedSignatures;
            let validators = vec![account(50), account(51), account(52)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            let dkg_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = sp_core::U256::from(7000u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                nft_id.clone(),
                60
            ));
            let aggk = [13u8; 33];
            for v in &validators {
                let s = TestingPallet::get_dkg_session(dkg_session_id).unwrap();
                if s.state < SessionState::DKGComplete {
                    assert_ok!(TestingPallet::submit_dkg_result(
                        RuntimeOrigin::none(),
                        SubmitDKGResultPayload { session_id: dkg_session_id, public_key: BoundedVec::truncate_from(aggk.to_vec()), public: v.clone() },
                        sr25519::Signature::from_raw([0u8;64])
                    ));
                }
            }
            let msg: BoundedVec<u8, crate::types::MaxMessageSize> = BoundedVec::try_from(vec![5,5,5]).unwrap();
            assert_ok!(TestingPallet::create_signing_session(
                RuntimeOrigin::none(),
                sp_core::U256::from(9000u64),
                nft_id.clone(),
                msg
            ));
            let (sign_id, _s) = crate::SigningSessions::<Test>::iter().next().unwrap();
            let sig = BoundedVec::truncate_from(vec![2u8;65]);
            // Insert single vote and then finalize via submit_signature_result which will also insert same vote again but that's fine
            ProposedSignatures::<Test>::insert(sign_id, 1u32, sig.clone());
            assert_ok!(TestingPallet::submit_signature_result(
                RuntimeOrigin::none(),
                crate::payloads::SubmitSignatureResultPayload { session_id: sign_id, signature: sig.clone(), public: validators[0].clone() },
                sr25519::Signature::from_raw([0u8;64])
            ));
            assert_eq!(ProposedSignatures::<Test>::iter_prefix(sign_id).count(), 0, "Votes cleared on completion");
        });
    }

    // --- Added coverage: DKG expiration GC ---
    #[test]
    fn dkg_expiration_clears_votes_and_session_removed() {
    // removed unused SaturatedConversion import
    use frame_support::traits::Hooks;
        new_test_ext().execute_with(|| {
            let validators = vec![account(80), account(81), account(82), account(83)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            let session_id = TestingPallet::next_session_id();
            let nft_id_u256 = sp_core::U256::from(9100u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                nft_id.clone(),
                60
            ));
            // Single vote only
            let aggk = [22u8; 33];
            assert_ok!(TestingPallet::submit_dkg_result(
                RuntimeOrigin::none(),
                SubmitDKGResultPayload { session_id, public_key: BoundedVec::truncate_from(aggk.to_vec()), public: validators[0].clone() },
                sr25519::Signature::from_raw([0u8;64])
            ));
            let s = TestingPallet::get_dkg_session(session_id).unwrap();
            assert!(s.state < SessionState::DKGComplete);
            assert!(crate::ProposedPublicKeys::<Test>::iter_prefix(nft_id.clone()).next().is_some());
            use frame_system::pallet_prelude::BlockNumberFor;
            let after_deadline = s.deadline + BlockNumberFor::<Test>::from(1u32);
            System::set_block_number(after_deadline);
            <TestingPallet as Hooks<_>>::on_initialize(after_deadline);
            assert!(TestingPallet::get_dkg_session(session_id).is_none(), "Expired session removed");
            assert_eq!(crate::ProposedPublicKeys::<Test>::iter_prefix(nft_id).count(), 0, "Votes GC'd");
        });
    }

    // --- Added coverage: internal finalize supersession & GC ---
    #[test]
    fn finalize_internal_supersedes_and_gcs_votes() {
        new_test_ext().execute_with(|| {
            let validators = vec![account(81), account(82), account(83)];
            setup_active_validators(&validators);
            let _ = TestingPallet::initialize_validator_ids();
            let first_session_id = TestingPallet::next_session_id();
            let nft_id_u256 = sp_core::U256::from(9200u64);
            let nft_bytes: Vec<u8> = nft_id_u256.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
            let nft_id: NftId = nft_bytes.clone().try_into().unwrap();
            assert_ok!(TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                nft_id.clone(),
                60
            ));
            // Insert a vote directly
            crate::ProposedPublicKeys::<Test>::insert(nft_id.clone(), 1u32, BoundedVec::truncate_from(vec![33u8;33]));
            assert!(crate::ProposedPublicKeys::<Test>::iter_prefix(nft_id.clone()).next().is_some());
            assert_ok!(TestingPallet::finalize_dkg_session_internal(first_session_id, vec![44u8;33]));
            assert_eq!(crate::ProposedPublicKeys::<Test>::iter_prefix(nft_id.clone()).count(), 0, "Votes cleared after finalize");
            // Second session
            let second_session_id = TestingPallet::next_session_id();
            assert_ok!(TestingPallet::create_dkg_session(
                RuntimeOrigin::signed(create_test_account(None)),
                nft_id.clone(),
                60
            ));
            assert_ok!(TestingPallet::finalize_dkg_session_internal(second_session_id, vec![55u8;33]));
            assert_eq!(TestingPallet::get_dkg_session(first_session_id).unwrap().state, SessionState::DKGSuperseded, "First superseded");
        });
    }
}
