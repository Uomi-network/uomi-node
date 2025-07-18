use frame_support::assert_ok;
use frame_support::traits::{ Currency, Hooks };
use sp_core::offchain::testing::{ TestOffchainExt, TestTransactionPoolExt };
use sp_core::offchain::{ OffchainDbExt, OffchainWorkerExt, TransactionPoolExt };
use sp_keystore::testing::MemoryKeystore;
use sp_keystore::{ Keystore, KeystoreExt };
use crate::mock::*;

use crate::{
    NodesPins,
    Event,
    AgentsPins,
    CidsStatus,
    InherentDidUpdate,
    Error,
    MinExpireDuration,
    CRYPTO_KEY_TYPE,
};
use std::{ io::Write, sync::{ Arc, Mutex } };
use frame_support::assert_noop;
use crate::types::MaxCidSize;
use env_logger::Builder;
use log::LevelFilter;
use crate::mock::*;
use sp_core::U256;
use sp_runtime::BoundedVec;

// Helper function to create a test CID
fn create_test_cid() -> BoundedVec<u8, MaxCidSize> {
    BoundedVec::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound")
}

// Helper function to create test account
fn create_test_account() -> AccountId {
    let seed = [0u8; 32];
    AccountId::from_raw(seed)
}

// Helper function to create test validators
fn create_test_validators(num_validators: u32, stake: u128) -> Vec<AccountId> {
    let mut validators = Vec::new();

    for i in 0..num_validators {
        let seed = [i as u8; 32];
        let account_id = AccountId::from_raw(seed);

        // Provide funds to the account
        let _ = <Balances as Currency<AccountId>>::make_free_balance_be(&account_id, stake);

        // Bond the validator
        assert_ok!(
            Staking::bond(
                RuntimeOrigin::signed(account_id.clone()),
                stake,
                pallet_staking::RewardDestination::Staked
            )
        );

        // Set validator preferences
        assert_ok!(
            Staking::validate(
                RuntimeOrigin::signed(account_id.clone()),
                pallet_staking::ValidatorPrefs {
                    commission: sp_runtime::Perbill::from_percent(0),
                    blocked: false,
                }
            )
        );

        validators.push(account_id);
    }

    validators
}

#[test]
fn test_pin_agent_works() {
    make_logger();

    new_test_ext().execute_with(|| {
        System::set_block_number(1);

        let account = create_test_account();
        let cid = create_test_cid();
        let nft_id = U256::from(1);
        let threshold = 90;

        assert_ok!(TestingPallet::pin_agent(RuntimeOrigin::signed(account), cid.clone(), nft_id, threshold));

        // Check storage updates
        assert_eq!(AgentsPins::<Test>::get(nft_id), cid);
        assert_eq!(CidsStatus::<Test>::get(&cid), (U256::zero(), U256::zero()));

        // Check event emission
        System::assert_has_event(
            (Event::IpfsOperationSuccess {
                operation: crate::IpfsOperation::Pin,
                cid: cid.to_vec(),
            }).into()
        );
    });
}

#[test]
fn test_pin_file_works() {
    make_logger();

    new_test_ext().execute_with(|| {
        System::set_block_number(1);

        let account = create_test_account();
        let cid = create_test_cid();
        let duration: u64 = 30000; // More than MinExpireDuration (28800)

        assert_ok!(TestingPallet::pin_file(RuntimeOrigin::signed(account), cid.clone(), duration));

        let current_block = System::block_number();
        let expected_expiry = current_block + duration;

        // Check storage was updated correctly
        let (stored_expiry, usable_from) = CidsStatus::<Test>::get(&cid);
        assert_eq!(stored_expiry, U256::from(expected_expiry));
        assert_eq!(usable_from, U256::zero());

        // Check event emission
        System::assert_has_event(
            (Event::TemporaryPinCreated {
                cid: cid.to_vec(),
                expires_at: expected_expiry,
            }).into()
        );
    });
}

#[test]
fn test_pin_file_fails_with_short_duration() {
    make_logger();

    new_test_ext().execute_with(|| {
        let account = create_test_account();
        let cid = create_test_cid();
        let short_duration: u64 = 1000; // Less than MinExpireDuration

        assert_noop!(
            TestingPallet::pin_file(RuntimeOrigin::signed(account), cid.clone(), short_duration),
            "Duration must be more than 28800 blocks"
        );
    });
}

#[test]
fn test_offchain_worker_functionality() {
    make_logger();

    let mut ext = new_test_ext();
    let (offchain, _state) = TestOffchainExt::new();
    let (pool, pool_state) = TestTransactionPoolExt::new();

    ext.register_extension(OffchainDbExt::new(offchain.clone()));
    ext.register_extension(OffchainWorkerExt::new(offchain));
    ext.register_extension(TransactionPoolExt::new(pool));

    // Create and register keystore
    let keystore = Arc::new(MemoryKeystore::new());
    let public_key = keystore.sr25519_generate_new(CRYPTO_KEY_TYPE, None).unwrap();
    ext.register_extension(KeystoreExt(keystore));

    ext.execute_with(|| {
        System::set_block_number(1);

        // Convert public key to account id and set up as validator
        let account_id = AccountId::from_raw(public_key.0);
        let stake = 1000;

        // Provide funds to the account
        let _ = <Balances as Currency<AccountId>>::make_free_balance_be(&account_id, stake);

        // Bond the validator
        assert_ok!(
            Staking::bond(
                RuntimeOrigin::signed(account_id.clone()),
                stake,
                pallet_staking::RewardDestination::Staked
            )
        );

        // Set validator preferences
        assert_ok!(
            Staking::validate(
                RuntimeOrigin::signed(account_id.clone()),
                pallet_staking::ValidatorPrefs {
                    commission: sp_runtime::Perbill::from_percent(0),
                    blocked: false,
                }
            )
        );

        let cid = create_test_cid();

        // Set up test data
        AgentsPins::<Test>::insert(U256::zero(), cid.clone());
        CidsStatus::<Test>::insert(cid.clone(), (U256::zero(), U256::zero()));

        // Run the offchain worker
        TestingPallet::offchain_worker(1);

        // Verify transaction was created
        let tx_pool = pool_state.read();
        assert!(!tx_pool.transactions.is_empty(), "Transaction pool should not be empty");
    });
}

#[test]
fn test_majority_pinning() {
    make_logger();

    new_test_ext().execute_with(|| {
        let cid = create_test_cid();

        // Create test validators
        let validators = create_test_validators(5, 1000);

        // Initially shouldn't be majority pinned
        assert!(!TestingPallet::is_majority_pinned(&cid));

        // Pin for 3 validators (majority)
        for i in 0..3 {
            NodesPins::<Test>::insert(&cid, &validators[i], true);
        }

        // Now should be majority pinned
        assert!(TestingPallet::is_majority_pinned(&cid));

        // Remove one pin to go below majority
        NodesPins::<Test>::remove(&cid, &validators[0]);

        // Should no longer be majority pinned
        assert!(!TestingPallet::is_majority_pinned(&cid));
    });
}

#[test]
fn test_pin_agent_update() {
    make_logger();

    new_test_ext().execute_with(|| {
        System::set_block_number(1);

        let account = create_test_account();
        let cid1 = create_test_cid();
        let cid2 = BoundedVec::try_from(vec![1, 2, 4]).expect("Vector exceeds the bound");

        let nft_id = U256::from(1);
        let threshold = 90;

        // Pin first CID
        assert_ok!(
            TestingPallet::pin_agent(RuntimeOrigin::signed(account.clone()), cid1.clone(), nft_id, threshold)
        );

        // Update with second CID
        assert_ok!(TestingPallet::pin_agent(RuntimeOrigin::signed(account), cid2.clone(), nft_id, threshold));

        // Check storage updates
        assert_eq!(AgentsPins::<Test>::get(nft_id), cid2);

        // Check that old CID has expiration set
        let (expires_at, _) = CidsStatus::<Test>::get(&cid1);
        assert!(expires_at > U256::zero());

        // Check that new CID is set as persistent
        let (expires_at, usable_from) = CidsStatus::<Test>::get(&cid2);
        assert_eq!(expires_at, U256::zero());
        assert_eq!(usable_from, U256::zero());
    });
}

#[test]
fn test_pin_expiration() {
    make_logger();

    let mut ext = new_test_ext();
    let (offchain, _state) = TestOffchainExt::new();
    let (pool, _pool_state) = TestTransactionPoolExt::new();

    ext.register_extension(OffchainDbExt::new(offchain.clone()));
    ext.register_extension(OffchainWorkerExt::new(offchain));
    ext.register_extension(TransactionPoolExt::new(pool));

    // Create and register keystore
    let keystore = Arc::new(MemoryKeystore::new());
    let public_key = keystore.sr25519_generate_new(CRYPTO_KEY_TYPE, None).unwrap();
    ext.register_extension(KeystoreExt(keystore));

    ext.execute_with(|| {
        System::set_block_number(1);

        // Convert public key to account id and set up as validator
        let account_id = AccountId::from_raw(public_key.0);
        let stake = 1000;

        // Provide funds to the account
        let _ = <Balances as Currency<AccountId>>::make_free_balance_be(&account_id, stake);

        // Bond the validator
        assert_ok!(
            Staking::bond(
                RuntimeOrigin::signed(account_id.clone()),
                stake,
                pallet_staking::RewardDestination::Staked
            )
        );

        // Set validator preferences
        assert_ok!(
            Staking::validate(
                RuntimeOrigin::signed(account_id.clone()),
                pallet_staking::ValidatorPrefs {
                    commission: sp_runtime::Perbill::from_percent(0),
                    blocked: false,
                }
            )
        );

        let cid = create_test_cid();
        let duration: u64 = 30000;

        // Pin file with expiration
        assert_ok!(
            TestingPallet::pin_file(
                RuntimeOrigin::signed(account_id.clone()),
                cid.clone(),
                duration
            )
        );

        // Fast forward to after expiration
        System::set_block_number(31000);

        // Run offchain worker which should process expired pins
        TestingPallet::offchain_worker(31000);

        // Check CID status after expiration
        let (expires_at, _) = CidsStatus::<Test>::get(&cid);
        let current_block_u256 = U256::from(System::block_number());
        assert!(current_block_u256 > expires_at);
    });
}

// HELPERS
//////////////////////////////////////////////////////////////////////////////////

// This function initializes the logger for the tests.
// It makes possible to see the logs from the tested pallet directly in the console.
// USAGE: Run tests with `cargo test -- --show-output`
// This function also returns a counter that can be used to check how many logs were generated.
// Example: `let counter = make_logger();`
//          `assert_eq!(*counter.lock().unwrap(), 1);`
fn make_logger() -> Arc<Mutex<u16>> {
    let log_counter = Arc::new(Mutex::new(0_u16));
    let log_counter_ref = Arc::clone(&log_counter);

    Builder::new()
        .filter_level(LevelFilter::Info)
        .format(move |buf, record| {
            {
                let mut counter = log_counter_ref.lock().unwrap();
                *counter += 1;
            }
            writeln!(buf, "{} - {}", record.level(), record.args())
        })
        .is_test(true)
        .try_init()
        .ok();

    log_counter
}

#[test]
fn test_inherent_data_processing() {
    make_logger();

    new_test_ext().execute_with(|| {
        System::set_block_number(1);

        let cid = create_test_cid();
        let expires_at = U256::from(100);
        let usable_from = U256::from(1);

        // Create test data
        let usable = vec![(cid.clone(), (expires_at, usable_from))];
        let to_remove = Vec::new();

        // Test setting inherent data
        assert_ok!(
            TestingPallet::set_inherent_data(RuntimeOrigin::none(), (
                usable.clone(),
                to_remove.clone(),
            ))
        );

        // Verify InherentDidUpdate storage is set
        assert!(InherentDidUpdate::<Test>::get());

        // Check CidsStatus was updated correctly
        let (_stored_expires_at, stored_usable_from) = CidsStatus::<Test>::get(&cid);
        assert_eq!(stored_usable_from, U256::from(1));
    });
}

#[test]
fn test_inherent_data_removal() {
    make_logger();

    new_test_ext().execute_with(|| {
        System::set_block_number(1);

        let cid = create_test_cid();
        let expires_at = U256::from(100);
        let usable_from = U256::from(1);

        // First add the CID to storage
        CidsStatus::<Test>::insert(&cid, (expires_at, usable_from));
        NodesPins::<Test>::insert(&cid, &create_test_account(), true);

        // Create removal data
        let usable = Vec::new();
        let to_remove = vec![(cid.clone(), (expires_at, usable_from))];

        // Test setting inherent data for removal
        assert_ok!(TestingPallet::set_inherent_data(RuntimeOrigin::none(), (usable, to_remove)));

        // Verify CID was removed from storage
        assert!(!CidsStatus::<Test>::contains_key(&cid));
        assert!(NodesPins::<Test>::iter_prefix(&cid).count() == 0);
    });
}

#[test]
fn test_extreme_validator_scenarios() {
    make_logger();

    new_test_ext().execute_with(|| {
        // Test with a reasonable number of validators for the test environment
        let validator_count = 10;
        let validators = create_test_validators(validator_count, 1000);
        let cid = create_test_cid();

        // Verify validator setup
        for validator in validators.iter() {
            assert!(pallet_staking::Validators::<Test>::contains_key(validator));
        }

        // Test with no validators pinning
        assert!(!TestingPallet::is_majority_pinned(&cid));

        // Test with exactly 50% of validators
        let half_validators = (validator_count / 2) as usize;
        for i in 0..half_validators {
            NodesPins::<Test>::insert(&cid, &validators[i], true);
        }
        assert!(!TestingPallet::is_majority_pinned(&cid));

        // Test with 50% + 1 validators
        NodesPins::<Test>::insert(&cid, &validators[half_validators], true);
        assert!(TestingPallet::is_majority_pinned(&cid));

        // Test removal of pins
        NodesPins::<Test>::remove(&cid, &validators[0]);
        assert!(!TestingPallet::is_majority_pinned(&cid));

        // Test with all validators
        for validator in validators.iter() {
            NodesPins::<Test>::insert(&cid, validator, true);
        }
        assert!(TestingPallet::is_majority_pinned(&cid));
    });
}

#[test]
fn test_concurrent_pin_operations() {
    make_logger();

    new_test_ext().execute_with(|| {
        let account = create_test_account();
        let initial_cid = create_test_cid();
        let nft_id = U256::from(1);
        let threshold = 90;

        // Add debug logging for initial state
        log::info!("Initial block number: {:?}", System::block_number());
        log::info!("MinExpireDuration: {:?}", MinExpireDuration::get());

        // First pin should succeed
        assert_ok!(
            TestingPallet::pin_agent(
                RuntimeOrigin::signed(account.clone()),
                initial_cid.clone(),
                nft_id,
                threshold
            )
        );

        // Verify initial state
        assert_eq!(AgentsPins::<Test>::get(nft_id), initial_cid);
        assert_eq!(CidsStatus::<Test>::get(&initial_cid), (U256::zero(), U256::zero()));

        // Attempt to pin the same CID again should fail
        assert_noop!(
            TestingPallet::pin_agent(
                RuntimeOrigin::signed(account.clone()),
                initial_cid.clone(),
                nft_id,
                threshold
            ),
            Error::<Test>::SomethingWentWrong
        );

        // Test updating with different CIDs
        for i in 1..5 {
            log::info!("Iteration {}", i);
            log::info!("Current block number: {:?}", System::block_number());

            let mut cid_data = vec![18, 32];
            cid_data.extend_from_slice(&[i as u8; 45]);
            let new_cid = BoundedVec::try_from(cid_data).expect("Vector exceeds bound");

            // Get the previous CID before updating
            let previous_cid = AgentsPins::<Test>::get(nft_id);
            log::info!(
                "Previous CID status before update: {:?}",
                CidsStatus::<Test>::get(&previous_cid)
            );

            assert_ok!(
                TestingPallet::pin_agent(
                    RuntimeOrigin::signed(account.clone()),
                    new_cid.clone(),
                    nft_id,
                    threshold
                )
            );

            // Forward block and verify immediately after
            System::set_block_number(System::block_number() + 1);
            log::info!("Block number after increment: {:?}", System::block_number());

            // Check previous CID status right after update
            let previous_status = CidsStatus::<Test>::get(&previous_cid);
            log::info!("Previous CID status after update: {:?}", previous_status);

            let (expires_at, _) = previous_status;
            assert!(
                expires_at > U256::zero(),
                "Previous CID should have expiration set. Current value: {}",
                expires_at
            );

            // Verify the new CID is set correctly
            assert_eq!(AgentsPins::<Test>::get(nft_id), new_cid);
            assert_eq!(CidsStatus::<Test>::get(&new_cid), (U256::zero(), U256::zero()));
        }
    });
}

#[test]
fn test_pin_lifecycle_with_inherents() {
    make_logger();

    let mut ext = new_test_ext();
    let (offchain, _state) = TestOffchainExt::new();
    let (pool, _pool_state) = TestTransactionPoolExt::new();

    ext.register_extension(OffchainDbExt::new(offchain.clone()));
    ext.register_extension(OffchainWorkerExt::new(offchain));
    ext.register_extension(TransactionPoolExt::new(pool));

    ext.execute_with(|| {
        System::set_block_number(1);

        let cid = create_test_cid();
        let account = create_test_account();
        let duration: u64 = 30000;

        // Step 1: Pin file
        assert_ok!(
            TestingPallet::pin_file(RuntimeOrigin::signed(account.clone()), cid.clone(), duration)
        );

        // Step 2: Create validators and simulate pinning
        let validators = create_test_validators(5, 1000);
        for validator in validators.iter().take(3) {
            NodesPins::<Test>::insert(&cid, validator, true);
        }

        // Step 3: Process inherent data to mark as usable
        let usable = vec![(cid.clone(), (U256::from(duration), U256::from(1)))];
        assert_ok!(TestingPallet::set_inherent_data(RuntimeOrigin::none(), (usable, Vec::new())));
        InherentDidUpdate::<Test>::take();

        // Step 4: Fast forward to expiration
        System::set_block_number(duration + 1);

        // Step 5: Process removal via inherent
        let to_remove = vec![(cid.clone(), (U256::from(duration), U256::from(1)))];
        assert_ok!(
            TestingPallet::set_inherent_data(RuntimeOrigin::none(), (Vec::new(), to_remove))
        );
        InherentDidUpdate::<Test>::take();

        // Verify final state
        assert!(!CidsStatus::<Test>::contains_key(&cid));
        assert!(NodesPins::<Test>::iter_prefix(&cid).count() == 0);
    });
}

#[test]
fn test_multiple_file_management() {
    make_logger();

    new_test_ext().execute_with(|| {
        let account = create_test_account();
        let mut cids = Vec::new();

        // Create and pin multiple files
        for i in 0..10 {
            let mut cid_data = vec![18, 32];
            cid_data.extend_from_slice(&[i as u8; 45]);
            let cid = BoundedVec::try_from(cid_data).expect("Vector exceeds bound");
            cids.push(cid.clone());

            assert_ok!(TestingPallet::pin_file(RuntimeOrigin::signed(account.clone()), cid, 30000));
        }

        // Verify all files are stored correctly
        for cid in cids {
            let (expires_at, _) = CidsStatus::<Test>::get(&cid);
            assert!(expires_at > U256::zero());
        }
    });
}

#[test]
fn test_edge_case_pin_scenarios() {
    make_logger();

    new_test_ext().execute_with(|| {
        let account = create_test_account();
        let cid = create_test_cid();

        // Test with maximum duration
        let max_duration: u64 = u64::MAX;
        assert_ok!(
            TestingPallet::pin_file(
                RuntimeOrigin::signed(account.clone()),
                cid.clone(),
                max_duration
            )
        );

        // Test rapid pin/unpin cycles
        let nft_id = U256::from(1);
        for i in 0..100 {
            let mut cid_data = vec![18, 32];
            cid_data.extend_from_slice(&[i as u8; 45]);
            let threshold = 90;
            let new_cid = BoundedVec::try_from(cid_data).expect("Vector exceeds bound");

            assert_ok!(
                TestingPallet::pin_agent(RuntimeOrigin::signed(account.clone()), new_cid, nft_id, threshold)
            );
        }
    });
}
// NOTE: Commented because it's not used for now
// fn get_test_account() -> AccountId {
//   let seed = [0u8; 32];
//   AccountId::from_raw(seed)
// }
