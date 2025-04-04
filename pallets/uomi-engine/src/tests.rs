use pallet_ipfs::types::Cid;
use pallet_ipfs::CidsStatus;
use crate::{
    mock::*, Chilling, Event, InherentDidUpdate, Inputs, MaxDataSize, NodesErrors, NodesOutputs, NodesTimeouts, NodesWorks, OpocAssignment, OpocBlacklist, OpocLevel, Outputs
};
use crate::types::{Address, NftId, RequestId};
use sp_std::vec;
use env_logger::Builder;
use frame_support::{
    assert_ok,
    inherent::ProvideInherent,
    pallet_prelude::InherentData,
    traits::{Currency, OffchainWorker},
    BoundedVec,
};
use log::LevelFilter;
use sp_core::{
    sr25519::Public,
    H160, U256,
};
use sp_keystore::{
    testing::MemoryKeystore,
    Keystore, KeystoreExt,
};
use sp_runtime::{
    offchain::{testing::TestOffchainExt, OffchainDbExt, OffchainWorkerExt},
    traits::Dispatchable,
    Perbill,
};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use sp_core::offchain::testing::TestTransactionPoolExt;
use sp_core::offchain::TransactionPoolExt;
use sp_std::collections::btree_map::BTreeMap;
use serial_test::serial;

type AccountId = Public;

// This is a sample test just to show how to write tests in Rust.
#[test]
fn test_sample() {
    fn ok() -> Result<(), &'static str> {
        Ok(())
    }

    assert_ok!(ok());
}

// RUN REQUEST
//////////////////////////////////////////////////////////////////////////////////

// This test should force the execution of the run_request function with a success result.
#[test]
fn test_run_request_success() {
    make_logger();

    new_test_ext().execute_with(|| {
        System::set_block_number(1); // NOTE: This is not necessary but is an example of how to set the block number in tests.

        let request_id: RequestId = 1.into();
        let address: Address = H160::repeat_byte(0xAA);
        let nft_id: NftId = 1.into();
        let input_data = vec![1, 2, 3];
        let input_file_cid = vec![1, 2, 3];

        let result = TestingPallet::run_request(request_id, address, nft_id.clone(), input_data.clone(), input_file_cid.clone(), U256::from(5), U256::from(25)).unwrap();
        assert_eq!(result, ());

        // Be sure request is stored on the Inputs storage
        let storage_input = Inputs::<Test>::get(request_id);
        let (si_block_number, si_address, si_nft_id, si_nft_required_consensus, si_nft_execution_max_time, si_nft_file_cid, si_input_data, si_input_file_cid) = storage_input;
        assert_eq!(si_block_number, 1.into());
        assert_eq!(si_address, address);
        assert_eq!(si_nft_id, nft_id);
        assert_eq!(si_nft_required_consensus, U256::from(5));
        assert_eq!(si_nft_execution_max_time, U256::from(25));
        assert_eq!(si_nft_file_cid, Cid::new());
        assert_eq!(si_input_data, input_data);
        assert_eq!(si_input_file_cid, input_file_cid);

        // Be sure the RequestAccepted event is emitted
        let events = System::events();
        //get ALL events in an array
        let events = events.iter().collect::<Vec<_>>();

        // Verifica che l'evento desiderato sia presente
        assert!(events.iter().any(|record| {
            matches!(
                record.event,
                RuntimeEvent::TestingPallet(Event::RequestAccepted { 
                    request_id: req_id,
                    address: addr,
                    nft_id: nft,
                }) if req_id == request_id && addr == address && nft == nft_id
            )
        }));
    });
}

#[test]
fn test_run_request_failure_with_zero_address() {
  make_logger();

  new_test_ext().execute_with(|| {
    let request_id: RequestId = 1.into();
    let address: Address = H160::repeat_byte(0x00);
    let nft_id: NftId = 1.into();
    let input_data = vec![1, 2, 3];
    let input_file_cid = vec![1, 2, 3];

    let result = TestingPallet::run_request(request_id, address, nft_id, input_data, input_file_cid, U256::from(5), U256::from(25));
    assert!(result.is_err());

    let error = result.err().unwrap();
    assert_eq!(error, sp_runtime::DispatchError::Other("Address must not be zero."));
  });
}

// This test should force the execution of the run_request function with a failure result because the request_id is zero.
#[test]
fn test_run_request_failure_with_zero_request_id() {
  make_logger();

  new_test_ext().execute_with(|| {
    let request_id: RequestId = 0.into();
    let address: Address = H160::repeat_byte(0xAA);
    let nft_id: NftId = 1.into();
    let input_data = vec![1, 2, 3];
    let input_file_cid = vec![1, 2, 3];

    let result = TestingPallet::run_request(request_id, address, nft_id, input_data, input_file_cid, U256::from(5), U256::from(25));
    assert!(result.is_err());

    let error = result.err().unwrap();
    assert_eq!(error, sp_runtime::DispatchError::Other("Request ID must be greater than 0."));
  });
}

// This test should force the execution of the run_request function with a failure result because the nft_id is zero.
#[test]
fn test_run_request_failure_with_zero_nft_id() {
  make_logger();

  new_test_ext().execute_with(|| {
    let request_id: RequestId = 1.into();
    let address: Address = H160::repeat_byte(0xAA);
    let nft_id: NftId = 0.into();
    let input_data = vec![1, 2, 3];
    let input_file_cid = vec![1, 2, 3];

    let result = TestingPallet::run_request(request_id, address, nft_id, input_data, input_file_cid, U256::from(5), U256::from(25));
    assert!(result.is_err());

    let error = result.err().unwrap();
    assert_eq!(error, sp_runtime::DispatchError::Other("NFT ID must be greater than 0."));
  });
}

// This test should force the execution of the run_request function with a failure result because the request_id already exists.
#[test]
fn test_run_request_failure_with_existing_request_id() {
    make_logger();

    new_test_ext().execute_with(|| {
        let request_id: RequestId = 1.into();
        
        // Crea un indirizzo che può essere convertito in un Public valido
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&[1u8; 20]);
        let address = Address::from_slice(&bytes);
        
        let nft_id: NftId = 1.into();
        let input_data = vec![1, 2, 3];
        
        // Crea un CID valido
        let mut cid_data = vec![18, 32];
        cid_data.extend_from_slice(&[1; 45]);
        let input_file_cid = cid_data;

        assert_ok!(TestingPallet::run_request(
            request_id, 
            address, 
            nft_id, 
            input_data.clone(), 
            input_file_cid.clone(),
            U256::from(5), U256::from(25)
        ));

        let result = TestingPallet::run_request(
            request_id, 
            address, 
            nft_id, 
            input_data, 
            input_file_cid,
            U256::from(5), U256::from(25)
        );
        
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            sp_runtime::DispatchError::Other("Request ID already exists.")
        );
    });
}

// This test should force the execution of the run_request function with a failure result because the input_data is too large.
#[test]
fn test_run_request_failure_with_large_input_data() {
    make_logger();

    new_test_ext().execute_with(|| {
        let request_id: RequestId = 1.into();
        let address: Address = H160::repeat_byte(0xAA);
        let nft_id: NftId = 1.into();
        let input_data = vec![0; (1024 * 1024) + 1];
        let input_file_cid = vec![1, 2, 3];

        let result = TestingPallet::run_request(request_id, address, nft_id, input_data, input_file_cid, U256::from(5), U256::from(25));
        assert!(result.is_err());

        let error = result.err().unwrap();
        assert_eq!(error, sp_runtime::DispatchError::Other("Input data too large."));
    });
}

// // This test should force the execution of the run_request function with the unsecured parameter set to true.
// #[test]
// fn test_run_request_with_unsecured_parameter() {
//     make_logger();

//     new_test_ext().execute_with(|| {
//         System::set_block_number(1); // NOTE: This is not necessary but is an example of how to set the block number in tests.

//         let stake = 10_000_000_000_000_000_000;
//         let num_validators = 1;
//         let validators = create_validators(num_validators, stake);
//         let validator = validators[0].clone();

//         let request_id: U256 = 1.into();
//         let address: H160 = H160::repeat_byte(0xAA);
//         let nft_id: U256 = 1.into();
//         let input_data = vec![1, 2, 3];
//         let input_file_cid = vec![1, 2, 3];

//         let result = TestingPallet::run_request(request_id, address, nft_id.clone(), input_data.clone(), input_file_cid.clone(), U256::from(1), U256::from(25)).unwrap();
//         assert_eq!(result, ());

//         // Be sure request is stored on the Inputs storage
//         let storage_input = Inputs::<Test>::get(request_id);
//         let (si_block_number, si_nft_id, si_nft_required_consensus, _si_nft_execution_max_time, si_nft_file_cid, si_input_data, si_input_file_cid) = storage_input;
//         assert_eq!(si_block_number, 1.into());
//         assert_eq!(si_nft_id, nft_id);
//         assert_eq!(si_nft_required_consensus, U256::from(1));
//         assert_eq!(si_nft_file_cid, BoundedVec::<u8, MaxDataSize>::new());
//         assert_eq!(si_input_data, input_data);
//         assert_eq!(si_input_file_cid, input_file_cid);

//         // Be sure exists a OpocAssignment for the request_id and the validator
//         let opoc_assignment = OpocAssignment::<Test>::get(request_id, validator.clone());
//         assert_ne!(opoc_assignment, U256::zero());
//         // Be sure the OpocAssignment expiration block number is set to the current block number + the input lifetime
//         assert_eq!(opoc_assignment, U256::from(1 + 25));
//         // Be sure the NodesWorks storage contains a record assigned to the validator with the value 1
//         let nodes_works_number = NodesWorks::<Test>::get(validator.clone(), request_id);
//         assert_eq!(nodes_works_number, true);
//     });
// }

// OFFCHAIN WORKER
//////////////////////////////////////////////////////////////////////////////////

// This test should force the execution of the offchain_worker function for the uomi_whitepaper_chat_agent.wasm with an invalid input.
// It should check the semaphore is released correctly.
#[test]
#[serial]
fn test_offchain_worker_uomi_whitepaper_chat_agent_fail() {
    make_logger();

    let mut ext = new_test_ext();
    
    // Set up the offchain worker test environment
    let (offchain, _state) = TestOffchainExt::new();
    let (pool, state) = TestTransactionPoolExt::new();
    ext.register_extension(OffchainDbExt::new(offchain.clone()));
    ext.register_extension(OffchainWorkerExt::new(offchain));
    ext.register_extension(TransactionPoolExt::new(pool));

    // Create and register the keystore
    let keystore = Arc::new(MemoryKeystore::new());
    keystore.sr25519_generate_new(crate::crypto::CRYPTO_KEY_TYPE, None).unwrap();
    ext.register_extension(KeystoreExt(keystore.clone()));
    let validator = keystore.sr25519_public_keys(crate::crypto::CRYPTO_KEY_TYPE).swap_remove(0);

    let empty_cid = Cid::default();
    let not_empty_bounded_vec = BoundedVec::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");

    ext.execute_with(|| {
        // Set current block
        System::set_block_number(12);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id: RequestId = U256::from(1);
        Inputs::<Test>::insert(request_id, (
            U256::zero(), // block_number
            H160::repeat_byte(0xAA), // address
            U256::from(1312), // nft_id
            U256::from(5), // nft_required_consensus
            U256::from(25), // nft_execution_max_time
            empty_cid.clone(), // nft_file_cid
            not_empty_bounded_vec.clone(), // input_data
            empty_cid.clone(), // input_file_cid
        ));

        // Insert an assignment for the first validator
        OpocAssignment::<Test>::insert(request_id, validator.clone(), (U256::from(current_block_number + 1), OpocLevel::Level0)); // NOTE: We set the expiration block number to the previous block so we simulate that the assignment is expired but the output is available
        NodesWorks::<Test>::insert(validator.clone(), request_id, true);

        // Read semaphore status and be sure is false
        let semaphore = TestingPallet::semaphore_status();
        assert_eq!(semaphore, false);

        // Run the offchain worker
        TestingPallet::offchain_worker(current_block_number);

        // Read semaphore status and be sure is false
        let semaphore = TestingPallet::semaphore_status();
        assert_eq!(semaphore, false);

        // Verify transactions in the pool
        let state_read = state.read();
        assert_eq!(state_read.transactions.len(), 2); // 1 to store the execution and 1 to store the node version
    });
}

// This test should force the execution of the offchain_worker function.
#[test]
#[serial]
fn test_offchain_worker_ok() {
    make_logger();

    let mut ext = new_test_ext();
    
    // Set up the offchain worker test environment
    let (offchain, _state) = TestOffchainExt::new();
    let (pool, state) = TestTransactionPoolExt::new();
    ext.register_extension(OffchainDbExt::new(offchain.clone()));
    ext.register_extension(OffchainWorkerExt::new(offchain));
    ext.register_extension(TransactionPoolExt::new(pool));

    // Create and register the keystore
    let keystore = Arc::new(MemoryKeystore::new());
    keystore.sr25519_generate_new(crate::crypto::CRYPTO_KEY_TYPE, None).unwrap();
    ext.register_extension(KeystoreExt(keystore.clone()));
    let validator = keystore.sr25519_public_keys(crate::crypto::CRYPTO_KEY_TYPE).swap_remove(0);

    let empty_cid = Cid::default();
    let not_empty_bounded_vec = BoundedVec::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");

    ext.execute_with(|| {
        // Set current block
        System::set_block_number(12);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id: RequestId = U256::from(1);
        Inputs::<Test>::insert(request_id, (
            U256::zero(), // block_number
            H160::repeat_byte(0xAA), // address
            U256::zero(), // nft_id
            U256::from(5), // nft_required_consensus
            U256::from(25), // nft_execution_max_time
            empty_cid.clone(), // nft_file_cid
            not_empty_bounded_vec.clone(), // input_data
            empty_cid.clone(), // input_file_cid
        ));

        // Insert an assignment for the first validator
        OpocAssignment::<Test>::insert(request_id, validator.clone(), (U256::from(current_block_number + 1), OpocLevel::Level0)); // NOTE: We set the expiration block number to the previous block so we simulate that the assignment is expired but the output is available
        NodesWorks::<Test>::insert(validator.clone(), request_id, true);

        // Run the offchain worker
        TestingPallet::offchain_worker(current_block_number);

        // Verify transactions in the pool
        let state_read = state.read();
        assert_eq!(state_read.transactions.len(), 2); // 1 to store the execution and 1 to store the node version
    });
}

#[test]
#[serial]
fn test_offchain_worker_infinite() {
    make_logger();

    let mut ext = new_test_ext();
    
    // Set up the offchain worker test environment
    let (offchain, _state) = TestOffchainExt::new();
    let (pool, state) = TestTransactionPoolExt::new();
    ext.register_extension(OffchainDbExt::new(offchain.clone()));
    ext.register_extension(OffchainWorkerExt::new(offchain));
    ext.register_extension(TransactionPoolExt::new(pool));

    // Create and register the keystore
    let keystore = Arc::new(MemoryKeystore::new());
    keystore.sr25519_generate_new(crate::crypto::CRYPTO_KEY_TYPE, None).unwrap();
    ext.register_extension(KeystoreExt(keystore.clone()));
    let validator = keystore.sr25519_public_keys(crate::crypto::CRYPTO_KEY_TYPE).swap_remove(0);

    let empty_cid = Cid::default();
    let not_empty_bounded_vec = BoundedVec::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");

    ext.execute_with(|| {
        // Set current block
        System::set_block_number(12);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id = U256::from(1);
        Inputs::<Test>::insert(request_id, (
            U256::zero(), // block_number
            H160::repeat_byte(0xAA), // address
            U256::from(1), // nft_id
            U256::from(5), // nft_required_consensus
            U256::from(25), // nft_execution_max_time
            empty_cid.clone(), // nft_file_cid
            not_empty_bounded_vec.clone(), // input_data
            empty_cid.clone(), // input_file_cid
        ));

        // Insert an assignment for the first validator
        OpocAssignment::<Test>::insert(request_id, validator.clone(), (U256::from(current_block_number + 1), OpocLevel::Level0)); // NOTE: We set the expiration block number to the previous block so we simulate that the assignment is expired but the output is available
        NodesWorks::<Test>::insert(validator.clone(), request_id, true);

        // Run the offchain worker
        TestingPallet::offchain_worker(current_block_number);

        // Verify transactions in the pool
        let state_read = state.read();
        assert_eq!(state_read.transactions.len(), 2); // 1 to store the execution and 1 to store the node version
    });
}

#[test]
#[serial]
fn test_offchain_worker_not_existing() {
    make_logger();

    let mut ext = new_test_ext();
    
    // Set up the offchain worker test environment
    let (offchain, _state) = TestOffchainExt::new();
    let (pool, state) = TestTransactionPoolExt::new();
    ext.register_extension(OffchainDbExt::new(offchain.clone()));
    ext.register_extension(OffchainWorkerExt::new(offchain));
    ext.register_extension(TransactionPoolExt::new(pool));

    // Create and register the keystore
    let keystore = Arc::new(MemoryKeystore::new());
    keystore.sr25519_generate_new(crate::crypto::CRYPTO_KEY_TYPE, None).unwrap();
    ext.register_extension(KeystoreExt(keystore.clone()));
    let validator = keystore.sr25519_public_keys(crate::crypto::CRYPTO_KEY_TYPE).swap_remove(0);

    let empty_cid = Cid::default();
    let not_empty_bounded_vec = BoundedVec::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");

    ext.execute_with(|| {
        // Set current block
        System::set_block_number(12);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id = U256::from(1);
        Inputs::<Test>::insert(request_id, (
            U256::zero(), // block_number
            H160::repeat_byte(0xAA), // address
            U256::from(999), // nft_id
            U256::from(5), // nft_required_consensus
            U256::from(25), // nft_execution_max_time
            empty_cid.clone(), // nft_file_cid
            not_empty_bounded_vec.clone(), // input_data
            empty_cid.clone(), // input_file_cid
        ));

        // Insert an assignment for the first validator
        OpocAssignment::<Test>::insert(request_id, validator.clone(), (U256::from(current_block_number + 1), OpocLevel::Level0)); // NOTE: We set the expiration block number to the previous block so we simulate that the assignment is expired but the output is available
        NodesWorks::<Test>::insert(validator.clone(), request_id, true);

        // Run the offchain worker
        TestingPallet::offchain_worker(current_block_number);

        // Verify transactions in the pool
        let state_read = state.read();
        assert_eq!(state_read.transactions.len(), 2);
    });
}

#[test]
fn test_offchain_run_wasm_function_with_valid_wasm() {
    make_logger();

    let mut ext = new_test_ext();

    ext.execute_with(|| {
        let wasm = include_bytes!("./test_agents/agent0.wasm").to_vec();
        let input_data = BoundedVec::<u8, MaxDataSize>::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");
        let input_file_cid = Cid::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");
        let result = TestingPallet::offchain_run_wasm(wasm.clone(), input_data.clone(), input_file_cid.clone(), H160::repeat_byte(0xAA), U256::from(1), U256::from(99), 
        U256::from(1),
        U256::from(99),
        U256::from(99), OpocLevel::Level0);
        assert!(result.is_ok());

        // Be sure result is input_data reversed
        let input_data_reversed = input_data.iter().rev().cloned().collect::<Vec<u8>>();
        assert_eq!(result.unwrap(), input_data_reversed);
    });
}

#[test]
fn test_offchain_run_wasm_function_with_infinite_wasm() {
    make_logger();

    let mut ext = new_test_ext();

    ext.execute_with(|| {
        let wasm = include_bytes!("./test_agents/agent1.wasm").to_vec();
        let input_data = BoundedVec::<u8, MaxDataSize>::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");
        let input_file_cid = Cid::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");

        let result = TestingPallet::offchain_run_wasm(wasm.clone(), input_data.clone(), input_file_cid.clone(), H160::repeat_byte(0xAA), U256::from(1), U256::from(3), 
        U256::from(1),
        U256::from(3),

        U256::from(3),
        OpocLevel::Level0
    );
        assert!(result.is_err());

        // Be sure error message is "WASM execution error"
        let error = result.err().unwrap();
        assert_eq!(error.to_string(), "WASM execution error");
    });
}

#[test]
fn test_offchain_run_wasm_function_with_call_ai() {
    make_logger();

    let mut ext = new_test_ext();

    ext.execute_with(|| {
        let wasm = include_bytes!("./test_agents/agent2.wasm").to_vec();
        let input_data = BoundedVec::<u8, MaxDataSize>::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");
        let input_file_cid = Cid::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");

        let result = TestingPallet::offchain_run_wasm(wasm.clone(), input_data.clone(), input_file_cid.clone(), H160::repeat_byte(0xAA), U256::from(1), U256::from(99), 
        
        
        U256::from(1),
        U256::from(99),

        U256::from(99), OpocLevel::Level0);
        assert!(result.is_ok());

        // Be sure result is input_data reversed
        let input_data_reversed = input_data.iter().rev().cloned().collect::<Vec<u8>>();
        assert_eq!(result.unwrap(), input_data_reversed);
    });
}

#[test]
fn test_offchain_run_wasm_function_with_get_file_cid() {
    make_logger();

    new_test_ext().execute_with(|| {
        System::set_block_number(2);
        let wasm = include_bytes!("./test_agents/agent3.wasm").to_vec();
        let input_data = BoundedVec::<u8, MaxDataSize>::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");
        let input_file_cid = Cid::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");

        // Insert the input_file_cid on Ipfs Pallet on storage CidsStatus
        CidsStatus::<Test>::insert(input_file_cid.clone(), (
            U256::from(0), // expiration_block_number
            U256::from(1) // usable_from_block_number
        ));

        // Run the offchain_run_wasm function
        let result = TestingPallet::offchain_run_wasm(wasm.clone(), input_data.clone(), input_file_cid.clone(), H160::repeat_byte(0xAA), U256::from(2), U256::from(99), 
        
        
        U256::from(1),
        U256::from(99),

        U256::from(99), OpocLevel::Level0);
        assert!(result.is_ok());
    });
}

#[test]
fn test_offchain_run_wasm_function_with_get_request_sender() {
    make_logger();

    new_test_ext().execute_with(|| {
        System::set_block_number(2);
        let wasm = include_bytes!("./test_agents/agent4.wasm").to_vec();
        let address = H160::repeat_byte(0xAA);
        let input_data = BoundedVec::<u8, MaxDataSize>::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");
        let input_file_cid = Cid::try_from(vec![1, 2, 3]).expect("Vector exceeds the bound");

        // Run the offchain_run_wasm function
        let result = TestingPallet::offchain_run_wasm(wasm.clone(), input_data.clone(), input_file_cid.clone(), address, U256::from(2), U256::from(99),
        
        U256::from(1),
        U256::from(99),
        U256::from(99), OpocLevel::Level0);
        assert!(result.is_ok());

        // Be sure result is the address
        let address_as_vec: BoundedVec::<u8, MaxDataSize> = address.as_ref().to_vec().try_into().unwrap_or_else(|_| BoundedVec::<u8, MaxDataSize>::default());
        assert_eq!(result.unwrap(), address_as_vec);
    });
}

// OPOC
//////////////////////////////////////////////////////////////////////////////////

#[test]
fn test_inherent_opoc_no_assignment() {
    make_logger();
    
    new_test_ext().execute_with(|| {
        let empty_cid = Cid::default();
        let empty_bounded_vec = BoundedVec::<u8, MaxDataSize>::default();

        let stake = 10_000_000_000_000_000_000;
        let num_validators = 1;
        let validators = create_validators(num_validators, stake);
        let validator = validators[0].clone();

        // Set current block
        System::set_block_number(1);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id: U256 = U256::from(1);
        Inputs::<Test>::insert(request_id, (
            U256::zero(),
            H160::repeat_byte(0xAA),
            U256::zero(),
            U256::from(5), // nft_required_consensus
            U256::from(25), // nft_execution_max_time
            empty_cid.clone(),
            empty_bounded_vec.clone(),
            empty_cid.clone(),
        ));

        let inherent_data = InherentData::new();
        let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
        System::set_block_number(0);
        assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
        assert!(TestingPallet::is_inherent(&inherent_call));
        let runtime_call: RuntimeCall = inherent_call.into();
        assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));
        
        // After the execution of the inherent, should exist 1 assignment for the request_id 1 and the validator
        let (opoc_assignment, level) = OpocAssignment::<Test>::get(request_id, validator.clone());
        assert_ne!(opoc_assignment, U256::zero());
        // After the execution of the inherent, the opoc assignment should have the expiration block number set to the current block number + the input lifetime
        assert_eq!(opoc_assignment, U256::from(current_block_number + 25));
        // The level of the opoc should be Level0
        assert_eq!(level, OpocLevel::Level0);
        // After the execution of the inherent, the NodesWorks storage should contain a record assigned to the validator with the value 1
        let nodes_works_number = NodesWorks::<Test>::get(validator.clone(), request_id);
        assert_eq!(nodes_works_number, true);
    });
}

#[test]
fn test_inherent_opoc_no_assignment_without_validators_available() {
    make_logger();
    
    new_test_ext().execute_with(|| {
        let empty_cid = Cid::default();
        let empty_bounded_vec = BoundedVec::<u8, MaxDataSize>::default();

        // Set current block
        System::set_block_number(1);

        // Insert an input on the Inputs storage
        let request_id: U256 = U256::from(1);
        Inputs::<Test>::insert(request_id, (
            U256::zero(),
            H160::repeat_byte(0xAA),
            U256::zero(),
            U256::from(5), // nft_required_consensus
            U256::from(25), // nft_execution_max_time
            empty_cid.clone(),
            empty_bounded_vec.clone(),
            empty_cid.clone(),
        ));

        let inherent_data = InherentData::new();
        let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
        System::set_block_number(0);
        assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
        assert!(TestingPallet::is_inherent(&inherent_call));
        let runtime_call: RuntimeCall = inherent_call.into();
        assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));
        
        // After the execution of the inherent, the OpocAssignment storage should contain 0 assignment for the request_id 1
        let opoc_assignment = OpocAssignment::<Test>::iter_prefix_values(request_id).collect::<Vec<_>>();
        assert_eq!(opoc_assignment.len(), 0);
        // After the execution of the inherent, the NodesWorks storage should contain 0 assignment
        let nodes_works_number = NodesWorks::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(nodes_works_number.len(), 0);
    });
}

#[test]
fn test_inherent_opoc_level_0_no_timeout() {
    make_logger();
    
    new_test_ext().execute_with(|| {
        let empty_bounded_vec = BoundedVec::<u8, MaxDataSize>::default();
        let empty_cid = Cid::default();
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 10;
        let validators = create_validators(num_validators, stake);
            
        // Set current block
        System::set_block_number(1);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id: U256 = U256::from(1);
        Inputs::<Test>::insert(request_id, (
            U256::zero(),
            H160::repeat_byte(0xAA),
            U256::zero(),
            U256::from(5), // nft_required_consensus
            U256::from(25), // nft_execution_max_time
            empty_cid.clone(),
            empty_bounded_vec.clone(),
            empty_cid.clone(),
        ));

        // Insert an assignment for the first validator
        OpocAssignment::<Test>::insert(request_id, validators[0].clone(), (U256::from(current_block_number + 1), OpocLevel::Level0));
        NodesWorks::<Test>::insert(validators[0].clone(), request_id, true);
        
        let inherent_data = InherentData::new();
        let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
        System::set_block_number(0);
        assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
        assert!(TestingPallet::is_inherent(&inherent_call));
        let runtime_call: RuntimeCall = inherent_call.into();
        assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));
        
        // After the execution of the inherent, the OpocAssignment storage should contain 1 assignment for the request_id 1 and the first validator
        let (opoc_assignment, level) = OpocAssignment::<Test>::get(request_id, validators[0].clone());
        assert_eq!(opoc_assignment, U256::from(current_block_number + 1));
        // Check that level is 0
        assert_eq!(level, OpocLevel::Level0);
        // After the execution of the inherent, the NodesWorks storage should contain 1 assignment for the first validator
        let nodes_works_number = NodesWorks::<Test>::get(validators[0].clone(), request_id);
        assert_eq!(nodes_works_number, true);
        // The validator should not be blacklisted
        let opoc_blacklist = OpocBlacklist::<Test>::get(validators[0].clone());
        assert_eq!(opoc_blacklist, false);
        // The validator should not have timeouts
        let nodes_timeouts = NodesTimeouts::<Test>::get(validators[0].clone());
        assert_eq!(nodes_timeouts, 0 as u32);
    });
}

#[test]
fn test_inherent_opoc_level_0_timeout() {
    make_logger();
    
    new_test_ext().execute_with(|| {
        let empty_bounded_vec = BoundedVec::<u8, MaxDataSize>::default();
        let empty_cid = Cid::default();
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 2;
        let validators = create_validators(num_validators, stake);
            
        // Set current block
        System::set_block_number(3);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id: U256 = U256::from(1);
        Inputs::<Test>::insert(request_id, (
            U256::zero(),
            H160::repeat_byte(0xAA),
            U256::zero(),
            U256::from(5), // nft_required_consensus
            U256::from(25), // nft_execution_max_time
            empty_cid.clone(),
            empty_bounded_vec.clone(),
            empty_cid.clone(),
        ));

        // Insert an assignment for the first validator
        OpocAssignment::<Test>::insert(U256::from(1), validators[0].clone(), (U256::from(current_block_number - 1), OpocLevel::Level0));
        NodesWorks::<Test>::insert(validators[0].clone(), request_id, true);
        
        let inherent_data = InherentData::new();
        let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
        System::set_block_number(2);
        assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
        assert!(TestingPallet::is_inherent(&inherent_call));
        let runtime_call: RuntimeCall = inherent_call.into();
        assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));
        
        // After the execution of the inherent, the OpocAssignment storage should contain 1 assignment for the request_id 1
        let opoc_assignment = OpocAssignment::<Test>::iter_prefix_values(request_id).collect::<Vec<_>>();
        assert_eq!(opoc_assignment.len(), 1);
        // After the execution of the inherent, the NodesWorks storage should contain 1 assignment
        let nodes_works_number = NodesWorks::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(nodes_works_number.len(), 1);
        // The validator should be blacklisted
        let opoc_blacklist = OpocBlacklist::<Test>::get(validators[0].clone());
        assert_eq!(opoc_blacklist, true);
        // The validator should have timeouts
        let nodes_timeouts = NodesTimeouts::<Test>::get(validators[0].clone());
        assert_eq!(nodes_timeouts, 1 as u32);
    });
}

#[test]
fn test_inherent_opoc_level_0_completed() {
    make_logger();
    
    new_test_ext().execute_with(|| {
        let empty_bounded_vec = BoundedVec::<u8, MaxDataSize>::default();
        let empty_cid = Cid::default();
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 5;
        let validators = create_validators(num_validators, stake);
            
        // Set current block
        System::set_block_number(3);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id: U256 = U256::from(1);
        let nft_required_consensus = U256::from(5);
        Inputs::<Test>::insert(request_id, (
            U256::zero(),
            H160::repeat_byte(0xAA),
            U256::zero(),
            nft_required_consensus, // nft_required_consensus
            U256::from(25), // nft_execution_max_time
            empty_cid.clone(),
            empty_bounded_vec.clone(),
            empty_cid.clone(),
        ));

        // Insert an assignment for the first validator
        OpocAssignment::<Test>::insert(U256::from(1), validators[0].clone(), (U256::from(current_block_number - 1), OpocLevel::Level0)); // NOTE: We set the expiration block number to the previous block so we simulate that the assignment is expired but the output is available
        NodesWorks::<Test>::insert(validators[0].clone(), request_id, true);

        // Insert the output for the first validator
        NodesOutputs::<Test>::insert(request_id, validators[0].clone(), empty_bounded_vec.clone());
        
        let inherent_data = InherentData::new();
        let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
        System::set_block_number(2);
        assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
        assert!(TestingPallet::is_inherent(&inherent_call));
        let runtime_call: RuntimeCall = inherent_call.into();
        assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));
        
        // After the execution of the inherent, the OpocAssignment storage should contain nft_required_consensus assignment for the request_id 1
        let opoc_assignments = OpocAssignment::<Test>::iter_prefix_values(request_id).collect::<Vec<_>>();
        assert_eq!(opoc_assignments.len() as u32, nft_required_consensus.as_u32());
        // After the execution of the inherent, the NodesWorks storage should contain nft_required_consensus - 1 assignments
        let nodes_works_number = NodesWorks::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(nodes_works_number.len() as u32, nft_required_consensus.as_u32() - 1);
        // All the opoc_assignments except one should have the expiration block number set to the current block number + the input lifetime
        let mut opoc_assignments_with_valid_expirations = 0;
        for (opoc_assignment, _opoc_level) in opoc_assignments {
            if opoc_assignment == U256::from(current_block_number + 25) {
                opoc_assignments_with_valid_expirations += 1;
            }
        }
        assert_eq!(opoc_assignments_with_valid_expirations, nft_required_consensus.as_u32() - 1);
    });
}

#[test]
fn test_inherent_opoc_level_0_completed_unsecure() {
    make_logger();
    
    new_test_ext().execute_with(|| {
        let empty_bounded_vec = BoundedVec::<u8, MaxDataSize>::default();
        let empty_cid = Cid::default();
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 5;
        let validators = create_validators(num_validators, stake);
            
        // Set current block
        System::set_block_number(3);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id: U256 = U256::from(1);
        let nft_required_consensus = U256::from(1); // unsecure means that nft_required_consensus is 1
        Inputs::<Test>::insert(request_id, (
            U256::zero(),
            H160::repeat_byte(0xAA),
            U256::zero(),
            nft_required_consensus, // nft_required_consensus
            U256::from(25), // nft_execution_max_time
            empty_cid.clone(),
            empty_bounded_vec.clone(),
            empty_cid.clone(),
        ));

        // Insert an assignment for the first validator
        OpocAssignment::<Test>::insert(U256::from(1), validators[0].clone(), (U256::from(current_block_number - 1), OpocLevel::Level0)); // NOTE: We set the expiration block number to the previous block so we simulate that the assignment is expired but the output is available
        NodesWorks::<Test>::insert(validators[0].clone(), request_id, true);

        // Insert the output for the first validator
        NodesOutputs::<Test>::insert(request_id, validators[0].clone(), empty_bounded_vec.clone());
        
        let inherent_data = InherentData::new();
        let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
        System::set_block_number(2);
        assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
        assert!(TestingPallet::is_inherent(&inherent_call));
        let runtime_call: RuntimeCall = inherent_call.into();
        assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));

        // storage Outputs should contain the output of the request
        let outputs = Outputs::<Test>::get(request_id);
        assert_eq!(outputs, (empty_bounded_vec.clone(), 1, 1));

        //check that storage_opoc_assignment is empty
        let opoc_assignments = OpocAssignment::<Test>::iter_prefix_values(request_id).collect::<Vec<_>>();
        assert_eq!(opoc_assignments.len() as u32, 0);
        //check that storage_nodes_outputs is empty
        let nodes_outputs = NodesOutputs::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(nodes_outputs.len() as u32, 0);
        //check that storage_nodes_works is empty
        let nodes_works_number = NodesWorks::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(nodes_works_number.len() as u32, 0);
        //check that storage_opoc_blacklist is empty
        let opoc_blacklist = OpocBlacklist::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(opoc_blacklist.len() as u32, 0);
        //check that storage_nodes_timeouts is empty
        let nodes_timeouts = NodesTimeouts::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(nodes_timeouts.len() as u32, 0); 
    });
}

#[test]
fn test_inherent_opoc_level_1_no_timeouts() {
  make_logger();
    
  new_test_ext().execute_with(|| {
      let empty_bounded_vec = BoundedVec::<u8, MaxDataSize>::default();
      let empty_cid = Cid::default();
      let stake = 10_000_000_000_000_000_000;
      let num_validators = 10;
      let validators = create_validators(num_validators, stake);
          
      // Set current block
      System::set_block_number(3);
      let current_block_number = System::block_number();

      // Insert an input on the Inputs storage
      let request_id: U256 = U256::from(1);
      let nft_required_consensus = U256::from(5);
      Inputs::<Test>::insert(request_id, (
          U256::zero(),
          H160::repeat_byte(0xAA),
          U256::zero(),
          nft_required_consensus,
          U256::from(25), // nft_execution_max_time
          empty_cid.clone(),
          empty_bounded_vec.clone(),
          empty_cid.clone(),
      ));

      // Insert an assignment for the first validator
      OpocAssignment::<Test>::insert(U256::from(1), validators[4].clone(), (U256::from(current_block_number - 1), OpocLevel::Level0)); 
      // Insert the output for the first validator
      NodesOutputs::<Test>::insert(request_id, validators[4].clone(), empty_bounded_vec.clone());

      // Insert an assignment for the other 4 validators
      for i in 0..4 {
          OpocAssignment::<Test>::insert(U256::from(1), validators[i].clone(), (U256::from(current_block_number + 1), OpocLevel::Level1));
          NodesWorks::<Test>::insert(validators[i].clone(), request_id, true);
      }
      
      let inherent_data = InherentData::new();
      let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
      System::set_block_number(2);
      assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
      assert!(TestingPallet::is_inherent(&inherent_call));
      let runtime_call: RuntimeCall = inherent_call.into();
      assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));
      
      // After the execution of the inherent, the OpocAssignment storage should contain nft_required_consensus assignment for the request_id 1
      let opoc_assignments = OpocAssignment::<Test>::iter_prefix_values(request_id).collect::<Vec<_>>();
      assert_eq!(opoc_assignments.len() as u32, nft_required_consensus.as_u32());
      // After the execution of the inherent, the NodesWorks storage should contain nft_required_consensus - 1 assignments
      let nodes_works_number = NodesWorks::<Test>::iter().collect::<Vec<_>>();
      assert_eq!(nodes_works_number.len() as u32, nft_required_consensus.as_u32() - 1);
      // All the opoc_assignments except one should have the expiration block number set to the current block number + 1
      let mut opoc_assignments_with_valid_expirations = 0;
      for (opoc_assignment, _opoc_level) in opoc_assignments {
          if opoc_assignment == U256::from(current_block_number + 1) {
              opoc_assignments_with_valid_expirations += 1;
          }
      }
      assert_eq!(opoc_assignments_with_valid_expirations, nft_required_consensus.as_u32() - 1);
  });
}

#[test]
fn test_inherent_opoc_level_1_some_timeouts() { // Case where during the execution of the opoc of level 1, one of the selected validators has a timeout
    make_logger();
        
    new_test_ext().execute_with(|| {
        let empty_bounded_vec = BoundedVec::<u8, MaxDataSize>::default();
        let empty_cid = Cid::default();
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 10;
        let validators = create_validators(num_validators, stake);
            
        // Set current block
        System::set_block_number(3);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id: U256 = U256::from(1);
        let nft_required_consensus = U256::from(5);
        Inputs::<Test>::insert(request_id, (
                U256::zero(),
                H160::repeat_byte(0xAA),
                U256::zero(),
                nft_required_consensus,
                U256::from(25), // nft_execution_max_time
                empty_cid.clone(),
                empty_bounded_vec.clone(),
                empty_cid.clone(),
        ));

        // Insert an assignment for the first validator
        OpocAssignment::<Test>::insert(U256::from(1), validators[4].clone(), (U256::from(current_block_number - 1), OpocLevel::Level0)); 
        // Insert the output for the first validator
        NodesOutputs::<Test>::insert(request_id, validators[4].clone(), empty_bounded_vec.clone());

        // Insert an assignment for the expired validator
        OpocAssignment::<Test>::insert(U256::from(1), validators[3].clone(), (U256::from(current_block_number - 1), OpocLevel::Level1));
        NodesWorks::<Test>::insert(validators[3].clone(), request_id, true);

        // Insert an assignment for the other 3 validators
        for i in 0..3 {
            OpocAssignment::<Test>::insert(U256::from(1), validators[i].clone(), (U256::from(current_block_number + 1), OpocLevel::Level1));
            NodesWorks::<Test>::insert(validators[i].clone(), request_id, true);
        }

        let inherent_data = InherentData::new();
        let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
        System::set_block_number(2);
        assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
        assert!(TestingPallet::is_inherent(&inherent_call));
        let runtime_call: RuntimeCall = inherent_call.into();
        assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));
        
        // After the execution of the inherent, the OpocAssignment storage should contain nft_required_consensus assignment for the request_id 1
        let opoc_assignments = OpocAssignment::<Test>::iter_prefix_values(request_id).collect::<Vec<_>>();
        assert_eq!(opoc_assignments.len() as u32, nft_required_consensus.as_u32());
        // After the execution of the inherent, the NodesWorks storage should contain nft_required_consensus - 1 assignments
        let nodes_works_number = NodesWorks::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(nodes_works_number.len() as u32, nft_required_consensus.as_u32() - 1);
        // All the opoc_assignments except one should have the expiration block number set to the current block number + 1
        let mut opoc_assignments_with_valid_expirations = 0;
        let mut opoc_assignment_with_new_expiration = 0;
        for (opoc_assignment, opoc_level) in opoc_assignments {
                if opoc_assignment == U256::from(current_block_number + 1) {
                    opoc_assignments_with_valid_expirations += 1;
                }
                if opoc_assignment == U256::from(current_block_number + 25) {
                    opoc_assignment_with_new_expiration += 1;
                }
        }

        // 3/4 of the assignments for the level 1 should have the expiration block number set to the current block number + 1
        let ok = u64::from(nft_required_consensus.as_u32() - 2);
        assert_eq!(opoc_assignments_with_valid_expirations, ok);
        // 1/4 of the assignments for the level 1 should have the expiration block number set to the current block number + the input lifetime
        // this means the the validator with the updated timeout is a new validator chosen to retry the execution that was in timeout
        assert_eq!(opoc_assignment_with_new_expiration, 1);

        let opoc_blacklist = OpocBlacklist::<Test>::get(validators[3].clone());
        assert_eq!(opoc_blacklist, true);
        // The validator should have timeouts
        let nodes_timeouts = NodesTimeouts::<Test>::get(validators[3].clone());
        assert_eq!(nodes_timeouts, 1 as u32);
    });
    
}

#[test]
fn test_inherent_opoc_level_1_completed_valid() {
    make_logger();
        
    new_test_ext().execute_with(|| {
        let empty_cid = Cid::default();
        //make an example of bounded vec with data inside
        let  bounded_vec: BoundedVec<u8, MaxDataSize> = BoundedVec::try_from(vec![1, 2, 3, 4, 5]).expect("Vector exceeds the bound");
        
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 10;
        let validators = create_validators(num_validators, stake);
            
        // Set current block
        System::set_block_number(3);
        let current_block_number = System::block_number();

        // Insert an input on the Inputs storage
        let request_id: U256 = U256::from(1);
        Inputs::<Test>::insert(request_id, (
                U256::zero(),
                H160::repeat_byte(0xAA),
                U256::zero(),
                U256::from(5), // nft_required_consensus
                U256::from(25), // nft_execution_max_time
                empty_cid.clone(),
                bounded_vec.clone(),
                empty_cid.clone(),
        ));

        // Insert an assignment for the first validator
        OpocAssignment::<Test>::insert(U256::from(1), validators[4].clone(), (U256::from(current_block_number - 1), OpocLevel::Level0)); 
        // Insert the output for the first validator
        NodesOutputs::<Test>::insert(request_id, validators[4].clone(), bounded_vec.clone());

        // Insert an assignment and an output for the other 4 validators
        for i in 0..4 {
            OpocAssignment::<Test>::insert(U256::from(1), validators[i].clone(), (U256::from(current_block_number + 1), OpocLevel::Level1));
            NodesWorks::<Test>::insert(validators[i].clone(), request_id, true);
            NodesOutputs::<Test>::insert(request_id, validators[i].clone(), bounded_vec.clone());
        }
        
        let inherent_data = InherentData::new();
        let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
        System::set_block_number(2);
        assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
        assert!(TestingPallet::is_inherent(&inherent_call));
        let runtime_call: RuntimeCall = inherent_call.into();
        assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));
        
        // storage Outputs should contain the output of the request
        let outputs = Outputs::<Test>::get(request_id);
        assert_eq!(outputs, (bounded_vec.clone(), 5, 5));

        //check that storage_opoc_assignment is empty
        let opoc_assignments = OpocAssignment::<Test>::iter_prefix_values(request_id).collect::<Vec<_>>();
        assert_eq!(opoc_assignments.len() as u32, 0);
        //check that storage_nodes_outputs is empty
        let nodes_outputs = NodesOutputs::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(nodes_outputs.len() as u32, 0);
        //check that storage_nodes_works is empty
        let nodes_works_number = NodesWorks::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(nodes_works_number.len() as u32, 0);
        //check that storage_opoc_blacklist is empty
        let opoc_blacklist = OpocBlacklist::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(opoc_blacklist.len() as u32, 0);
        //check that storage_nodes_timeouts is empty
        let nodes_timeouts = NodesTimeouts::<Test>::iter().collect::<Vec<_>>();
        assert_eq!(nodes_timeouts.len() as u32, 0); 
    });
}

#[test]
fn test_inherent_opoc_level_1_completed_invalid() {
  make_logger();
    
  new_test_ext().execute_with(|| {
    let empty_cid = Cid::default();
    //make an example of bounded vec with data inside
    let bounded_vec: BoundedVec<u8, MaxDataSize> = BoundedVec::try_from(vec![1, 2, 3, 4, 5]).expect("Vector exceeds the bound");
    
    let stake = 10_000_000_000_000_000_000;
    let num_validators = 10;
    let validators = create_validators(num_validators, stake);
    let default_bounded_vec = BoundedVec::<u8, MaxDataSize>::default();
        
    // Set current block
    System::set_block_number(3);
    let current_block_number = System::block_number();

    // Insert an input on the Inputs storage
    let request_id: U256 = U256::from(1);
    Inputs::<Test>::insert(request_id, (
        U256::zero(),
        H160::repeat_byte(0xAA),
        U256::zero(),
        U256::from(5), // nft_required_consensus
        U256::from(25), // nft_execution_max_time
        empty_cid.clone(),
        bounded_vec.clone(),
        empty_cid.clone(),
    ));

    // Insert an assignment for the first validator
    OpocAssignment::<Test>::insert(U256::from(1), validators[4].clone(), (U256::from(current_block_number - 1), OpocLevel::Level0)); 
    // Insert the output for the first validator
    NodesOutputs::<Test>::insert(request_id, validators[4].clone(), bounded_vec.clone());

    // Insert an assignment and an output for the other 4 validators
    for i in 0..3 {
        OpocAssignment::<Test>::insert(U256::from(1), validators[i].clone(), (U256::from(current_block_number + 1), OpocLevel::Level1));
        NodesWorks::<Test>::insert(validators[i].clone(), request_id, true);
        NodesOutputs::<Test>::insert(request_id, validators[i].clone(), bounded_vec.clone());
    }
    
    OpocAssignment::<Test>::insert(U256::from(1), validators[3].clone(), (U256::from(current_block_number + 1), OpocLevel::Level1));
    NodesWorks::<Test>::insert(validators[3].clone(), request_id, true);
    NodesOutputs::<Test>::insert(request_id, validators[3].clone(), default_bounded_vec.clone());
    
    let inherent_data = InherentData::new();
    let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
    System::set_block_number(2);
    assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
    assert!(TestingPallet::is_inherent(&inherent_call));
    let runtime_call: RuntimeCall = inherent_call.into();
    assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));
      
    //check if opoc assignment has numv_validators elements
    let opoc_assignments = OpocAssignment::<Test>::iter_prefix_values(request_id).collect::<Vec<_>>();
    assert_eq!(opoc_assignments.len() as u32, num_validators);
      
  });
}

#[test]
fn test_inherent_opoc_level_2_completed() {
  make_logger();
    
  new_test_ext().execute_with(|| {
    let empty_cid = Cid::default();
    //make an example of bounded vec with data inside
    let bounded_vec: BoundedVec<u8, MaxDataSize> = BoundedVec::try_from(vec![1, 2, 3, 4, 5]).expect("Vector exceeds the bound");
    
    let stake = 10_000_000_000_000_000_000;
    let num_validators = 10;
    let validators = create_validators(num_validators, stake);
    let default_bounded_vec = BoundedVec::<u8, MaxDataSize>::default();
        
    // Set current block
    System::set_block_number(3);
    let current_block_number = System::block_number();

    // Insert an input on the Inputs storage
    let request_id: U256 = U256::from(1);
    Inputs::<Test>::insert(request_id, (
        U256::zero(),
        H160::repeat_byte(0xAA),
        U256::zero(),
        U256::from(5), // nft_required_consensus
        U256::from(25), // nft_execution_max_time
        empty_cid.clone(),
        bounded_vec.clone(),
        empty_cid.clone(),
    ));

    // Insert an assignment and an output for the first 7 validators
    for i in 0..7 {
        OpocAssignment::<Test>::insert(U256::from(1), validators[i].clone(), (U256::from(current_block_number + 1), OpocLevel::Level2));
        NodesWorks::<Test>::insert(validators[i].clone(), request_id, true);
        NodesOutputs::<Test>::insert(request_id, validators[i].clone(), bounded_vec.clone());
    }

    // Insert an assignment and another output for the other 3 validators
    for i in 7..10 {
        OpocAssignment::<Test>::insert(U256::from(1), validators[i].clone(), (U256::from(current_block_number + 1), OpocLevel::Level2));
        NodesWorks::<Test>::insert(validators[i].clone(), request_id, true);
        NodesOutputs::<Test>::insert(request_id, validators[i].clone(), default_bounded_vec.clone());
    }
    
    let inherent_data = InherentData::new();
    let inherent_call = TestingPallet::create_inherent(&inherent_data).expect("Should create inherent");
    System::set_block_number(2);
    assert!(TestingPallet::check_inherent(&inherent_call, &inherent_data).is_ok());
    assert!(TestingPallet::is_inherent(&inherent_call));
    let runtime_call: RuntimeCall = inherent_call.into();
    assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));
      

    // storage Outputs should contain the output of the request generated from the majority of validators
    let outputs = Outputs::<Test>::get(request_id);
    assert_eq!(outputs, (bounded_vec.clone(), 10, 7));

    //check that storage_opoc_assignment is empty
    let opoc_assignments = OpocAssignment::<Test>::iter_prefix_values(request_id).collect::<Vec<_>>();
    assert_eq!(opoc_assignments.len() as u32, 0);
    //check that storage_nodes_outputs is empty
    let nodes_outputs = NodesOutputs::<Test>::iter().collect::<Vec<_>>();
    assert_eq!(nodes_outputs.len() as u32, 0);
    //check that storage_nodes_works is empty
    let nodes_works_number = NodesWorks::<Test>::iter().collect::<Vec<_>>();
    assert_eq!(nodes_works_number.len() as u32, 0);
    //check that storage_opoc_blacklist has 3 elements
    let opoc_blacklist = OpocBlacklist::<Test>::iter().collect::<Vec<_>>();
    assert_eq!(opoc_blacklist.len() as u32, 3);
    // check that storage_nodes_errors has 3 elements
    let nodes_error = NodesErrors::<Test>::iter().collect::<Vec<_>>();
    assert_eq!(nodes_error.len() as u32, 3);
    //check that storage_nodes_timeouts is empty
    let nodes_timeouts = NodesTimeouts::<Test>::iter().collect::<Vec<_>>();
    assert_eq!(nodes_timeouts.len() as u32, 0);   
  });
}

#[test]
fn test_inherent_in_block() {
    make_logger();
    
    new_test_ext().execute_with(|| {
      // Testa l'inherent su più blocchi
      for block_number in 1..=3 {
            System::set_block_number(block_number);
            
            let inherent_data = InherentData::new();

            if let Some(inherent_call) = TestingPallet::create_inherent(&inherent_data) {
                let runtime_call: RuntimeCall = inherent_call.into();
                assert_ok!(runtime_call.dispatch(RuntimeOrigin::none()));

                // force the reset of the inherent (this is done by the runtime on on_finalize)
                InherentDidUpdate::<Test>::take();
            }
      }
  });
}

// OPOC ASSIGNMENT FUNCTIONS
//////////////////////////////////////////////////////////////////////////////////

#[test]
fn test_opoc_assignment_for_one_validator_free_in_blacklist() {
    make_logger();

    new_test_ext().execute_with(|| {
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 5;
        let validators = create_validators(num_validators, stake);
        let main_validator = validators[0].clone();
        let request_id: U256 = U256::from(1);
        let current_block: U256 = U256::from(1);

        let mut opoc_blacklist_operations = BTreeMap::<AccountId, bool>::new();
        let mut opoc_assignment_operations = BTreeMap::<(U256, AccountId), (U256, OpocLevel)>::new();
        let mut nodes_works_operations = BTreeMap::<AccountId, BTreeMap<U256, bool>>::new();

        // Add request_id to the Inputs storage to permit the calculation of the expiration block number works correctly
        Inputs::<Test>::insert(request_id, (
            U256::zero(),
            H160::repeat_byte(0xAA),
            U256::zero(),
            U256::from(1), // nft_required_consensus
            U256::from(45), // nft_execution_max_time
            Cid::default(),
            BoundedVec::<u8, MaxDataSize>::default(),
            Cid::default(),
        ));

        // Put main_validator in blacklist
        opoc_blacklist_operations.insert(main_validator.clone(), true);

        // Put all validators except main_validator in nodes_works
        let mut request_id_true = BTreeMap::<U256, bool>::new();
        request_id_true.insert(request_id, true);
        for i in 1..(num_validators as usize) {
            let validator = validators[i].clone();
            if validator != main_validator {
                nodes_works_operations.insert(validator, request_id_true.clone());
            }
        }

        // Run the opoc_assignment function
        let assigned_completed = match TestingPallet::opoc_assignment(
            &mut opoc_blacklist_operations,
            &mut opoc_assignment_operations,
            &mut nodes_works_operations,
            &request_id,
            &current_block,
            crate::OpocLevel::Level0,
            1,
            vec![],
            true
        ) {
            Ok(_) => true,
            Err(_) => false
        };
        assert_eq!(assigned_completed, true);

        // Be sure that the main_validator is not more on the blacklist
        let opoc_blacklist = opoc_blacklist_operations.get(&main_validator).unwrap();
        assert_eq!(*opoc_blacklist, false);

        // Be sure that the main_validator is on the opoc_assignment_operations with the expiration block number set to the current block number + nft_execution_max_time
        let (opoc_assignment, opoc_level) = opoc_assignment_operations.get(&(request_id, main_validator)).unwrap();
        assert_eq!(*opoc_assignment, U256::from(1 + 45));
        assert_eq!(*opoc_level, crate::OpocLevel::Level0);

        // Be sure that the main_validator is on the nodes_works_operations with the request_id set to true
        let nodes_works = nodes_works_operations.get(&main_validator).unwrap();
        let request_id_true = nodes_works.get(&request_id).unwrap();
        assert_eq!(*request_id_true, true);
    });
}

// OPOC ASSIGNMENT GET RANDOM VALIDATORS FUNCTIONS
//////////////////////////////////////////////////////////////////////////////////

#[test]
fn test_opoc_assignment_get_random_validators_on_multiple_cases() {
    make_logger();

    new_test_ext().execute_with(|| {
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 100;
        let _validators = create_validators(num_validators, stake);

        let nodes_works_operations = BTreeMap::<AccountId, BTreeMap<U256, bool>>::new();

        // Request 100 validators, all available
        let validators = TestingPallet::opoc_assignment_get_random_validators(
            &nodes_works_operations,
            U256::from(100),
            false,
            vec![]
        ).unwrap();
        assert_eq!(validators.len(), 100);

        // Request 50 validators, all available
        let validators = TestingPallet::opoc_assignment_get_random_validators(
            &nodes_works_operations,
            U256::from(50),
            false,
            vec![]
        ).unwrap();
        assert_eq!(validators.len(), 50);

        // Request 1 validator, all available
        let validators = TestingPallet::opoc_assignment_get_random_validators(
            &nodes_works_operations,
            U256::from(1),
            false,
            vec![]
        ).unwrap();
        assert_eq!(validators.len(), 1);

        // Request 101 validators, not enough available
        let validators = TestingPallet::opoc_assignment_get_random_validators(
            &nodes_works_operations,
            U256::from(101),
            false,
            vec![]
        );
        assert_eq!(validators.is_err(), true);

        // Request 50 validators, exclude 50 validators
        let excluded_validators: Vec<AccountId> = (0..50).map(|i| AccountId::from_raw([i as u8; 32])).collect();
        let validators = TestingPallet::opoc_assignment_get_random_validators(
            &nodes_works_operations,
            U256::from(50),
            false,
            excluded_validators.clone()
        ).unwrap();
        assert_eq!(validators.len(), 50);
        // be sure selected validators are not in the excluded_validators
        for validator in validators {
            assert_eq!(excluded_validators.contains(&validator), false);
        }

        // Request 50 validators, exclude 51 validators
        let excluded_validators: Vec<AccountId> = (0..51).map(|i| AccountId::from_raw([i as u8; 32])).collect();
        let validators = TestingPallet::opoc_assignment_get_random_validators(
            &nodes_works_operations,
            U256::from(50),
            false,
            excluded_validators
        );
        assert_eq!(validators.is_err(), true);
    });
}

#[test]
fn test_opoc_assignment_for_one_validator_free_in_chilling() {
    make_logger();

    new_test_ext().execute_with(|| {
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 5;
        let validators = create_validators(num_validators, stake);
        let main_validator = validators[0].clone();
        let request_id: U256 = U256::from(1);
        let current_block: U256 = U256::from(1);

        let mut opoc_blacklist_operations = BTreeMap::<AccountId, bool>::new();
        let mut opoc_assignment_operations = BTreeMap::<(U256, AccountId), (U256, OpocLevel)>::new();
        let mut nodes_works_operations = BTreeMap::<AccountId, BTreeMap<U256, bool>>::new();

        // Add request_id to the Inputs storage to permit the calculation of the expiration block number works correctly
        Inputs::<Test>::insert(request_id, (
            U256::zero(),
            H160::repeat_byte(0xAA),
            U256::zero(),
            U256::from(1), // nft_required_consensus
            U256::from(45), // nft_execution_max_time
            Cid::default(),
            BoundedVec::<u8, MaxDataSize>::default(),
            Cid::default(),
        ));

        // Put all validators except main_validator in nodes_works
        let mut request_id_true = BTreeMap::<U256, bool>::new();
        request_id_true.insert(request_id, true);
        for i in 1..(num_validators as usize) {
            let validator = validators[i].clone();
            if validator != main_validator {
                nodes_works_operations.insert(validator, request_id_true.clone());
            }
        }

        // Put main_validator in chilling
        Chilling::<Test>::insert(&main_validator, true);

        // Run the opoc_assignment function
        let assigned_completed = match TestingPallet::opoc_assignment(
            &mut opoc_blacklist_operations,
            &mut opoc_assignment_operations,
            &mut nodes_works_operations,
            &request_id,
            &current_block,
            crate::OpocLevel::Level0,
            1,
            vec![],
            true
        ) {
            Ok(_) => true,
            Err(_) => false
        };
        assert_eq!(assigned_completed, true);

        // Be sure that the main_validator is not on the opoc_assignment_operations
        let opoc_assignment = opoc_assignment_operations.get(&(request_id, main_validator));
        assert_eq!(opoc_assignment, None);

        // Remove the chilling from the main_validator
        Chilling::<Test>::remove(&main_validator);

        // Run the opoc_assignment function
        let assigned_completed = match TestingPallet::opoc_assignment(
            &mut opoc_blacklist_operations,
            &mut opoc_assignment_operations,
            &mut nodes_works_operations,
            &request_id,
            &current_block,
            crate::OpocLevel::Level0,
            1,
            vec![],
            true
        ) {
            Ok(_) => true,
            Err(_) => false
        };
        assert_eq!(assigned_completed, true);

        // Be sure that the main_validator is on the opoc_assignment_operations with the expiration block number set to the current block number + nft_execution_max_time
        let (opoc_assignment, opoc_level) = opoc_assignment_operations.get(&(request_id, main_validator)).unwrap();
        assert_eq!(*opoc_assignment, U256::from(1 + 45));
        assert_eq!(*opoc_level, OpocLevel::Level0);
    });
}

// OFFCHAIN WORKER CALL AI FUNCTIONS
//////////////////////////////////////////////////////////////////////////////////

// NOTE: Commented because http request is not working in the tests
// #[test]
// fn test_offchain_worker_call_ai() {
//     make_logger();

//     let mut ext = new_test_ext();
    
//     // Set up the offchain worker test environment
//     let (offchain, _state) = TestOffchainExt::new();
//     let (pool, _state) = TestTransactionPoolExt::new();
//     ext.register_extension(OffchainDbExt::new(offchain.clone()));
//     ext.register_extension(OffchainWorkerExt::new(offchain));
//     ext.register_extension(TransactionPoolExt::new(pool));

//     ext.execute_with(|| {
//         let current_block: BlockNumber = U256::from(1).into();

//         // insert a model on AIModels
//         let model_key = AiModelKey::from(1);
//         let local_name: Data = "test_model".as_bytes().to_vec().try_into().unwrap();
//         AIModels::<Test>::insert(model_key, (
//             local_name.clone(),
//             local_name.clone(),
//             current_block.clone(),
//         ));

//         // define an input json
//         let input: Vec<u8> = r#"{"messages": [{ role: "system", content: "Hello, are you an AI?" }]}"#.as_bytes().to_vec().try_into().unwrap();

//         // call the function
//         let response = TestingPallet::offchain_worker_call_ai(
//             model_key,
//             current_block,
//             input,
//         );
//         log::info!("RESPONSE: {:?}", response);
//     });
// }

// SET CHILLING FUNCTIONS
//////////////////////////////////////////////////////////////////////////////////

#[test]
fn test_set_chilling_true() {
    make_logger();
    
    new_test_ext().execute_with(|| {
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 1;
        let validators = create_validators(num_validators, stake);
        let validator = validators[0].clone();
        
        // be sure chilling storage does not contain the validator
        let chilling = Chilling::<Test>::get(&validator);
        assert_eq!(chilling, false);

        // call the function using validator as origin
        let response = TestingPallet::set_chilling(RuntimeOrigin::signed(validator.clone()), true);

        // be sure response is ok
        assert_eq!(response, Ok(()));
        
        // be sure chilling storage contains the validator
        let chilling = Chilling::<Test>::get(&validator);
        assert_eq!(chilling, true);
    });
}

#[test]
fn test_set_chilling_false() {
    make_logger();
    
    new_test_ext().execute_with(|| {
        let stake = 10_000_000_000_000_000_000;
        let num_validators = 1;
        let validators = create_validators(num_validators, stake);
        let validator = validators[0].clone();

        // add the validator to the chilling storage
        Chilling::<Test>::insert(&validator, true);
        
        // be sure chilling storage does contain the validator
        let chilling = Chilling::<Test>::get(&validator);
        assert_eq!(chilling, true);

        // call the function using validator as origin
        let response = TestingPallet::set_chilling(RuntimeOrigin::signed(validator.clone()), false);
        
        // be sure response is ok
        assert_eq!(response, Ok(()));
        
        // be sure chilling storage does not contain the validator
        let chilling = Chilling::<Test>::get(&validator);
        assert_eq!(chilling, false);
    });
}

#[test]
fn test_set_chilling_called_by_a_non_validator() {
    make_logger();
    
    // NOTE: I'm not sure this is the best way to create a not valid validator but it works =)
    let mut ext = new_test_ext();
    let keystore = Arc::new(MemoryKeystore::new());
    keystore.sr25519_generate_new(crate::crypto::CRYPTO_KEY_TYPE, None).unwrap();
    ext.register_extension(KeystoreExt(keystore.clone()));
    let validator = keystore.sr25519_public_keys(crate::crypto::CRYPTO_KEY_TYPE).swap_remove(0);
    
    ext.execute_with(|| {
        // be sure chilling storage does not contain the validator
        let chilling = Chilling::<Test>::get(&validator);
        assert_eq!(chilling, false);

        // call the function using a non-validator as origin
        let response = TestingPallet::set_chilling(RuntimeOrigin::signed(validator), true);

        // be sure response is an error
        assert_eq!(response, Err("Only validators can call this function".into()));
        
        // be sure chilling storage does not contain the validator
        let chilling = Chilling::<Test>::get(&validator);
        assert_eq!(chilling, false);
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

// NOTE: Commented because it's not used for now
// fn get_test_account() -> AccountId {
//   let seed = [0u8; 32];
//   AccountId::from_raw(seed)
// }

fn create_validators(num_validators: u32, stake: u128) -> Vec<AccountId> {
    let mut validators = Vec::new();
    
    for i in 0..num_validators {
        // Crea un account unico per ogni validator
        let seed = [i as u8; 32];
        let account_id = AccountId::from_raw(seed);
        
        // Assegna fondi all'account
        let _ = <Balances as Currency<AccountId>>::make_free_balance_be(
            &account_id,
            stake
        );

        // Bond i fondi
        assert_ok!(Staking::bond(
            RuntimeOrigin::signed(account_id.clone()),
            stake,
            pallet_staking::RewardDestination::Staked,
        ));

        // Dichiara l'intenzione di validare
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(account_id.clone()),
            pallet_staking::ValidatorPrefs {
                commission: Perbill::from_percent(0),
                blocked: false,
            }
        ));

        validators.push(account_id);
    }

    validators
}
