use frame_support::pallet_prelude::{DispatchError, DispatchResult};
use frame_system::offchain::{SendUnsignedTransaction, Signer};
use pallet_ipfs::types::{Cid, ExpirationBlockNumber, UsableFromBlockNumber};
use pallet_ipfs::MinExpireDuration;
use sp_core::U256;
use sp_std::{
    vec,
    vec::Vec,
};
use scale_info::prelude::string::String;
use scale_info::prelude::format;
use core::sync::atomic::{AtomicBool, Ordering};

static mut SEMAPHORE: AtomicBool = AtomicBool::new(false);

use crate::{
    consts::{MAX_INPUTS_MANAGED_PER_BLOCK, PALLET_VERSION},
    ipfs::IpfsInterface,
    payloads::{PayloadNodesOutputs, PayloadNodesVersions},
    types::{BlockNumber, Data, NftId, RequestId, Version, AiModelKey},
    {BlockTime, Call, Config, Inputs, NodesOutputs, NodesVersions, OpocAssignment, Pallet, AIModels},
};

impl<T: Config> Pallet<T> {
    pub fn semaphore_status() -> bool {
        unsafe { SEMAPHORE.load(Ordering::Relaxed) }
    }

    // Offchain worker entry point
    #[cfg(feature = "std")]
    pub fn offchain_run(account_id: &T::AccountId) -> DispatchResult {
        log::info!("UOMI-ENGINE: Running offchain worker");

        // Be sure account is a validator, if not, do nothing
        if !cfg!(test) && !Self::address_is_active_validator(account_id) {
            log::info!("UOMI-ENGINE: Account is not a validator, skipping this run");
            return Ok(());
        }

        // Store the current node used version on the chain
        let stored_version = NodesVersions::<T>::get(&account_id);
        if stored_version != PALLET_VERSION { // we don't need to store the version if it's already stored correctly
            Self::offchain_store_version(&PALLET_VERSION).unwrap_or_else(|e| {
                log::error!("UOMI-ENGINE: Error storing updated node versions: {:?}", e);
            });
        }

        // Run agents
        Self::offchain_run_agents(&account_id).unwrap_or_else(|e| {
            log::error!("UOMI-ENGINE: Error running agents: {:?}", e);
        });

        Ok(())
    }

    #[cfg(feature = "std")]
    fn offchain_run_agents(account_id: &T::AccountId) -> DispatchResult {
        log::info!("UOMI-ENGINE: Running agents");

        // Check semaphore to be sure to do nothing if another agent is running
        // SAFETY: This is safe because offchain workers run in their own thread
        let semaphore = unsafe { &SEMAPHORE };
        if semaphore.compare_exchange(
            false,  // expected value
            true,   // new value
            Ordering::Acquire,
            Ordering::Relaxed
        ).is_err() {
            // Another worker is already running
            log::info!("UOMI-ENGINE: Another worker is already running");
            return Ok(());
        }

        // Find the request with less expiration block number to execute
        let (request_id, expiration_block_number) = Self::offchain_find_request_with_min_expiration_block_number(&account_id);
        if request_id == RequestId::default() {
            log::info!("UOMI-ENGINE: No requests to run found");
            // Unlock the semaphore
            semaphore.store(false, Ordering::Release);
            return Ok(());
        }
        log::info!("UOMI-ENGINE: Request with request id: {:?} - Expiration block number: {:?}", request_id, expiration_block_number);

        // Load request data from Inputs storage
        let (block_number, nft_id, _nft_required_consensus, nft_execution_max_time, nft_file_cid, input_data, input_file_cid) = Inputs::<T>::get(&request_id);
        log::info!("UOMI-ENGINE: Request data loaded with block number: {:?}, nft_id: {:?} and nft_execution_max_time: {:?}", block_number, nft_id, nft_execution_max_time);

        // Load wasm associated to the request nft_id
        let wasm = match Self::offchain_load_wasm_from_nft_id(&nft_id, &nft_file_cid) {
            Ok(wasm) => wasm,
            Err(error) => {
                log::error!("UOMI-ENGINE: Error loading the wasm from the NFT ID: {:?}", error);
                // In case of error loading the wasm, complete the request with an empty output
                Self::offchain_store_output_data(&request_id, &Data::default()).unwrap_or_else(|e| {
                    log::error!("UOMI-ENGINE: Error storing output data: {:?}", e);
                });
                // Unlock the semaphore
                semaphore.store(false, Ordering::Release);
                return Ok(());
            },
        };
        log::info!("UOMI-ENGINE: Wasm loaded with length: {:?}", wasm.len());

        // Run the wasm and store the output data
        match Self::offchain_run_wasm(wasm, input_data, input_file_cid, block_number, expiration_block_number, nft_execution_max_time) {
            Ok(output_data) => {
                log::info!("UOMI-ENGINE: Request {:?} executed successfully with output data length: {:?}", request_id, output_data.len());
                // Store the output data
                Self::offchain_store_output_data(&request_id, &output_data).unwrap_or_else(|e| {
                    log::error!("UOMI-ENGINE: Error storing output data: {:?}", e);
                });
            },
            Err(error) => {
                log::error!("UOMI-ENGINE: Error running request {:?}: {:?}", request_id, error);
                // In case of error running the wasm, complete the request with an empty output
                Self::offchain_store_output_data(&request_id, &Data::default()).unwrap_or_else(|e| {
                    log::error!("UOMI-ENGINE: Error storing output data: {:?}", e);
                });
            },
        }

        // Unlock the semaphore
        semaphore.store(false, Ordering::Release);

        log::info!("UOMI-ENGINE: Request {:?} completed", request_id);
        Ok(())
    }

    fn offchain_find_request_with_min_expiration_block_number(account_id: &T::AccountId) -> (RequestId, BlockNumber) {
        let mut opoc_assignments = Vec::<(RequestId, BlockNumber)>::new();
        let inputs = Inputs::<T>::iter().collect::<Vec<_>>();

        for (request_id, _) in inputs.iter().take(MAX_INPUTS_MANAGED_PER_BLOCK) {
            log::info!("Checking request: {:?}", request_id);

            // Check if the request is assigned to the validator by checking if the request_id is in the OpocAssignment storage
            let has_opoc_assignment = OpocAssignment::<T>::contains_key(*request_id, &account_id);
            if !has_opoc_assignment {
                log::info!("Request {:?} is not assigned to the validator", request_id);
                continue;
            }

            // Be sure request is not already managed by checking if the request_id is in the NodesOutputs storage
            let has_node_output = NodesOutputs::<T>::contains_key(*request_id, &account_id);
            if has_node_output {
                log::info!("Request {:?} is already managed", request_id);
                continue;
            }

            // Read the expiration_block_number from the OpocAssignment storage
            let expiration_block_number = OpocAssignment::<T>::get(*request_id, &account_id);

            // Add the request_id and expiration_block_number to the opoc_assignment vector
            opoc_assignments.push((*request_id, expiration_block_number));

            log::info!("Request {:?} is assigned to the validator and not already managed", request_id);
        }

        // Return zero if no opoc_assignments has been found
        if opoc_assignments.is_empty() {
            return (Default::default(), Default::default());
        }

        // Sort opoc_assignments by expiration block number
        opoc_assignments.sort_by(|a, b| a.1.cmp(&b.1));

        // Return first request
        opoc_assignments[0]
    }

    fn offchain_load_wasm_from_nft_id(nft_id: &NftId, nft_file_cid: &Cid) -> Result<Vec<u8>, DispatchError> {
        // In case of tests, load agents used for tests
        if cfg!(test) {
            if nft_id == &U256::from(0) { // Agent 0 is a simple agent that return correctly the input data inverted
                let wasm = include_bytes!("./test_agents/agent0.wasm").to_vec();
                return Ok(wasm);
            }
            if nft_id == &U256::from(1) { // Agent 1 is a simple agent that run an infinite loop
                let wasm = include_bytes!("./test_agents/agent1.wasm").to_vec();
                return Ok(wasm);
            }
            if nft_id == &U256::from(2) { // Agent 2 is a simple agent that request the execution of ai model 0
                let wasm = include_bytes!("./test_agents/agent2.wasm").to_vec();
                return Ok(wasm);
            }
            if nft_id == &U256::from(3) { // Agent 3 is a simple agent that request a file from IPFS using the input as CID
                let wasm = include_bytes!("./test_agents/agent3.wasm").to_vec();
                return Ok(wasm);
            }
            if nft_id == &U256::from(1312) { // Agent 1312 is the famous uomi whitepaper chat agent
                let wasm = include_bytes!("./test_agents/uomi_whitepaper_chat_agent.wasm").to_vec();
                return Ok(wasm);
            }

            return Err(DispatchError::Other("Error loading the wasm from the NFT ID for tests"));
        }
        log::info!("Loading wasm from NFT ID: {:?}", nft_id);

        match T::IpfsPallet::get_file(nft_file_cid) {
            Ok(wasm) => Ok(wasm),
            Err(error) => {
                log::error!("Error loading the wasm from the NFT ID: {:?}", error);
                Err(DispatchError::Other("Error loading the wasm from the NFT ID"))
            },
        }
    }

    #[cfg(feature = "std")]
    pub fn offchain_run_wasm(wasm: Vec<u8>, input_data: Data, input_file_cid: Cid, block_number: BlockNumber, expiration_block_number: BlockNumber, nft_execution_max_time: U256) -> Result<Data, wasmtime::Error> {
        // Convert input_data to a Vec<u8>
        let input_data_as_vec = input_data.to_vec();

        // Calculate the timeout for the execution of the request
        // The timeout should be calculated as expiration_block_number - start_block
        // If timeout is > nft_execution_max_time - 3, timeout should be nft_execution_max_time - 3
        // NOTE: We calculate time after the wasm loading to avoid the wasm loading time to be counted in the timeout.
        let start_block = <frame_system::Pallet<T>>::block_number();
        let timeout_blocks_max = nft_execution_max_time - U256::from(3);
        let mut timeout_blocks = expiration_block_number - start_block;
        if timeout_blocks > timeout_blocks_max {
            timeout_blocks = nft_execution_max_time - U256::from(3);
        }
        let timeout_time = timeout_blocks * U256::from(BlockTime::get());
        let timeout_time_cs = timeout_time.low_u64() as u64 * 10;
        let timeout_time_ms = timeout_time.low_u64() as u64 * 1000;

        type HostState = Vec<u8>;
        let mut config = wasmtime::Config::new();
        config.epoch_interruption(true);
        let engine = wasmtime::Engine::new(&config).unwrap();
        let mut store = wasmtime::Store::new(&engine, HostState::new());
        store.set_epoch_deadline(timeout_time_cs);
        store.epoch_deadline_trap();
        let module = wasmtime::Module::new(&engine, &wasm)?;

        let get_input_data = move |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, _len: i32| {
            let data_to_write = Self::offchain_worker_generate_data_for_wasm(input_data_as_vec.clone());
            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            memory.write(caller, ptr as usize, &data_to_write).expect("Failed to write memory");
        };

        let get_input_file = move |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, _len: i32| {
            let file = T::IpfsPallet::get_file(&input_file_cid).unwrap();
            let data_to_write = Self::offchain_worker_generate_data_for_wasm(file);
            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            memory.write(caller, ptr as usize, &data_to_write).expect("Failed to write memory");
        };

        let set_output = move |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, len: i32| {
            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            let mut buffer = vec![0u8; len as usize];
            memory.read(&caller, ptr as usize, &mut buffer).expect("Failed to read memory");
            *caller.data_mut() = buffer;
        };

        let call_ai = move |mut caller: wasmtime::Caller<'_, HostState>, model: i32, ptr: i32, len: i32, output_ptr: i32, _: i32| {
            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            let mut buffer = vec![0u8; len as usize];
            memory.read(&caller, ptr as usize, &mut buffer).expect("Failed to read memory");
            let model = AiModelKey::from(model as u32);
            let output = Self::offchain_worker_call_ai(model, block_number, buffer).unwrap();
            let data_to_write = Self::offchain_worker_generate_data_for_wasm(output);
            memory.write(caller, output_ptr as usize, &data_to_write).expect("Failed to write memory");
        };

        let get_cid_file = move |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, len: i32, output_ptr: i32, _: i32| {
            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            let mut buffer = vec![0u8; len as usize];
            memory.read(&caller, ptr as usize, &mut buffer).expect("Failed to read memory");
            let cid = Cid::try_from(buffer).unwrap();
            let file = Self::offcahin_worker_get_cid_file(cid, block_number).unwrap();
            let data_to_write = Self::offchain_worker_generate_data_for_wasm(file);
            memory.write(caller, output_ptr as usize, &data_to_write).expect("Failed to write memory");
        };

        let console_log = move |mut caller: wasmtime::Caller<'_, HostState>, _ptr: i32, _len: i32| {
            // Do nothing, function exposed to help wasm debugging
        };

        let mut linker = wasmtime::Linker::new(&engine);
        linker.func_wrap("env", "get_input_file", get_input_file).unwrap();
        linker.func_wrap("env", "get_input_data", get_input_data).unwrap();
        linker.func_wrap("env", "set_output", set_output).unwrap();
        linker.func_wrap("env", "call_ai", call_ai).unwrap();
        linker.func_wrap("env", "get_cid_file", get_cid_file).unwrap();
        linker.func_wrap("env", "console_log", console_log).unwrap();

        let instance = linker.instantiate(&mut store, &module)?;
        let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;

        // Start a thread to increment the epoch counter
        let mut time_passed_ms = 0;
        let engine_clone = engine.clone();
        std::thread::spawn(move || {
            while time_passed_ms < timeout_time_ms {
                std::thread::sleep(std::time::Duration::from_millis(100));
                engine_clone.increment_epoch();
                time_passed_ms += 100;
            }
        });

        match run.call(&mut store, ()) {
            Ok(_) => {
                let stored_data = store.data().clone();
                let data: Data = stored_data.try_into().unwrap_or_else(|_| Data::default());
                Ok(data)
            }
            Err(err) => {
                log::error!("UOMI-ENGINE: WASM execution error: {:?}", err);
                Err(wasmtime::Error::new(std::io::Error::new(std::io::ErrorKind::Other, "WASM execution error")))
            }
        }
    }

    // BACKUP IMPLEMENTATION WITH WASMI
    // Need wasmi = { version = "0.35", default-features = false } on Cargo.toml
    // #[cfg(feature = "std")]
    // pub fn wasmi_offchain_run_wasm(wasm: Vec<u8>, input_data: Data, input_file_cid: Cid, block_number: BlockNumber, expiration_block_number: BlockNumber, nft_execution_max_time: U256) -> Result<Data, wasmi::Error> {
    //     // Convert input_data to a Vec<u8>
    //     let input_data_as_vec = input_data.to_vec();

    //     // Calculate the timeout for the execution of the request
    //     // The timeout should be calculated as expiration_block_number - current_block
    //     // If timeout is > nft_execution_max_time - 2, timeout should be nft_execution_max_time - 2
    //     // NOTE: We calculate time after the wasm loading to avoid the wasm loading time to be counted in the timeout.
    //     let current_block = <frame_system::Pallet<T>>::block_number();
    //     let timeout_blocks_max = nft_execution_max_time - U256::from(2);
    //     let mut timeout_blocks = expiration_block_number - current_block;
    //     if timeout_blocks > timeout_blocks_max {
    //         timeout_blocks = nft_execution_max_time - U256::from(2);
    //     }
    //     let timeout_time = timeout_blocks * U256::from(BlockTime::get());
    //     let timeout_time_ms = timeout_time.low_u64() as u64 * 1000;

    //     type HostState = Vec<u8>;
    //     let mut config = wasmi::Config::default();
    //     config.consume_fuel(true);
    //     let engine = wasmi::Engine::new(&config);
    //     let module = wasmi::Module::new(&engine, &wasm[..])?;
    //     let mut store = wasmi::Store::new(&engine, HostState::new());
    //     let _ = store.set_fuel(100_000_000);

    //     let get_input_data = wasmi::Func::wrap(
    //         &mut store,
    //         move |mut caller: wasmi::Caller<'_, HostState>, ptr: i32, _len: i32| {
    //             let data_to_write = Self::offchain_worker_generate_data_for_wasm(input_data_as_vec.clone());

    //             let memory = caller
    //                 .get_export("memory")
    //                 .and_then(wasmi::Extern::into_memory)
    //                 .expect("Failed to get memory export");
    
    //             memory
    //                 .write(&mut caller, ptr as usize, &data_to_write)
    //                 .expect("Failed to write memory");
    //         }
    //     );

    //     let get_input_file = wasmi::Func::wrap(
    //         &mut store,
    //         move |mut caller: wasmi::Caller<'_, HostState>, ptr: i32, _len: i32| {
    //             let file = T::IpfsPallet::get_file(&input_file_cid).unwrap();
    //             let data_to_write = Self::offchain_worker_generate_data_for_wasm(file);

    //             let memory = caller
    //                 .get_export("memory")
    //                 .and_then(wasmi::Extern::into_memory)
    //                 .expect("Failed to get memory export");
    
    //             memory
    //                 .write(&mut caller, ptr as usize, &data_to_write)
    //                 .expect("Failed to write memory");
    //         }
    //     );

    //     let set_output = wasmi::Func::wrap(
    //         &mut store,
    //         |mut caller: wasmi::Caller<'_, HostState>, ptr: i32, len: i32| {
    //             let memory = caller
    //                 .get_export("memory")
    //                 .and_then(wasmi::Extern::into_memory)
    //                 .expect("Failed to get memory export");
    
    //             let mut buffer = vec![0u8; len as usize];
    //             memory
    //                 .read(&caller, ptr as usize, &mut buffer)
    //                 .expect("Failed to read memory");
    
    //             *caller.data_mut() = buffer;
    //         }
    //     );

    //     let call_ai = wasmi::Func::wrap(
    //         &mut store,
    //         move |mut caller: wasmi::Caller<'_, HostState>, model: i32, ptr: i32, len: i32, output_ptr: i32, _: i32| {
    //             let memory = caller
    //                 .get_export("memory")
    //                 .and_then(wasmi::Extern::into_memory)
    //                 .expect("Failed to get memory export");

    //             let mut buffer = vec![0u8; len as usize];

    //             memory
    //                 .read(&caller, ptr as usize, &mut buffer)
    //                 .expect("Failed to read memory");

    //             let model = AiModelKey::from(model as u32);

    //             let output = Self::offchain_worker_call_ai(model, block_number, buffer).unwrap();
    //             let data_to_write = Self::offchain_worker_generate_data_for_wasm(output);

    //             let memory = caller
    //                 .get_export("memory")
    //                 .and_then(wasmi::Extern::into_memory)
    //                 .expect("Failed to get memory export");

    //             memory
    //                 .write(&mut caller, output_ptr as usize, &data_to_write)
    //                 .expect("Failed to write memory");
    //         }
    //     );

    //     let get_cid_file = wasmi::Func::wrap(
    //         &mut store,
    //         move |mut caller: wasmi::Caller<'_, HostState>, ptr: i32, len: i32, output_ptr: i32, _: i32| {
    //             let memory = caller
    //                 .get_export("memory")
    //                 .and_then(wasmi::Extern::into_memory)
    //                 .expect("Failed to get memory export");

    //             let mut buffer = vec![0u8; len as usize];

    //             memory
    //                 .read(&caller, ptr as usize, &mut buffer)
    //                 .expect("Failed to read memory");

    //             let cid = Cid::try_from(buffer).unwrap();
                
    //             let file = Self::offcahin_worker_get_cid_file(cid, block_number).unwrap();
    //             let data_to_write = Self::offchain_worker_generate_data_for_wasm(file);

    //             let memory = caller
    //                 .get_export("memory")
    //                 .and_then(wasmi::Extern::into_memory)
    //                 .expect("Failed to get memory export");

    //             memory
    //                 .write(&mut caller, output_ptr as usize, &data_to_write)
    //                 .expect("Failed to write memory");
    //         }
    //     );

    //     let console_log = wasmi::Func::wrap(
    //         &mut store,
    //         |_caller: wasmi::Caller<'_, HostState>, _ptr: i32, _len: i32| {
    //             // Do nothing, function exposed to help wasm debugging
    //         }
    //     );

    //     let mut linker: wasmi::Linker<Vec<u8>> = wasmi::Linker::new(&engine);
    //     linker.define("env", "get_input_data", get_input_data)?;
    //     linker.define("env", "get_input_file", get_input_file)?;
    //     linker.define("env", "set_output", set_output)?;
    //     linker.define("env", "call_ai", call_ai)?;
    //     linker.define("env", "get_cid_file", get_cid_file)?;
    //     linker.define("env", "console_log", console_log)?;

    //     let instance = linker.instantiate(&mut store, &module)?.start(&mut store)?;
    //     let wasm_run = instance.get_typed_func::<(), ()>(&store, "run")?;

    //     // // Create a channel to communicate between threads
    //     // let (tx, rx) = std::sync::mpsc::channel();

    //     // // Run the function in a separate thread with same Externalities-provided environment
    //     // std::thread::spawn(move || {
    //     //     wasm_run.call(&mut store, ()).unwrap();
    //     //     tx.send(store.into_data()).unwrap();
    //     // });

    //     // // Wait for timeout_time_ms or until the function completes
    //     // let store_data = match rx.recv_timeout(std::time::Duration::from_millis(timeout_time_ms)) {
    //     //     Ok(store_data) => {
    //     //         log::info!("WASM execution completed successfully");
    //     //         store_data
    //     //     },
    //     //     Err(_) => {
    //     //         log::error!("WASM execution timeout");
    //     //         return Err(wasmi::Error::new("WASM execution timeout"));
    //     //     },
    //     // };

    //     // Run the function
    //     wasm_run.call(&mut store, ())?;
    //     let store_data = store.into_data();

    //     // Convert the store_data to a BoundedVec. If the store_data is too big, it will be converted to an empty BoundedVec
    //     let store_data_bounded: Data = store_data
    //         .clone()
    //         .try_into()
    //         .unwrap_or_else(|_| Data::default());

    //     Ok(store_data_bounded)        
    // }

    fn offchain_worker_generate_data_for_wasm(data: Vec<u8>) -> Vec<u8> {
        let data_len = data.len();
        let mut wasm_data = Vec::new();

        // write data_len on first 4 bytes of wasm_data, then write data
        wasm_data.extend(&(data_len as u32).to_le_bytes());
        wasm_data.extend(data);

        wasm_data
    }

    pub fn offchain_worker_call_ai(model: AiModelKey, block_number: BlockNumber, input: Vec<u8>) -> Result<Vec<u8>, DispatchError> {
        if model == AiModelKey::zero() { // Model 0 is a simple model that return the input data inverted used for tests
            let output = input.iter().rev().cloned().collect();
            return Ok(output);
        }
    
        let (local_name, previous_local_name, available_from_block_number) = AIModels::<T>::get(&model);
        let final_local_name = if block_number < available_from_block_number {
            previous_local_name
        } else {
            local_name
        };

        if final_local_name == Data::default() {
            return Err(DispatchError::Other("Error getting the model name from the AiModels storage - final_local_name is empty"));
        }

        let url = "http://localhost:8888/run";
        let input_data = String::from_utf8(input).map_err(|_| {
            log::error!("UOMI-ENGINE: Invalid UTF-8 in input data");
            DispatchError::Other("Invalid UTF-8 in input data")
        })?;

        let model = String::from_utf8(final_local_name.to_vec()).map_err(|_| {
            log::error!("UOMI-ENGINE: Invalid UTF-8 in final local name");
            DispatchError::Other("Invalid UTF-8 in final local name")
        })?;

        fn escape_json_string(s: &str) -> String {
            s.replace('\\', "\\\\")  // First escape backslashes
             .replace('\"', "\\\"")  // Then escape quotes
             .replace('\n', "\\n")   // Handle newlines
             .replace('\r', "\\r")   // Handle carriage returns
             .replace('\t', "\\t")   // Handle tabs
        }
        let body: String = format!("{{\"model\": \"{}\", \"input\": \"{}\"}}", model, escape_json_string(&input_data));

        let mut request = sp_runtime::offchain::http::Request::post(url, vec![body.as_bytes()]);
        request = request
            .add_header("Content-Type", "application/json")
            .add_header("Accept", "application/json");

        let pending = match request.send() {
            Ok(pending_request) => pending_request,
            Err(e) => {
                log::error!("UOMI-ENGINE: Failed to send HTTP request: {:?}", e);
                return Err(DispatchError::Other("Failed to send HTTP request"));
            }
        };
    
        let response = match pending.wait() {
            Ok(response) => response,
            Err(e) => {
                log::error!("UOMI-ENGINE: HTTP request failed after sending: {:?}", e);
                return Err(DispatchError::Other("HTTP request failed after sending"));
            }
        };
    
        if response.code != 200 {
            let body = response.body().collect::<Vec<u8>>();
            if let Ok(body_str) = sp_std::str::from_utf8(&body) {
                log::error!("UOMI-ENGINE: Error response from AI service. Status: {}. Body: {}", response.code, body_str);
            } else {
                log::error!("UOMI-ENGINE: Error response from AI service. Status: {}. Body is not UTF-8", response.code);
            }
            return Err(DispatchError::Other("Error response from AI service"));
        }
    
        let response_body = response.body().collect::<Vec<u8>>();
        let output: Data = response_body.try_into().map_err(|_| {
            log::error!("UOMI-ENGINE: Failed to convert response body to Data type");
            DispatchError::Other("Failed to convert response body")
        })?;

        Ok(output.to_vec())
    }

    fn offcahin_worker_get_cid_file(cid: Cid, block_number: BlockNumber) -> Result<Vec<u8>, DispatchError> {
        let file;
        if cfg!(test) { // In tests, we use the cid as file
            file = cid.to_vec();
        } else {
            let ipfs_min_expire_duration = U256::from(MinExpireDuration::get());

            match T::IpfsPallet::get_cid_status(&cid) {
                Ok((expiration_block_number, usable_from_block_number)) => {
                    if expiration_block_number != ExpirationBlockNumber::zero() && block_number + ipfs_min_expire_duration > expiration_block_number {
                        log::error!("UOMI-ENGINE: The file requested by wasm expires before the minimum expiration duration");
                        file = Vec::new();
                    } else if usable_from_block_number == UsableFromBlockNumber::zero() || usable_from_block_number > block_number {
                        log::error!("The file requested by wasm was not usable at the request block number");
                        file = Vec::new();
                    } else {
                        file = T::IpfsPallet::get_file(&cid).unwrap();
                    }
                },
                Err(error) => {
                    log::error!("Error getting the file info from the IPFS pallet: {:?}", error);
                    file = Vec::new();
                },
            };
        }

        Ok(file)
    }

    fn offchain_store_output_data(request_id: &RequestId, output_data: &Data) -> DispatchResult {
        let signer = Signer::<T, T::UomiAuthorityId>::all_accounts();
        if !signer.can_sign() {
            log::error!("No accounts available to sign the transaction");
            return Err(DispatchError::Other("No accounts available to sign"));
        }

        let _ = signer.send_unsigned_transaction(
            |acct| PayloadNodesOutputs { 
                request_id: request_id.clone(), 
                output_data: output_data.clone(),
                public: acct.public.clone(),
            },
            |payload, signature| Call::store_nodes_outputs { 
                payload, 
                signature 
            },
        );

        Ok(())
    }

    fn offchain_store_version(version: &Version) -> DispatchResult {
        let signer = Signer::<T, T::UomiAuthorityId>::all_accounts();
        if !signer.can_sign() {
            log::error!("No accounts available to sign the transaction");
            return Err(DispatchError::Other("No accounts available to sign"));
        }

        let _ = signer.send_unsigned_transaction(
            |acct| PayloadNodesVersions { 
                public: acct.public.clone(),
                version: version.clone(),
            },
            |payload, signature| Call::store_nodes_versions { 
                payload, 
                signature 
            },
        );

        Ok(())
    }
}