use frame_support::pallet_prelude::{DispatchError, DispatchResult};
use frame_system::offchain::{SendUnsignedTransaction, Signer};
use pallet_ipfs::types::{Cid, ExpirationBlockNumber, UsableFromBlockNumber};
use pallet_ipfs::MinExpireDuration;
use sp_core::{U256, H160};
use sp_std::{
    vec,
    vec::Vec,
};
use sp_core::Get;
use scale_info::prelude::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

// Semaphore implementation to limit the executions of requests in parallel
const SEMAPHORE_ARRAY_REPEAT_VALUE: SemaphoreAtomicSlot = SemaphoreAtomicSlot::new();
const SEMAPHORE_MAX_SLOTS: usize = 4; // Maximum number of concurrent requests
static SEMAPHORE_SLOTS: [SemaphoreAtomicSlot; SEMAPHORE_MAX_SLOTS] = [
    SEMAPHORE_ARRAY_REPEAT_VALUE; SEMAPHORE_MAX_SLOTS
];
#[derive(Debug)]
struct SemaphoreAtomicSlot {
    // U256 is represented as 4 x u64
    part0: AtomicU64,
    part1: AtomicU64,
    part2: AtomicU64,
    part3: AtomicU64,
    in_use: AtomicU64, // 0 = free, 1 = occupied
}

impl SemaphoreAtomicSlot {
    const fn new() -> Self {
        Self {
            part0: AtomicU64::new(0),
            part1: AtomicU64::new(0),
            part2: AtomicU64::new(0),
            part3: AtomicU64::new(0),
            in_use: AtomicU64::new(0),
        }
    }

    fn try_set(&self, request_id: U256) -> bool {
        // Attempt to acquire the slot atomically
        if self.in_use.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            return false;
        }

        // Convert U256 to 4 u64 parts
        let bytes = request_id.0;
        self.part0.store(bytes[0], Ordering::Relaxed);
        self.part1.store(bytes[1], Ordering::Relaxed);
        self.part2.store(bytes[2], Ordering::Relaxed);
        self.part3.store(bytes[3], Ordering::Relaxed);

        true
    }

    fn clear(&self) {
        self.part0.store(0, Ordering::Relaxed);
        self.part1.store(0, Ordering::Relaxed);
        self.part2.store(0, Ordering::Relaxed);
        self.part3.store(0, Ordering::Relaxed);
        self.in_use.store(0, Ordering::Release);
    }

    fn matches(&self, request_id: U256) -> bool {
        if self.in_use.load(Ordering::Acquire) == 0 {
            return false;
        }

        let bytes = request_id.0;
        self.part0.load(Ordering::Relaxed) == bytes[0] &&
        self.part1.load(Ordering::Relaxed) == bytes[1] &&
        self.part2.load(Ordering::Relaxed) == bytes[2] &&
        self.part3.load(Ordering::Relaxed) == bytes[3]
    }

    fn is_in_use(&self) -> bool {
        self.in_use.load(Ordering::Acquire) == 1
    }
}

/// Attempts to add a request_id to the semaphore
/// Returns true if added successfully, false otherwise
pub fn semaphore_try_to_add(request_id: U256) -> bool {
    // First check if the request_id is already present
    for slot in &SEMAPHORE_SLOTS[0..SEMAPHORE_MAX_SLOTS] {
        if slot.matches(request_id) {
            return false; // Already running
        }
    }

    // Look for a free slot and acquire it
    for slot in &SEMAPHORE_SLOTS[0..SEMAPHORE_MAX_SLOTS] {
        if slot.try_set(request_id) {
            return true;
        }
    }

    false // No slot available
}

/// Removes a request_id from the semaphore
pub fn semaphore_remove(request_id: U256) {
    for slot in &SEMAPHORE_SLOTS {
        if slot.matches(request_id) {
            slot.clear();
            return;
        }
    }
}

/// Checks if a request_id is running
pub fn semaphore_is_running(request_id: U256) -> bool {
    for slot in &SEMAPHORE_SLOTS {
        if slot.matches(request_id) {
            return true;
        }
    }
    false
}

/// Counts how many requests are currently running
pub fn semaphore_counter() -> usize {
    SEMAPHORE_SLOTS.iter()
        .filter(|slot| slot.is_in_use())
        .count()
}

/// Show all the request_ids currently running (for debug purposes)
pub fn semaphore_list() -> Vec<U256> {
    let mut running_requests = Vec::new();
    for slot in &SEMAPHORE_SLOTS {
        if slot.is_in_use() {
            let part0 = slot.part0.load(Ordering::Relaxed);
            let part1 = slot.part1.load(Ordering::Relaxed);
            let part2 = slot.part2.load(Ordering::Relaxed);
            let part3 = slot.part3.load(Ordering::Relaxed);
            let request_id = U256([part0, part1, part2, part3]);
            running_requests.push(request_id);
        }
    }
    running_requests
}
// --- End semaphore implementation ---

use crate::OpocLevel;
use crate::{
    consts::{MAX_INPUTS_MANAGED_PER_BLOCK, PALLET_VERSION},
    ipfs::IpfsInterface,
    payloads::{PayloadNodesOutputs, PayloadNodesVersions, PayloadNodesOpocL0Inferences},
    types::{BlockNumber, Data, NftId, RequestId, Version, AiModelKey},
    {BlockTime, Call, Config, Inputs, NodesOutputs, NodesVersions, OpocAssignment, Pallet, AIModels, NodesOpocL0Inferences},
};

#[derive(miniserde::Serialize, miniserde::Deserialize)]
struct CallAiRequestWithProof {
    request_id: String,
    model: String,
    input: String,
    proof: String,
}

#[derive(miniserde::Serialize, miniserde::Deserialize)]
struct CallAiRequestWithoutProof {
    request_id: String,
    model: String,
    input: String,
}

#[derive(miniserde::Serialize, miniserde::Deserialize)]
struct CallAiResponse {
    result: bool,
    response: String,
    proof: String
}

#[derive(miniserde::Serialize, miniserde::Deserialize)]
struct CallAiResponseCleaned {
    response: String,
}


impl<T: Config> Pallet<T> {
    // Test-only helpers
    #[cfg(test)]
    pub fn test_semaphore_try_to_add(request_id: &RequestId) -> bool {
        semaphore_try_to_add(*request_id)
    }
    #[cfg(test)]
    pub fn test_semaphore_remove(request_id: &RequestId) {
        semaphore_remove(*request_id);
    }
    #[cfg(test)]
    pub fn test_semaphore_counter() -> u32 {
        semaphore_counter() as u32
    }
    #[cfg(test)]
    pub fn test_semaphore_list() -> Vec<U256> {
        semaphore_list()
    }

    // Offchain worker entry point
    #[cfg(feature = "std")]
    pub fn offchain_run(account_id: &T::AccountId) -> DispatchResult {
        log::info!("UOMI-ENGINE: Offchain worker run started");

        // Be sure account is a validator, if not, do nothing
        if !cfg!(test) && !Self::address_is_active_validator(account_id) {
            log::info!("UOMI-ENGINE: Offchain worker stopped, account is not an active validator");
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
        // Find the request with less expiration block number to execute
        let (request_id, (expiration_block_number, _opoc_level)) = Self::offchain_find_request_with_min_expiration_block_number(&account_id);
        if request_id == RequestId::default() {
            log::info!("UOMI-ENGINE: No requests to process");
            return Ok(());
        }

        // Be sure the request is not already running on another thread
        if !semaphore_try_to_add(request_id) {
            log::info!("UOMI-ENGINE: Request {:?} is already running on another thread", request_id);
            return Ok(());
        }

        // Load request data from Inputs storage
        let (block_number, address, nft_id, nft_required_consensus, nft_execution_max_time, nft_file_cid, input_data, input_file_cid) = Inputs::<T>::get(&request_id);
        log::info!("UOMI-ENGINE: Processing request {:?} assigned to validator {:?}, expiration block number: {:?}", request_id, account_id, expiration_block_number);

        // Detect the level of opoc the execution should have
        let opoc_level = match Self::offchain_detect_opoc_level(&request_id, &account_id) {
            Ok(level) => level,
            Err(error) => {
                log::error!("UOMI-ENGINE: Error detecting opoc level: {:?}", error);
                // In case of error checking the opoc level, complete the request with an empty output
                Self::offchain_store_output_data(&request_id, &Data::default()).unwrap_or_else(|e| {
                    log::error!("UOMI-ENGINE: Error storing output data: {:?}", e);
                });
                // Remove request_id from the semaphore
                semaphore_remove(request_id);
                return Ok(());
            }
        };

        // Load wasm associated to the request nft_id
        let wasm = match Self::offchain_load_wasm_from_nft_id(&nft_id, &nft_file_cid) {
            Ok(wasm) => wasm,
            Err(error) => {
                log::error!("UOMI-ENGINE: Error loading the wasm from the NFT ID: {:?}", error);
                // In case of error loading the wasm, complete the request with an empty output
                Self::offchain_store_output_data(&request_id, &Data::default()).unwrap_or_else(|e| {
                    log::error!("UOMI-ENGINE: Error storing output data: {:?}", e);
                });
                // Remove request_id from the semaphore
                semaphore_remove(request_id);
                return Ok(());
            },
        };

        // Run the wasm and store the output data
        match Self::offchain_run_wasm(wasm, input_data, input_file_cid, address, block_number, expiration_block_number, nft_required_consensus, nft_execution_max_time, request_id, opoc_level) {
            Ok(output_data) => {
                let final_output_data = output_data.clone();

                // Store the output data
                Self::offchain_store_output_data(&request_id, &final_output_data).unwrap_or_else(|e| {
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

        // Remove request_id from the semaphore
        semaphore_remove(request_id);
        
        log::info!("UOMI-ENGINE: Finished processing request {:?}", request_id);
        Ok(())
    }

    fn offchain_find_request_with_min_expiration_block_number(account_id: &T::AccountId) -> (RequestId, (BlockNumber,OpocLevel)) {
        let mut opoc_assignments = Vec::<(RequestId, (BlockNumber, OpocLevel))>::new();
        let inputs = Inputs::<T>::iter().collect::<Vec<_>>();

        for (request_id, _) in inputs.iter().take(MAX_INPUTS_MANAGED_PER_BLOCK) {
            // Check if the request is assigned to the validator by checking if the request_id is in the OpocAssignment storage
            let has_opoc_assignment = OpocAssignment::<T>::contains_key(*request_id, &account_id);
            if !has_opoc_assignment {
                continue;
            }

            // Be sure request is not already managed by checking if the request_id is in the NodesOutputs storage
            let has_node_output = NodesOutputs::<T>::contains_key(*request_id, &account_id);
            if has_node_output {
                continue;
            }

            // Be sure is not already running on the semaphore
            if semaphore_is_running(*request_id) {
                log::info!("UOMI-ENGINE: Request {:?} is already running on another thread", request_id);
                continue;
            }

            // Read the expiration_block_number from the OpocAssignment storage
            let opoc_assignement_data = OpocAssignment::<T>::get(*request_id, &account_id);

            // Add the request_id and expiration_block_number to the opoc_assignment vector
            opoc_assignments.push((*request_id, opoc_assignement_data));
        }

        // Return zero if no opoc_assignments has been found
        if opoc_assignments.is_empty() {
            return (Default::default(), Default::default());
        }

        // Sort opoc_assignments by expiration block number
        opoc_assignments.sort_by(|a, b| a.1.0.cmp(&b.1.0));

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
            if nft_id == &U256::from(4) { // Agent 4 is a simple agent that read the sender address and return it as output
                let wasm = include_bytes!("./test_agents/agent4.wasm").to_vec();
                return Ok(wasm);
            }
            if nft_id == &U256::from(1312) { // Agent 1312 is the famous uomi whitepaper chat agent
                let wasm = include_bytes!("./test_agents/uomi_whitepaper_chat_agent.wasm").to_vec();
                return Ok(wasm);
            }

            return Err(DispatchError::Other("Error loading the wasm from the NFT ID for tests"));
        }

        match T::IpfsPallet::get_file(nft_file_cid) {
            Ok(wasm) => Ok(wasm),
            Err(error) => {
                log::error!("Error loading the wasm from the NFT ID: {:?}", error);
                Err(DispatchError::Other("Error loading the wasm from the NFT ID"))
            },
        }
    }

    #[cfg(feature = "std")]
    pub fn offchain_run_wasm(wasm: Vec<u8>, input_data: Data, input_file_cid: Cid, address: H160, block_number: BlockNumber, expiration_block_number: BlockNumber, nft_required_consensus: U256, nft_execution_max_time: U256, request_id: RequestId, opoc_level:OpocLevel) -> Result<Data, wasmtime::Error> {
        // Convert input_data to a Vec<u8>
        let input_data_as_vec = input_data.to_vec();
        // Convert address to a Vec<u8>
        let address_as_vec = address.as_bytes().to_vec();

        // Calculate the timeout for the execution of the request
        // The timeout should be calculated as expiration_block_number - start_block
        // If timeout is > nft_execution_max_time - 3, timeout should be nft_execution_max_time - 3
        // NOTE: We calculate time after the wasm loading to avoid the wasm loading time to be counted in the timeout.
        let start_block = U256::from(0) + <frame_system::Pallet<T>>::block_number();
        let timeout_blocks_max = nft_execution_max_time - U256::from(3);
        if expiration_block_number < start_block { // NOTE: This case should never happen, but check to avoid runtime error
            log::error!("UOMI-ENGINE: Expiration block number is before the start block number");
            return Err(wasmtime::Error::new(std::io::Error::new(std::io::ErrorKind::Other, "Expiration block number is before the start block number")));
        }
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
        let engine = match wasmtime::Engine::new(&config) {
            Ok(engine) => engine,
            Err(error) => {
                log::error!("UOMI-ENGINE: Error creating the wasm engine: {:?}", error);
                return Err(error);
            },
        };
        let mut store = wasmtime::Store::new(&engine, HostState::new());
        store.set_epoch_deadline(timeout_time_cs);
        store.epoch_deadline_trap();
        let module = match wasmtime::Module::new(&engine, &wasm) {
            Ok(module) => module,
            Err(error) => {
                log::error!("UOMI-ENGINE: Error loading the wasm module: {:?}", error);
                return Err(error);
            },
        };

        let get_input_data = move |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, _len: i32| {
            let data_to_write = Self::offchain_worker_generate_data_for_wasm(input_data_as_vec.clone());
            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            memory.write(caller, ptr as usize, &data_to_write).expect("Failed to write memory");
        };

        let get_input_file = move |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, _len: i32| {
            let file = match T::IpfsPallet::get_file(&input_file_cid) {
                Ok(file) => file,
                Err(error) => {
                    log::error!("Error getting the file from the IPFS pallet: {:?}", error);
                    Vec::new()
                }
            };
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

        let set_output_transaction = move |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, len: i32| {
            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            let mut buffer = vec![0u8; len as usize];
            memory.read(&caller, ptr as usize, &mut buffer).expect("Failed to read memory");
            *caller.data_mut() = buffer;
        };

        let get_cid_file = move |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, len: i32, output_ptr: i32, _: i32| {
            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            let mut buffer = vec![0u8; len as usize];
            memory.read(&caller, ptr as usize, &mut buffer).expect("Failed to read memory");
            let cid = match Cid::try_from(buffer) {
                Ok(cid) => cid,
                Err(error) => {
                    log::error!("Error converting buffer to CID: {:?}", error);
                    Cid::default()
                }
            };
            let file = match Self::offcahin_worker_get_cid_file(cid, block_number) {
                Ok(file) => file,
                Err(error) => {
                    log::error!("Error getting the file from the IPFS pallet: {:?}", error);
                    Vec::new()
                }
            };
            let data_to_write = Self::offchain_worker_generate_data_for_wasm(file);
            memory.write(caller, output_ptr as usize, &data_to_write).expect("Failed to write memory");
        };

        let get_request_sender = move |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, len: i32| {
            let data_to_write = Self::offchain_worker_generate_data_for_wasm(address_as_vec.clone());
            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            memory.write(caller, ptr as usize, &data_to_write).expect("Failed to write memory");
        };

        let console_log = move |mut caller: wasmtime::Caller<'_, HostState>, _ptr: i32, _len: i32| {
            // Do nothing, function exposed to help wasm debugging
        };

        // NOTE: The call_ai function is "special". It needs to track the number of calls and count them by incrementing a counter.
        // This is required to permit us to log the executions and store them on OpocL0Inferences (on Opoc level 0) or read them from OpocL0Inferences (on Opoc level 1/2).
        let call_ai_counter = std::sync::RwLock::new(0u32);
        let call_ai = move |mut caller: wasmtime::Caller<'_, HostState>, model: i32, ptr: i32, len: i32, output_ptr: i32, _: i32| {
            *call_ai_counter.write().unwrap() += 1;

            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            let mut buffer = vec![0u8; len as usize];
            memory.read(&caller, ptr as usize, &mut buffer).expect("Failed to read memory");
            let model = AiModelKey::from(model as u32);
            let output = match Self::offchain_worker_call_ai(model, block_number, buffer, nft_required_consensus, *call_ai_counter.read().unwrap(), request_id, opoc_level) {
                Ok(output) => output,
                Err(error) => {
                    log::error!("Error calling the AI: {:?}", error);
                    Vec::new()
                }
            };
            let data_to_write = Self::offchain_worker_generate_data_for_wasm(output);
            memory.write(caller, output_ptr as usize, &data_to_write).expect("Failed to write memory");
        };

        // --- New: read_chain_state host function ---
        let read_chain_state = move |mut caller: wasmtime::Caller<'_, HostState>, pallet_ptr: i32, pallet_len: i32, storage_ptr: i32, storage_len: i32, key_ptr: i32, key_len: i32, output_ptr: i32| {
            let memory = caller.get_export("memory").and_then(|x| x.into_memory()).expect("Failed to get memory export");
            let mut pallet_buf = vec![0u8; pallet_len as usize];
            let mut storage_buf = vec![0u8; storage_len as usize];
            let mut key_buf = vec![0u8; key_len as usize];
            memory.read(&caller, pallet_ptr as usize, &mut pallet_buf).expect("Failed to read memory");
            memory.read(&caller, storage_ptr as usize, &mut storage_buf).expect("Failed to read memory");
            memory.read(&caller, key_ptr as usize, &mut key_buf).expect("Failed to read memory");

            let pallet = String::from_utf8_lossy(&pallet_buf).to_string();
            let storage = String::from_utf8_lossy(&storage_buf).to_string();

            let result = Self::offchain_read_chain_state(pallet, storage, key_buf);
            let data_to_write = match result {
                Ok(data) => Self::offchain_worker_generate_data_for_wasm(data),
                Err(_) => Self::offchain_worker_generate_data_for_wasm(vec![]),
            };
            memory.write(caller, output_ptr as usize, &data_to_write).expect("Failed to write memory");
        };
        // --- End new host function ---

        let mut linker = wasmtime::Linker::new(&engine);
        linker.func_wrap("env", "get_input_file", get_input_file).unwrap();
        linker.func_wrap("env", "get_input_data", get_input_data).unwrap();
        linker.func_wrap("env", "set_output", set_output).unwrap();
        linker.func_wrap("env", "set_output_transaction", set_output_transaction).unwrap();
        linker.func_wrap("env", "get_cid_file", get_cid_file).unwrap();
        linker.func_wrap("env", "get_request_sender", get_request_sender).unwrap();
        linker.func_wrap("env", "console_log", console_log).unwrap();
        linker.func_wrap("env", "call_ai", call_ai).unwrap();
        linker.func_wrap("env", "read_chain_state", read_chain_state).unwrap();

        let instance = match linker.instantiate(&mut store, &module) {
            Ok(instance) => instance,
            Err(error) => {
                log::error!("Error instantiating the wasm module: {:?}", error);
                return Err(error);
            }
        };
        let run = match instance.get_typed_func::<(), ()>(&mut store, "run") {
            Ok(run) => run,
            Err(error) => {
                log::error!("Error getting the run function: {:?}", error);
                return Err(error);
            }
        };

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

    fn offchain_worker_generate_data_for_wasm(data: Vec<u8>) -> Vec<u8> {
        let data_len = data.len();
        let mut wasm_data = Vec::new();

        // write data_len on first 4 bytes of wasm_data, then write data
        wasm_data.extend(&(data_len as u32).to_le_bytes());
        wasm_data.extend(data);

        wasm_data
    }

    #[cfg(feature = "std")]
    pub fn offchain_worker_call_ai(model: AiModelKey, block_number: BlockNumber, input: Vec<u8>, required_consensus: U256, counter: u32, request_id: RequestId, opoc_level:OpocLevel) -> Result<Vec<u8>, DispatchError> {
        let request_id_as_string = format!("{:?}", request_id);
            
        if model == AiModelKey::zero() { // Model 0 is a simple model that return the input data inverted used for tests
            let output = input.iter().rev().cloned().collect();
            return Ok(output);
        }

        if model >= U256::from(100) && required_consensus > U256::from(1) { // Models with id > 100 (example image generation) can not be called with security (consensus > 1)
            return Err(DispatchError::Other("Model can not be called by agents with required consensus > 1"));
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

        let input_data = String::from_utf8(input).map_err(|_| {
            log::error!("UOMI-ENGINE: Invalid UTF-8 in input data");
            DispatchError::Other("Invalid UTF-8 in input data")
        })?;

        let model = String::from_utf8(final_local_name.to_vec()).map_err(|_| {
            log::error!("UOMI-ENGINE: Invalid UTF-8 in final local name");
            DispatchError::Other("Invalid UTF-8 in final local name")
        })?;


        if opoc_level == OpocLevel::Level0 { 
            let body_data = CallAiRequestWithoutProof {
                request_id: request_id_as_string,
                model: model.clone(),
                input: input_data.clone(),
            };
            let body = miniserde::json::to_string(&body_data);

            let output = Self::offchain_worker_call_ai_send_request(body)?;
            let output_string = String::from_utf8(output.to_vec()).map_err(|_| {
                log::error!("UOMI-ENGINE: Invalid UTF-8 in output data");
                DispatchError::Other("Invalid UTF-8 in output data")
            })?;
            let output_string = output_string.trim();
            let output_json: CallAiResponse = miniserde::json::from_str(&output_string).map_err(|_| {
                log::error!("UOMI-ENGINE: Error parsing output data to JSON");
                DispatchError::Other("Error parsing output data to JSON")
            })?;
            let output_json_cleaned = CallAiResponseCleaned {
                response: output_json.response,
            };
            let output_string_cleaned = miniserde::json::to_string(&output_json_cleaned);
            let output: Data = output_string_cleaned.as_bytes().to_vec().try_into().map_err(|_| {
                log::error!("UOMI-ENGINE: Failed to convert output to Data type");
                DispatchError::Other("Failed to convert output")
            })?;

            if !output_json.proof.is_empty() { 
                // Store the inference on OpocL0Inferences
                let signer = Signer::<T, T::UomiAuthorityId>::all_accounts();
                if !signer.can_sign() {
                    log::error!("No accounts available to sign the transaction");
                    return Err(DispatchError::Other("No accounts available to sign"));
                }

                // Convert output_proof to a Data
                let output_proof: Data = output_json.proof.as_bytes().to_vec().try_into().map_err(|_| {
                    log::error!("UOMI-ENGINE: Failed to convert output proof to Data type");
                    DispatchError::Other("Failed to convert output proof")
                })?;

                let _ = signer.send_unsigned_transaction(
                    |acct| PayloadNodesOpocL0Inferences { 
                        request_id: request_id.clone(), 
                        inference_index: counter,
                        inference_proof: output_proof.clone(),
                        public: acct.public.clone(),
                    },
                    |payload, signature| Call::store_nodes_opoc_l0_inferences { 
                        payload, 
                        signature 
                    },
                );
            }

            Ok(output.to_vec())
        } else {

            let mut proof: Data = Data::default();
            for (account_id, inference_data) in NodesOpocL0Inferences::<T>::iter_prefix(request_id) { // TODO: On turing, we need to be sure the account_id is the same of the node used on opoc level 0
                let (inference_index, inference_proof) = inference_data;
                if inference_index == counter {
                    let opoc_assignment = OpocAssignment::<T>::try_get(request_id, account_id);
                    if opoc_assignment.is_ok() && opoc_assignment.unwrap().1 == OpocLevel::Level0 {
                        proof = inference_proof;
                        break;
                    }
                }
            }

            if proof.is_empty() {
                log::error!("UOMI-ENGINE: No proof found for request_id {:?} and inference_index {}", request_id, counter);
                return Err(DispatchError::Other("No proof found for the requested inference"));
            }

            let body_data = CallAiRequestWithProof {
                request_id: request_id_as_string,
                model: model.clone(),
                input: input_data.clone(),
                proof: String::from_utf8(proof.to_vec()).unwrap_or_default(),
            };
            let body = miniserde::json::to_string(&body_data);

            let output = Self::offchain_worker_call_ai_send_request(body)?;
            let output_string = String::from_utf8(output.to_vec()).map_err(|_| {
                log::error!("UOMI-ENGINE: Invalid UTF-8 in output data");
                DispatchError::Other("Invalid UTF-8 in output data")
            })?;

            let output_string = output_string.trim();
            let output_json: CallAiResponse = miniserde::json::from_str(&output_string).map_err(|_| {
                log::error!("UOMI-ENGINE: Error parsing output data to JSON");
                DispatchError::Other("Error parsing output data to JSON")
            })?;
            let output_json_cleaned = CallAiResponseCleaned {
                response: output_json.response,
            };
            let output_string_cleaned = miniserde::json::to_string(&output_json_cleaned);
            let output: Data = output_string_cleaned.as_bytes().to_vec().try_into().map_err(|_| {
                log::error!("UOMI-ENGINE: Failed to convert output to Data type");
                DispatchError::Other("Failed to convert output")
            })?;

            Ok(output.to_vec())
        }
    
    }
    
    fn offchain_worker_call_ai_send_request(body: String) -> Result<Data, DispatchError> {
        let url = "http://127.0.0.1:8888/run";

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

        Ok(output)
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

    /// Basically we get one "random" assignment and check the OpocLevel it has
    /// Before we counted them. Both checks are founded on the same premise
    /// i.e. the fact that at each time step there's only one "kind" of assignemt going on
    /// per each reqquest
    fn offchain_detect_opoc_level(request_id: &RequestId, account_id: &T::AccountId) -> Result<OpocLevel, DispatchError> {
        let has_opoc_assignment = OpocAssignment::<T>::contains_key(*request_id, &account_id);
        if !has_opoc_assignment {
            log::error!("UOMI-ENGINE: The request_id is not assigned to the validator");
            return Err(DispatchError::Other("The request_id is not assigned to the validator"));
        }

        let opoc_assignment_data = OpocAssignment::<T>::get(*request_id, &account_id);
        Ok(opoc_assignment_data.1)
    }

    #[cfg(feature = "std")]
    pub fn offchain_read_chain_state(
        pallet: String,
        storage: String,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, DispatchError> {
        // Compose the storage key: Twox128(pallet) ++ Twox128(storage) ++ key
        let mut storage_key = sp_std::vec::Vec::new();
        storage_key.extend(sp_io::hashing::twox_128(pallet.as_bytes()));
        storage_key.extend(sp_io::hashing::twox_128(storage.as_bytes()));
        storage_key.extend(key);
        // Read the storage value
        let value = sp_io::storage::get(&storage_key);
        match value {
            Some(data) => Ok(data.to_vec()),
            None => Err(DispatchError::Other("Chain state not found")),
        }
    }
}