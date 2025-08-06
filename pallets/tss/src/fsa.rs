use sp_std::collections::btree_map::BTreeMap;
use sp_std::prelude::*;
use sp_std::vec::Vec;
use scale_info::prelude::string::String;
use crate::{Config, LastOpocRequestId};
use crate::multichain::MultiChainRpcClient;
use crate::types::RpcResponse;
use miniserde::Deserialize;


/// Errors that can occur when processing OPOC requests
#[derive(Debug)]
pub enum ProcessingError {
    /// No requests to sign were found
    NoRequestsFound,
    /// Failed to parse output for a specific request ID
    ParseError(u32),
    /// Invalid action type
    UnsupportedActionType(&'static str),
    /// Multi-chain transaction error
    MultiChainError(&'static str),
    /// Chain configuration error
    ChainConfigError(&'static str),
}

impl ProcessingError {
    fn as_str(&self) -> &'static str {
        match self {
            ProcessingError::NoRequestsFound => "No requests to sign found",
            ProcessingError::ParseError(_) => "Failed to parse output",
            ProcessingError::UnsupportedActionType(_) => "Unsupported action type",
            ProcessingError::MultiChainError(msg) => msg,
            ProcessingError::ChainConfigError(msg) => msg,
        }
    }
}

// Define the struct for the deserialized output
#[derive(Deserialize, Debug)]
pub struct Action {
    pub action_type: String,
    pub _trigger_policy: String,
    pub data: Vec<u8>,
    pub chain_id: u32,
    // Additional fields for enhanced transaction support
    pub to: Option<String>,
    pub value: Option<String>,
    pub gas_limit: Option<String>,
    pub gas_price: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Output {
    pub actions: Vec<Action>,
    pub _response: String,
}   


impl<T: Config> crate::pallet::Pallet<T> {
    /// Process OPOC (Off-chain Processing Output Consumer) requests
    /// Fetches and processes outputs from pallet_uomi_engine starting from the last processed request ID
    /// Returns a tuple of (requests_to_sign, last_processed_request_id) for on-chain processing
    pub fn process_opoc_requests() -> Result<(BTreeMap<sp_core::U256, (u32, Vec<u8>)>, u32), &'static str> {
        // Get the last opoc request id we handled in the previous block
        let last_opoc_request_id = LastOpocRequestId::<T>::get();
        let mut requests_to_sign = BTreeMap::<sp_core::U256, (u32, Vec<u8>)>::new();
        let mut last_processed_id = last_opoc_request_id;

        // Only process if we have a valid starting point
        if last_opoc_request_id == 0 {
            log::info!("No previous OPOC request ID found, starting from ID 1");
        }

        // Process up to 10 requests per block to avoid overwhelming the system
        let start_request_id = last_opoc_request_id + 1;
        let max_request_id = start_request_id + 9; // Process 10 requests max

        for request_id in start_request_id..=max_request_id {
            match Self::process_single_request(request_id) {
                Ok(Some(data)) => {
                    requests_to_sign.insert(sp_core::U256::from(request_id), data);
                    last_processed_id = request_id;
                }
                Ok(None) => {
                    // No action needed for this request, but still track the processed ID
                    last_processed_id = request_id;
                }
                Err(e) => {
                    log::warn!("Failed to process request ID {}: {:?}", request_id, e);
                    // Stop processing on error, don't update the processed ID
                    break;
                }
            }
        }

        if requests_to_sign.is_empty() {
            log::info!("No requests to sign found, last processed ID: {}", last_processed_id);
            return Err("No requests to sign found");
        }

        log::info!("Successfully processed {} requests to sign, last processed ID: {}", 
                  requests_to_sign.len(), last_processed_id);
        Ok((requests_to_sign, last_processed_id))
    }

    /// Process a single OPOC request
    pub fn process_single_request(request_id: u32) -> Result<Option<(u32, Vec<u8>)>, ProcessingError> {
        // Fetch the output for this request ID
        let (output, _, _) = pallet_uomi_engine::Outputs::<T>::get(sp_core::U256::from(request_id));
        
        log::info!("Processing output for request ID {}", request_id);

        // Convert output from a bounded vec to a string
        let output_string = output
            .into_inner()
            .into_iter()
            .map(|x| x as char)
            .collect::<String>();

        // Parse the output using miniserde
        let parsed_output = miniserde::json::from_str::<Output>(&output_string)
            .map_err(|_| ProcessingError::ParseError(request_id))?;

        // Process all actions in the output
        for action in parsed_output.actions {
            log::info!("Processing action: {:?}", action);

            if let Some(data) = handle_action_type(&action.action_type, action.data, action.chain_id)? {
                return Ok(Some(data));
            }
        }

        Ok(None)
    }
}


/// Handle different action types
fn handle_action_type(
    action_type: &str,
    data: Vec<u8>,
    chain_id: u32,
) -> Result<Option<(u32, Vec<u8>)>, ProcessingError> {
    match action_type {
        "transaction" => handle_transaction_action(data, chain_id),
        "multi_chain_transaction" => handle_multi_chain_transaction(data, chain_id),
        unsupported => {
            log::warn!("Unsupported action type: {}", unsupported);
            Err(ProcessingError::UnsupportedActionType("Unsupported action type"))
        }
    }
}

/// Handle transaction actions
fn handle_transaction_action(data: Vec<u8>, chain_id: u32) -> Result<Option<(u32, Vec<u8>)>, ProcessingError> {
    log::info!(
        "Handling transaction action with {} bytes of data on chain ID: {}",
        data.len(),
        chain_id
    );

    // Validate chain configuration
    let chain_config = MultiChainRpcClient::get_chain_config(chain_id)
        .map_err(|e| ProcessingError::ChainConfigError(e))?;
    
    MultiChainRpcClient::validate_chain_config(&chain_config)
        .map_err(|e| ProcessingError::ChainConfigError(e))?;

    log::info!(
        "Transaction will be processed on chain: {} (ID: {})",
        String::from_utf8_lossy(&chain_config.name),
        chain_config.chain_id
    );

    // For now, the transaction action means we need to trigger the TSS signature
    // for this agent and the given data. We prepare the data to submit from the
    // offchain worker, with the NFT id and the data needed by create_signing_session
    
    Ok(Some((chain_id, data)))
}

/// Handle multi-chain transaction actions with enhanced functionality
fn handle_multi_chain_transaction(data: Vec<u8>, chain_id: u32) -> Result<Option<(u32, Vec<u8>)>, ProcessingError> {
    log::info!(
        "Handling multi-chain transaction with {} bytes of data on chain ID: {}",
        data.len(),
        chain_id
    );

    // Get chain configuration
    let chain_config = MultiChainRpcClient::get_chain_config(chain_id)
        .map_err(|e| ProcessingError::ChainConfigError(e))?;
    
    // Validate chain configuration
    MultiChainRpcClient::validate_chain_config(&chain_config)
        .map_err(|e| ProcessingError::ChainConfigError(e))?;

    // Parse transaction data if it's in a structured format
    // For now, we'll assume the data contains the raw transaction bytes
    let processed_data = process_transaction_data(&data, &chain_config)?;

    log::info!(
        "Multi-chain transaction prepared for chain: {} (ID: {}), data size: {} bytes",
        String::from_utf8_lossy(&chain_config.name),
        chain_config.chain_id,
        processed_data.len()
    );

    Ok(Some((chain_id, processed_data)))
}

/// Process transaction data for specific chain requirements
fn process_transaction_data(
    data: &[u8],
    chain_config: &crate::types::ChainConfig,
) -> Result<Vec<u8>, ProcessingError> {
    // Different chains might require different data formats
    match chain_config.chain_id {
        1 | 56 | 137 | 43114 | 42161 | 10 | 250 => {
            // Ethereum-compatible chains
            process_ethereum_transaction_data(data, chain_config)
        }
        _ => {
            log::warn!("Unsupported chain ID for transaction processing: {}", chain_config.chain_id);
            Err(ProcessingError::MultiChainError("Unsupported chain for transaction processing"))
        }
    }
}

/// Process transaction data for Ethereum-compatible chains
fn process_ethereum_transaction_data(
    data: &[u8],
    chain_config: &crate::types::ChainConfig,
) -> Result<Vec<u8>, ProcessingError> {
    log::info!(
        "Processing Ethereum-compatible transaction data for chain: {}",
        String::from_utf8_lossy(&chain_config.name)
    );

    // For now, we'll pass through the data as-is
    // In a real implementation, this could:
    // 1. Parse the transaction parameters
    // 2. Validate gas limits and prices
    // 3. Apply chain-specific adjustments
    // 4. Re-encode the transaction
    
    Ok(data.to_vec())
}

/// Submit a signed transaction to the appropriate chain
pub fn submit_transaction_to_chain(
    chain_id: u32,
    signed_transaction: &[u8],
) -> Result<RpcResponse, ProcessingError> {
    // Get chain configuration
    let chain_config = MultiChainRpcClient::get_chain_config(chain_id)
        .map_err(|e| ProcessingError::ChainConfigError(e))?;

    // Submit transaction via RPC
    let response = MultiChainRpcClient::send_transaction(&chain_config, signed_transaction)
        .map_err(|e| ProcessingError::MultiChainError(e))?;

    log::info!(
        "Transaction submitted to chain {} with status: {:?}",
        String::from_utf8_lossy(&chain_config.name),
        response.status
    );

    Ok(response)
}

/// Check transaction status on a specific chain
pub fn check_transaction_status(
    chain_id: u32,
    tx_hash: &str,
) -> Result<RpcResponse, ProcessingError> {
    let chain_config = MultiChainRpcClient::get_chain_config(chain_id)
        .map_err(|e| ProcessingError::ChainConfigError(e))?;

    let response = MultiChainRpcClient::get_transaction_receipt(&chain_config, tx_hash)
        .map_err(|e| ProcessingError::MultiChainError(e))?;

    log::info!(
        "Transaction status check for {} on chain {}: {:?}",
        tx_hash,
        String::from_utf8_lossy(&chain_config.name),
        response.status
    );

    Ok(response)
}