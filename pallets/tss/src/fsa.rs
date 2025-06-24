use sp_std::collections::btree_map::BTreeMap;
use sp_std::prelude::*;
use sp_std::vec::Vec;
use crate::{Config, LastOpocRequestId};
use miniserde::Deserialize;


/// Errors that can occur when processing OPOC requests
#[derive(Debug)]
pub enum ProcessingError {
    /// No requests to sign were found
    NoRequestsFound,
    /// Failed to parse output for a specific request ID
    ParseError(u32),
    /// Invalid action type
    UnsupportedActionType(String),
}

impl ProcessingError {
    fn as_str(&self) -> &'static str {
        match self {
            ProcessingError::NoRequestsFound => "No requests to sign found",
            ProcessingError::ParseError(_) => "Failed to parse output",
            ProcessingError::UnsupportedActionType(_) => "Unsupported action type",
        }
    }
}

// Define the struct for the deserialized output
#[derive(Deserialize, Debug)]
pub struct Action {
    action_type: String,
    _trigger_policy: String,
    data: Vec<u8>,
    chain_id: u32,
}

#[derive(Deserialize, Debug)]
pub struct Output {
    actions: Vec<Action>,
    _response: String,
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
    fn process_single_request(request_id: u32) -> Result<Option<(u32, Vec<u8>)>, ProcessingError> {
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
        "transaction" => Ok(handle_transaction_action(data, chain_id)),
        unsupported => {
            log::warn!("Unsupported action type: {}", unsupported);
            Err(ProcessingError::UnsupportedActionType(String::from(unsupported)))
        }
    }
}

/// Handle transaction actions
fn handle_transaction_action(data: Vec<u8>, chain_id: u32) -> Option<(u32, Vec<u8>)> {
    log::info!(
        "Handling transaction action with {} bytes of data on chain ID: {}",
        data.len(),
        chain_id
    );

    // For now, the transaction action means we need to trigger the TSS signature
    // for this agent and the given data. We prepare the data to submit from the
    // offchain worker, with the NFT id and the data needed by create_signing_session
    
    // TODO: Implement proper chain_id handling and validation
    Some((chain_id, data))
}