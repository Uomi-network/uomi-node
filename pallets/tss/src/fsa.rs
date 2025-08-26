use sp_std::collections::btree_map::BTreeMap;
use sp_std::prelude::*;
use sp_std::vec::Vec;
use sp_core::U256;
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
    ParseError(U256),
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
    pub _trigger_policy: Option<String>,
    /// Hex string representing call data (e.g. "0x", "0xdeadbeef").
    /// For consistency we ALWAYS expect a string now (not a JSON array of bytes).
    pub data: String,
    pub chain_id: u32,
    // Additional fields for enhanced transaction support
    pub to: Option<String>,
    pub value: Option<String>,
    pub gas_limit: Option<String>,
    pub gas_price: Option<String>,
    // Extended optional fields for richer tx construction
    pub nonce: Option<String>,
    pub tx_type: Option<String>,                 // "legacy" (default) or "eip1559"
    pub max_fee_per_gas: Option<String>,         // For EIP-1559
    pub max_priority_fee_per_gas: Option<String>,// For EIP-1559
}

#[derive(Deserialize, Debug)]
pub struct Output {
    pub actions: Vec<Action>,
    // pub _response: String,
}   


impl<T: Config> crate::pallet::Pallet<T> {
    /// Process OPOC (Off-chain Processing Output Consumer) requests
    /// Fetches and processes outputs from pallet_uomi_engine starting from the last processed request ID
    /// Returns a tuple of (requests_to_sign, last_processed_request_id as U256) for offchain processing
    pub fn process_opoc_requests() -> Result<(BTreeMap<U256, (U256, u32, Vec<u8>)>, U256), &'static str> {
        let last_opoc_request_id = LastOpocRequestId::<T>::get();
        let mut requests_to_sign = BTreeMap::<U256, (U256, u32, Vec<u8>)>::new();
        let mut current = last_opoc_request_id.saturating_add(U256::one());
        let mut last_processed = last_opoc_request_id;

        if last_opoc_request_id.is_zero() { log::info!("No previous OPOC request ID found, starting from ID 1"); }

        for _ in 0..10u8 { // process at most 10 per cycle
            match Self::process_single_request(current) {
                Ok(Some((nft_id, data))) => {
                    requests_to_sign.insert(current, (nft_id, data.0, data.1));
                    last_processed = current;
                }
                Ok(None) => {
                    // Treat as processed even if no actionable action
                    last_processed = current;
                }
                Err(e) => {
                    log::warn!("Failed to process request ID {:?}: {:?}", current, e);
                    break; // stop on hard error
                }
            }
            current = current.saturating_add(U256::one());
        }
        if requests_to_sign.is_empty() { return Err("No requests to sign found"); }
        Ok((requests_to_sign, last_processed))
    }

    /// Process a single OPOC request
    pub fn process_single_request(request_id: U256) -> Result<Option<(U256, (u32, Vec<u8>))>, ProcessingError> {
        // Fetch the output for this request ID directly using U256
        let (output, _, _, nft_id) = pallet_uomi_engine::Outputs::<T>::get(request_id);

        log::info!("Processing output for request ID {:?}", request_id);

        // Convert output from a bounded vec to a string
        let output_string = output
            .into_inner()
            .into_iter()
            .map(|x| x as char)
            .collect::<String>();

        // Parse the output using miniserde
        let output = match miniserde::json::from_str::<Output>(&output_string) {
            Ok(o) => o,
            Err(_) => {
                // Parsing failures are non-fatal for an individual request; we just skip it.
                log::warn!("Failed to parse output for request ID {:?}", request_id);
                return Ok(None);
            }
        };

        // Process all actions in the successfully parsed output
        for action in output.actions {
            log::info!("Processing action for request {:?}: {:?}", request_id, action);

            if let Some(data) = handle_action(&action)? {
                return Ok(Some((nft_id, data)));
            }
        }

        Ok(None)
    }
}


/// Handle an action, potentially constructing a transaction preimage from structured fields.
fn handle_action(action: &Action) -> Result<Option<(u32, Vec<u8>)>, ProcessingError> {
    match action.action_type.as_str() {
        "transaction" | "multi_chain_transaction" => build_or_passthrough(action),
        unsupported => {
            log::warn!("Unsupported action type: {}", unsupported);
            Err(ProcessingError::UnsupportedActionType("Unsupported action type"))
        }
    }
}

fn parse_num_u64(label: &str, v: &str) -> Option<u64> {
    let s = v.trim();
    if s.is_empty() { return None; }
    let (radix, digits) = if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (16, stripped)
    } else { (10, s) };
    match u64::from_str_radix(digits, radix) {
        Ok(n) => Some(n),
        Err(_) => {
            log::warn!("Failed to parse {} value '{}'", label, v);
            None
        }
    }
}

fn build_or_passthrough(action: &Action) -> Result<Option<(u32, Vec<u8>)>, ProcessingError> {
    // Always validate chain config first
    let chain_config = MultiChainRpcClient::get_chain_config(action.chain_id)
        .map_err(|e| ProcessingError::ChainConfigError(e))?;
    MultiChainRpcClient::validate_chain_config(&chain_config)
        .map_err(|e| ProcessingError::ChainConfigError(e))?;

    // Decode hex string data -> bytes (tolerate missing 0x prefix). On error use empty vec.
    fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
        let clean = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        if clean.is_empty() { return Ok(Vec::new()); }
        if clean.len() % 2 != 0 { return Err(()); }
        let mut out = Vec::with_capacity(clean.len()/2);
        let bytes = clean.as_bytes();
        let hex_val = |c: u8| -> Option<u8> {
            match c { b'0'..=b'9' => Some(c - b'0'), b'a'..=b'f' => Some(10 + c - b'a'), b'A'..=b'F' => Some(10 + c - b'A'), _ => None }
        };
        let mut i = 0;
        while i < bytes.len() { 
            let hi = hex_val(bytes[i]).ok_or(())?; 
            let lo = hex_val(bytes[i+1]).ok_or(())?; 
            out.push((hi<<4) | lo); 
            i += 2; 
        }
        Ok(out)
    }
    let data_bytes = match decode_hex(&action.data) { Ok(v) => v, Err(_) => { log::warn!("Invalid hex in action.data '{}', using empty bytes", action.data); Vec::new() } };

    // If we have structured fields, attempt to construct a preimage; otherwise fallback to raw data
    if let Some(ref to) = action.to {
        use crate::multichain::TransactionBuilder;
        let value = action.value.as_ref().and_then(|v| parse_num_u64("value", v)).unwrap_or(0);
        let gas_limit = action.gas_limit.as_ref().and_then(|v| parse_num_u64("gas_limit", v)).unwrap_or(21_000);
        let gas_price = action.gas_price.as_ref().and_then(|v| parse_num_u64("gas_price", v)).unwrap_or(1_000_000_000); // 1 gwei default
        let nonce = action.nonce.as_ref().and_then(|v| parse_num_u64("nonce", v)).unwrap_or(0);
        let tx_type = action.tx_type.as_deref().unwrap_or("eip1559");

        let build_res = if tx_type.eq_ignore_ascii_case("eip1559") {
            let max_fee = action.max_fee_per_gas.as_ref().and_then(|v| parse_num_u64("max_fee_per_gas", v)).unwrap_or(gas_price);
            let max_priority = action.max_priority_fee_per_gas.as_ref().and_then(|v| parse_num_u64("max_priority_fee_per_gas", v)).unwrap_or(1_000_000_000);
            TransactionBuilder::build_eip1559_transaction(
                to,
                value,
                &data_bytes,
                gas_limit,
                max_fee,
                max_priority,
                nonce,
                action.chain_id,
            )
        } else {
            TransactionBuilder::build_ethereum_transaction(
                to,
                value,
                &data_bytes,
                gas_limit,
                gas_price,
                nonce,
                action.chain_id,
            )
        };

        match build_res {
            Ok(preimage) => {
                log::info!("Constructed {} transaction preimage ({} bytes) for chain {}", tx_type, preimage.len(), action.chain_id);
                return Ok(Some((action.chain_id, preimage)));
            }
            Err(e) => {
                log::warn!("Failed to build structured transaction ({}). Falling back to raw data ({} bytes)", e, data_bytes.len());
                return Ok(Some((action.chain_id, data_bytes)));
            }
        }
    }

    // No structured fields; treat provided data as preimage bytes directly
    Ok(Some((action.chain_id, data_bytes)))
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