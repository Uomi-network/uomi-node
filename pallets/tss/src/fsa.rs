use sp_std::collections::btree_map::BTreeMap;
use sp_std::prelude::*;
use sp_std::vec::Vec;
use sp_core::U256;
use scale_info::prelude::string::String;
use crate::{Config, LastOpocRequestId, DkgSessions, AggregatedPublicKeys};
use sp_io::hashing::keccak_256;
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
    /// No output found for a specific request ID
    NoOutputFound,
}

impl ProcessingError {
    fn as_str(&self) -> &'static str {
        match self {
            ProcessingError::NoRequestsFound => "No requests to sign found",
            ProcessingError::ParseError(_) => "Failed to parse output",
            ProcessingError::UnsupportedActionType(_) => "Unsupported action type",
            ProcessingError::MultiChainError(msg) => msg,
            ProcessingError::ChainConfigError(msg) => msg,
            ProcessingError::NoOutputFound => "No output found for request ID",
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
    /// Destination address (hex, 0x-prefixed)
    pub to: Option<String>,
    /// Sender address (hex, 0x-prefixed) – needed for nonce & gas estimation when nonce not supplied
    pub from: Option<String>,
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
                Err(ProcessingError::NoOutputFound) => {
                    log::warn!("No output found for request ID {:?}", current);
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

        // if Outputs does not contain the request_id, return None
        if output.is_empty() {
            log::warn!("No output found for request ID {:?}", request_id);
            return Err(ProcessingError::NoOutputFound);
        }

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
        for mut action in output.actions {
            // Attempt to auto-derive sender (from) if missing using aggregated public key associated with nft_id
            if action.from.is_none() {
                // Convert U256 nft_id -> bounded vec (same as elsewhere: little-endian limbs -> bytes)
                if let Ok(nft_bv) = {
                    let bytes: Vec<u8> = nft_id.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
                    crate::types::NftId::try_from(bytes)
                } {
                    if let Some(from_addr) = derive_from_address::<T>(nft_bv) {
                        action.from = Some(from_addr);
                    }
                }
            }

            log::info!("Processing action for request {:?}: {:?}", request_id, action);

            if let Some(data) = handle_action(&action)? {
                return Ok(Some((nft_id, data)));
            }
        }

        Ok(None)
    }
}

/// Derive an Ethereum address (hex 0x...) from the aggregated public key linked to an NFT id via DKG session.
/// Steps:
/// 1. Find DKG session whose `nft_id` matches.
/// 2. Fetch aggregated public key bytes from `AggregatedPublicKeys` storage using session id.
/// 3. Normalize key to 64-byte uncompressed form (strip 0x04 prefix if 65 bytes).
/// 4. keccak256(pubkey[0..64]) and take last 20 bytes -> H160.
/// 5. Return hex string 0x + lowercase.
fn derive_from_address<T: Config>(nft_id: crate::types::NftId) -> Option<String> {
    // Find session id with this nft_id (linear scan; could be optimized with reverse index later)
    let mut found_session: Option<crate::types::SessionId> = None;
    for (sid, sess) in DkgSessions::<T>::iter() { if sess.nft_id == nft_id { found_session = Some(sid); break; } }
    let session_id = found_session?;
    let pubkey = AggregatedPublicKeys::<T>::get(session_id)?; // BoundedVec<u8>
    let key_bytes: Vec<u8> = pubkey.to_vec();
    let slice = key_bytes.as_slice();
    // Accept 64 (raw x||y) or 65 (0x04||x||y). Reject others.
    let raw = if slice.len() == 65 && slice[0] == 0x04 { &slice[1..] } else { slice };
    if raw.len() != 64 { return None; }
    let hash = keccak_256(raw);
    let addr_bytes = &hash[12..]; // last 20 bytes
    // hex encode
    let mut out = String::from("0x");
    const HEX: &[u8;16] = b"0123456789abcdef";
    for b in addr_bytes { out.push(HEX[(b>>4) as usize] as char); out.push(HEX[(b & 0x0f) as usize] as char); }
    Some(out)
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
        // Helper wrappers so unit tests (non-offchain context) don't invoke offchain RPC APIs and panic.
        #[cfg(test)]
        fn try_fetch_gas_price(_chain_id: u32) -> Option<u64> { None }
        #[cfg(not(test))]
        fn try_fetch_gas_price(chain_id: u32) -> Option<u64> {
            MultiChainRpcClient::get_chain_config(chain_id).ok()
                .and_then(|cfg| MultiChainRpcClient::get_gas_price(&cfg).ok())
        }
        #[cfg(test)]
        fn try_estimate_gas(_chain_id: u32, _from: &str, _to: &str, _value: Option<u64>, _data: &[u8]) -> Option<u64> { None }
        #[cfg(not(test))]
        fn try_estimate_gas(chain_id: u32, from: &str, to: &str, value: Option<u64>, data: &[u8]) -> Option<u64> {
            MultiChainRpcClient::get_chain_config(chain_id).ok()
                .and_then(|cfg| MultiChainRpcClient::estimate_gas(&cfg, from, to, value, Some(data)).ok())
        }
        #[cfg(test)]
        fn try_fetch_nonce(_chain_id: u32, _from: &str) -> Option<u64> { None }
        #[cfg(not(test))]
        fn try_fetch_nonce(chain_id: u32, from: &str) -> Option<u64> {
            MultiChainRpcClient::get_chain_config(chain_id).ok()
                .and_then(|cfg| MultiChainRpcClient::get_account_nonce(&cfg, from).ok())
        }
        let value = action.value.as_ref().and_then(|v| parse_num_u64("value", v)).unwrap_or(0);

        // Dynamic RPC-derived fields (with safe fallbacks if unavailable / errors)
        // gas_price / max fees
        let mut rpc_gas_price: Option<u64> = None;
        if action.gas_price.is_none() || action.tx_type.as_deref().map(|t| t.eq_ignore_ascii_case("eip1559")).unwrap_or(true) {
            rpc_gas_price = try_fetch_gas_price(action.chain_id);
        }
        let gas_price = action.gas_price.as_ref()
            .and_then(|v| parse_num_u64("gas_price", v))
            .or(rpc_gas_price)
            .unwrap_or(1_000_000_000); // fallback 1 gwei

        // gas_limit (estimate if not provided)
        let mut rpc_gas_limit: Option<u64> = None;
        if action.gas_limit.is_none() {
            // if let Some(ref from_addr) = action.from {
            //     rpc_gas_limit = try_estimate_gas(action.chain_id, from_addr, to, action.value.as_ref().and_then(|v| parse_num_u64("value", v)), &data_bytes);
            // }
            rpc_gas_limit = Some(25_000); // todo: fix.
        }
        let gas_limit = action.gas_limit.as_ref().and_then(|v| parse_num_u64("gas_limit", v)).or(rpc_gas_limit).unwrap_or(21_000);

        // nonce (query if not provided)
        let mut rpc_nonce: Option<u64> = None;
        if action.nonce.is_none() {
            if let Some(ref from_addr) = action.from {
                rpc_nonce = try_fetch_nonce(action.chain_id, from_addr);
            }
        }
        let nonce = action.nonce.as_ref().and_then(|v| parse_num_u64("nonce", v)).or(rpc_nonce).unwrap_or(0);

        let tx_type = action.tx_type.as_deref().unwrap_or("eip1559");

        log::info!("[tx build] chain={} to={} from={:?} nonce={} gas_limit={} gas_price={} (provided: gp? {} gl? {} n? {})", 
            action.chain_id, to, action.from, nonce, gas_limit, gas_price,
            action.gas_price.is_some(), action.gas_limit.is_some(), action.nonce.is_some());

        let build_res = if tx_type.eq_ignore_ascii_case("eip1559") {
            // Derive max fees: prefer explicit fields; else use gas_price as both (simple heuristic)
            let max_fee = action.max_fee_per_gas.as_ref().and_then(|v| parse_num_u64("max_fee_per_gas", v)).unwrap_or(gas_price);
            let max_priority = action.max_priority_fee_per_gas.as_ref().and_then(|v| parse_num_u64("max_priority_fee_per_gas", v))
                .unwrap_or_else(|| core::cmp::min(gas_price, 1_000_000_000));
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