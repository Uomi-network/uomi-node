//! Simple EIP-7702 test: Deploy a simple contract, then authorize EOA to use it
//!
//! This example:
//! 1. Deploys a simple storage contract (or uses existing one)
//! 2. Creates an EIP-7702 authorization to delegate to that contract
//! 3. Sends a transaction to test the delegation
//!
//! Env overrides:
//!   CONTRACT_ADDRESS   Use existing contract (skip deployment)
//!   RPC_HTTP           RPC endpoint (default http://127.0.0.1:9944)
//!
//! Run: `cargo run -p uomi --example test_eip7702`

use ethers::{
    abi::Abi,
    contract::Contract,
    core::types::{Signature, H160, H256, TransactionRequest, U256},
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
};
use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use reqwest::blocking::Client;
use serde_json::json;
use std::{env, sync::Arc, time::Duration};

const TX_TYPE_7702: u8 = 0x04;

fn main() -> eyre::Result<()> {
    let pk = "0x01ab6e801c06e59ca97a14fc0a1978b27fa366fc87450e0b65459dd3515b7391";
    let wallet: LocalWallet = pk.parse()?;
    let from = wallet.address();
    let rpc = env::var("RPC_HTTP").unwrap_or_else(|_| "http://127.0.0.1:9944".into());

    println!("=== EIP-7702 Test ===");
    println!("Account: 0x{:x}", from);

    // Step 1: Get or deploy a simple contract
    let contract_address = if let Ok(addr) = env::var("CONTRACT_ADDRESS") {
        let parsed = addr.trim_start_matches("0x").parse::<H160>()?;
        println!("Using existing contract: 0x{:x}", parsed);
        parsed
    } else {
        println!("\nNo CONTRACT_ADDRESS provided. Using existing contract from your chain:");
        println!("CONTRACT_ADDRESS=0xf9decfbad1b8d0cb5cc08f936013580aeb87e7e8");
        "0xf9decfbad1b8d0cb5cc08f936013580aeb87e7e8".parse::<H160>()?
    };

    // Step 2: Create EIP-7702 transaction
    println!("\n=== Creating EIP-7702 Transaction ===");

    let chain_id = fetch_chain_id(&rpc).unwrap_or(4370u64);
    let nonce = fetch_nonce(&rpc, format!("0x{:x}", from).as_str()).unwrap_or(0);
    let base_fee = fetch_base_fee(&rpc).unwrap_or(U256::from(1_000_000_000u64));

    println!("Chain ID: {}", chain_id);
    println!("Nonce: {}", nonce);
    println!("Base Fee: {}", base_fee);

    let max_priority_fee = U256::from(1_000_000_000u64);
    let max_fee = base_fee * 2 + max_priority_fee;
    let gas_limit = U256::from(100_000u64);

    // Create authorization for the contract
    // Authorization tuple: [chain_id, address, nonce]
    // CRITICAL: Per EIP-7702, authorization is checked AFTER sender nonce is incremented
    // For self-delegation (caller == authorizing_address), use nonce + 1
    let auth_nonce = U256::from(nonce + 1);

    println!("\nCreating authorization:");
    println!("  Contract to delegate: 0x{:x}", contract_address);
    println!("  Authorization nonce: {}", auth_nonce);

    // Sign the authorization: keccak256(MAGIC || rlp([chain_id, address, nonce]))
    const MAGIC: u8 = 0x05;
    let mut auth_rlp = RlpStream::new_list(3);
    auth_rlp.append(&U256::from(chain_id));
    auth_rlp.append(&contract_address);
    auth_rlp.append(&auth_nonce);

    let auth_rlp_bytes = auth_rlp.out().to_vec();
    let mut auth_msg = Vec::with_capacity(1 + auth_rlp_bytes.len());
    auth_msg.push(MAGIC);
    auth_msg.extend_from_slice(&auth_rlp_bytes);
    let auth_hash = keccak(&auth_msg);

    let auth_sig: Signature = wallet.sign_hash(auth_hash.into())?;
    let auth_y_parity: u8 = (auth_sig.v - 27) as u8;

    println!("  Signature y_parity: {}", auth_y_parity);
    println!("  Signature r: 0x{:x}", auth_sig.r);
    println!("  Signature s: 0x{:x}", auth_sig.s);

    // Build the transaction
    // IMPORTANT: Field order is [chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList, authList]
    // Note: accessList comes BEFORE authList!
    let to = from; // Send to self (which will now act as the contract)
    let value = U256::zero();
    let data: Vec<u8> = vec![]; // Could call a function here

    let mut payload = RlpStream::new_list(10);
    payload.append(&U256::from(chain_id));
    payload.append(&U256::from(nonce));
    payload.append(&max_priority_fee);
    payload.append(&max_fee);
    payload.append(&gas_limit);
    payload.append(&to);
    payload.append(&value);
    payload.append(&data);

    // Access list (empty) - comes BEFORE authorization list
    payload.begin_list(0);

    // Authorization list - comes AFTER access list
    payload.begin_list(1); // 1 authorization
    payload.begin_list(6); // [chain_id, address, nonce, y_parity, r, s] - 6 fields!
    payload.append(&U256::from(chain_id));
    payload.append(&contract_address);
    payload.append(&auth_nonce);
    payload.append(&auth_y_parity);
    // ethers::Signature has r and s as H256 (32 bytes)
    let r_u256 = {
        let mut bytes = [0u8; 32];
        auth_sig.r.to_big_endian(&mut bytes);
        U256::from_big_endian(&bytes)
    };
    let s_u256 = {
        let mut bytes = [0u8; 32];
        auth_sig.s.to_big_endian(&mut bytes);
        U256::from_big_endian(&bytes)
    };
    payload.append(&r_u256);
    payload.append(&s_u256);

    // Sign the transaction
    let unsigned_bytes = payload.out().to_vec();
    let mut to_hash = Vec::with_capacity(1 + unsigned_bytes.len());
    to_hash.push(TX_TYPE_7702);
    to_hash.extend_from_slice(&unsigned_bytes);
    let tx_hash = keccak(&to_hash);
    let tx_sig: Signature = wallet.sign_hash(tx_hash.into())?;
    let tx_y_parity: u8 = (tx_sig.v - 27) as u8;

    // Build signed transaction
    let mut signed = RlpStream::new_list(13);
    let rlp_unsigned = rlp::Rlp::new(&unsigned_bytes);
    for i in 0..rlp_unsigned.item_count().unwrap() {
        signed.append_raw(rlp_unsigned.at(i).unwrap().as_raw(), 1);
    }
    signed.append(&tx_y_parity);
    signed.append(&tx_sig.r);
    signed.append(&tx_sig.s);

    let final_body = signed.out().to_vec();
    let mut full = Vec::with_capacity(1 + final_body.len());
    full.push(TX_TYPE_7702);
    full.extend_from_slice(&final_body);
    let raw_hex = format!("0x{}", hex::encode(&full));

    println!("\n=== Sending Transaction ===");
    println!("Raw transaction: {}", raw_hex);
    println!("Transaction signature y_parity: {}", tx_y_parity);

    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendRawTransaction",
        "params": [raw_hex]
    });

    match client.post(&rpc).json(&body).send() {
        Ok(resp) => {
            match resp.text() {
                Ok(text) => {
                    println!("\n=== Response ===");
                    println!("{}", text);

                    // Parse to check for success
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(result) = v.get("result") {
                            println!("\n✅ SUCCESS! Transaction hash: {}", result);
                        } else if let Some(error) = v.get("error") {
                            println!("\n❌ ERROR: {}", error);
                        }
                    }
                }
                Err(e) => eprintln!("Failed to read response: {}", e),
            }
        }
        Err(e) => eprintln!("Failed to send request: {}", e),
    }

    Ok(())
}

fn keccak(data: &[u8]) -> H256 {
    H256::from_slice(Keccak256::digest(data).as_slice())
}

fn fetch_chain_id(rpc: &str) -> Option<u64> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []});
    let client = Client::builder().timeout(Duration::from_secs(4)).build().ok()?;
    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: serde_json::Value = resp.json().ok()?;
    v.get("result")
        .and_then(|r| r.as_str())
        .and_then(|hex_id| u64::from_str_radix(hex_id.trim_start_matches("0x"), 16).ok())
}

fn fetch_base_fee(rpc: &str) -> Option<U256> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber", "params": ["latest", false]});
    let client = Client::builder().timeout(Duration::from_secs(4)).build().ok()?;
    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: serde_json::Value = resp.json().ok()?;
    let bf_hex = v.get("result")?.get("baseFeePerGas")?.as_str()?;
    u64::from_str_radix(bf_hex.trim_start_matches("0x"), 16).ok().map(U256::from)
}

fn fetch_nonce(rpc: &str, addr: &str) -> Option<u64> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount", "params": [addr, "latest"]});
    let client = Client::builder().timeout(Duration::from_secs(4)).build().ok()?;
    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: serde_json::Value = resp.json().ok()?;
    let hex_nonce = v.get("result")?.as_str()?;
    u64::from_str_radix(hex_nonce.trim_start_matches("0x"), 16).ok()
}
