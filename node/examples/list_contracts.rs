//! List all deployed contracts by querying eth_getLogs for contract creation events
//!
//! Env overrides:
//!   RPC_HTTP        RPC endpoint (default http://127.0.0.1:9944)
//!   FROM_BLOCK      Starting block number in hex (default "0x0")
//!   TO_BLOCK        Ending block number in hex (default "latest")
//!
//! Run: `cargo run -p uomi --example list_contracts`

use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::{env, time::Duration};

fn main() -> eyre::Result<()> {
    let rpc = env::var("RPC_HTTP").unwrap_or_else(|_| "http://127.0.0.1:9944".into());
    let from_block = env::var("FROM_BLOCK").unwrap_or_else(|_| "0x0".into());
    let to_block = env::var("TO_BLOCK").unwrap_or_else(|_| "latest".into());

    println!("Scanning for contracts from block {} to {}", from_block, to_block);

    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;

    // Get current block number
    let chain_id = fetch_chain_id(&client, &rpc).unwrap_or(0);
    let current_block = fetch_block_number(&client, &rpc).unwrap_or(0);
    println!("Chain ID: {}", chain_id);
    println!("Current block: {}\n", current_block);

    // Method 1: Scan blocks for contract creations
    println!("=== Scanning blocks for contract creations ===");

    let from = if from_block == "latest" {
        current_block
    } else if from_block.starts_with("0x") {
        u64::from_str_radix(from_block.trim_start_matches("0x"), 16).unwrap_or(0)
    } else {
        from_block.parse().unwrap_or(0)
    };

    let to = if to_block == "latest" {
        current_block
    } else if to_block.starts_with("0x") {
        u64::from_str_radix(to_block.trim_start_matches("0x"), 16).unwrap_or(current_block)
    } else {
        to_block.parse().unwrap_or(current_block)
    };

    let mut contracts = Vec::new();

    for block_num in from..=to.min(current_block) {
        let block_hex = format!("0x{:x}", block_num);

        // Get block with full transaction details
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBlockByNumber",
            "params": [block_hex, true]
        });

        if let Ok(resp) = client.post(&rpc).json(&body).send() {
            if let Ok(v) = resp.json::<Value>() {
                if let Some(block) = v.get("result") {
                    if let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) {
                        for tx in txs {
                            // Contract creation has null 'to' field
                            if tx.get("to").and_then(|t| t.as_str()).is_none() ||
                               tx.get("to").map(|t| t.is_null()).unwrap_or(false) {

                                let hash = tx.get("hash").and_then(|h| h.as_str()).unwrap_or("unknown");
                                let from = tx.get("from").and_then(|f| f.as_str()).unwrap_or("unknown");

                                // Get transaction receipt to find contract address
                                if let Some(contract_addr) = get_contract_address(&client, &rpc, hash) {
                                    contracts.push((block_num, hash.to_string(), from.to_string(), contract_addr));
                                }
                            }
                        }
                    }
                }
            }
        }

        if block_num % 100 == 0 && block_num > from {
            println!("Scanned up to block {}", block_num);
        }
    }

    println!("\n=== Found {} contracts ===", contracts.len());
    for (block, tx_hash, deployer, contract_addr) in &contracts {
        println!("Block: {} | Contract: {} | Deployer: {} | Tx: {}",
                 block, contract_addr, deployer, tx_hash);

        // Try to get code to verify it's actually a contract
        if let Some(code_size) = get_code_size(&client, &rpc, contract_addr) {
            println!("  Code size: {} bytes", code_size);
        }
    }

    Ok(())
}

fn fetch_chain_id(client: &Client, rpc: &str) -> Option<u64> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []});
    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: Value = resp.json().ok()?;
    v.get("result")
        .and_then(|r| r.as_str())
        .and_then(|hex_id| u64::from_str_radix(hex_id.trim_start_matches("0x"), 16).ok())
}

fn fetch_block_number(client: &Client, rpc: &str) -> Option<u64> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []});
    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: Value = resp.json().ok()?;
    v.get("result")
        .and_then(|r| r.as_str())
        .and_then(|hex| u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok())
}

fn get_contract_address(client: &Client, rpc: &str, tx_hash: &str) -> Option<String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash]
    });

    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: Value = resp.json().ok()?;
    v.get("result")
        .and_then(|r| r.get("contractAddress"))
        .and_then(|addr| addr.as_str())
        .map(|s| s.to_string())
}

fn get_code_size(client: &Client, rpc: &str, address: &str) -> Option<usize> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getCode",
        "params": [address, "latest"]
    });

    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: Value = resp.json().ok()?;
    let code = v.get("result").and_then(|c| c.as_str())?;

    // Subtract "0x" prefix and divide by 2 (2 hex chars = 1 byte)
    Some((code.len() - 2) / 2)
}
