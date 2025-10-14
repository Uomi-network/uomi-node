//! Verify EIP-7702 delegation by checking account code
//!
//! This script checks if an EOA has delegated code set via EIP-7702.
//! According to EIP-7702, when delegation is active, the account's code
//! should be a special delegation designator.
//!
//! Env overrides:
//!   ACCOUNT_ADDRESS    Address to check for delegation (default: test wallet)
//!   RPC_HTTP           RPC endpoint (default http://127.0.0.1:9944)
//!
//! Run: `cargo run -p uomi --example verify_delegation`

use ethers::core::types::H160;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::{env, time::Duration};

fn main() -> eyre::Result<()> {
    let rpc = env::var("RPC_HTTP").unwrap_or_else(|_| "http://127.0.0.1:9944".into());

    // Default to the test wallet address
    let default_addr = "0xaaafb3972b05630fccee866ec69cdadd9bac2771";
    let account = env::var("ACCOUNT_ADDRESS").unwrap_or_else(|_| default_addr.into());

    println!("=== EIP-7702 Delegation Verification ===");
    println!("Account: {}", account);
    println!("RPC: {}\n", rpc);

    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

    // Get account code
    println!("Fetching account code...");
    let code = get_code(&client, &rpc, &account);

    match code {
        Some(code_hex) => {
            println!("Code: {}", code_hex);
            println!("Code length: {} bytes", (code_hex.len() - 2) / 2);

            // EIP-7702 delegation designator starts with 0xef0100
            // The format is: 0xef0100 || <20-byte address>
            if code_hex.starts_with("0xef0100") {
                println!("\n✅ DELEGATION DETECTED!");

                if code_hex.len() >= 46 { // 0x (2) + ef0100 (6) + address (40) = 48
                    let delegated_to = &code_hex[8..48]; // Skip "0xef0100"
                    println!("   Delegated to: 0x{}", delegated_to);

                    // Verify the delegated contract exists
                    println!("\nVerifying delegated contract...");
                    let delegated_code = get_code(&client, &rpc, &format!("0x{}", delegated_to));
                    match delegated_code {
                        Some(dc) if dc != "0x" => {
                            println!("✅ Delegated contract exists");
                            println!("   Contract code size: {} bytes", (dc.len() - 2) / 2);

                            // Show first few bytes of contract code
                            if dc.len() > 34 {
                                println!("   Contract code starts with: {}...", &dc[0..34]);
                            }
                        }
                        _ => println!("⚠️  Delegated contract has no code or doesn't exist"),
                    }
                } else {
                    println!("⚠️  Delegation marker found but address is missing or truncated");
                }
            } else if code_hex == "0x" {
                println!("\n❌ NO DELEGATION");
                println!("   Account has no code (regular EOA)");
            } else {
                println!("\n⚠️  UNEXPECTED CODE");
                println!("   Account has code but not EIP-7702 delegation marker");
                println!("   This might be a regular smart contract");
            }
        }
        None => {
            println!("❌ Failed to fetch account code");
        }
    }

    // Also check account balance and nonce for completeness
    println!("\n=== Account Details ===");
    if let Some(balance) = get_balance(&client, &rpc, &account) {
        println!("Balance: {} wei ({:.6} ether)", balance, wei_to_eth(&balance));
    }
    if let Some(nonce) = get_nonce(&client, &rpc, &account) {
        println!("Nonce: {}", nonce);
    }

    Ok(())
}

fn get_code(client: &Client, rpc: &str, address: &str) -> Option<String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getCode",
        "params": [address, "latest"]
    });

    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: Value = resp.json().ok()?;
    v.get("result").and_then(|c| c.as_str()).map(|s| s.to_string())
}

fn get_balance(client: &Client, rpc: &str, address: &str) -> Option<String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBalance",
        "params": [address, "latest"]
    });

    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: Value = resp.json().ok()?;
    v.get("result").and_then(|b| b.as_str()).map(|s| s.to_string())
}

fn get_nonce(client: &Client, rpc: &str, address: &str) -> Option<u64> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionCount",
        "params": [address, "latest"]
    });

    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: Value = resp.json().ok()?;
    let hex_nonce = v.get("result")?.as_str()?;
    u64::from_str_radix(hex_nonce.trim_start_matches("0x"), 16).ok()
}

fn wei_to_eth(wei_hex: &str) -> f64 {
    if let Ok(wei_u128) = u128::from_str_radix(wei_hex.trim_start_matches("0x"), 16) {
        wei_u128 as f64 / 1e18
    } else {
        0.0
    }
}
