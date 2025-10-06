//! Check transaction receipt details
//!
//! Env overrides:
//!   TX_HASH     Transaction hash to check
//!   RPC_HTTP    RPC endpoint (default http://127.0.0.1:9944)
//!
//! Run: `TX_HASH=0x... cargo run -p uomi --example check_tx_receipt`

use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::{env, time::Duration};

fn main() -> eyre::Result<()> {
    let rpc = env::var("RPC_HTTP").unwrap_or_else(|_| "http://127.0.0.1:9944".into());
    let tx_hash = env::var("TX_HASH")
        .unwrap_or_else(|_| "0x599055cbd8c6c0b0261ff3ac2fcef3329df8e07c3a6daaf8f9ca42ddab139a96".into());

    println!("=== Transaction Receipt ===");
    println!("TX: {}", tx_hash);
    println!("RPC: {}\n", rpc);

    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

    // Get transaction receipt
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash]
    });

    let resp = client.post(&rpc).json(&body).send()?;
    let v: Value = resp.json()?;

    if let Some(result) = v.get("result") {
        if result.is_null() {
            println!("❌ Transaction not found or pending");
            return Ok(());
        }

        println!("Receipt found:");
        println!("{}", serde_json::to_string_pretty(result)?);

        // Extract key fields
        if let Some(status) = result.get("status").and_then(|s| s.as_str()) {
            let status_value = u64::from_str_radix(status.trim_start_matches("0x"), 16).unwrap_or(0);
            if status_value == 1 {
                println!("\n✅ Transaction succeeded (status: {})", status);
            } else {
                println!("\n❌ Transaction failed (status: {})", status);
            }
        }

        if let Some(gas_used) = result.get("gasUsed").and_then(|g| g.as_str()) {
            let gas = u64::from_str_radix(gas_used.trim_start_matches("0x"), 16).unwrap_or(0);
            println!("Gas used: {}", gas);
        }

        if let Some(logs) = result.get("logs").and_then(|l| l.as_array()) {
            println!("Logs count: {}", logs.len());
            for (i, log) in logs.iter().enumerate() {
                println!("\nLog {}:", i);
                println!("  {}", serde_json::to_string_pretty(log)?);
            }
        }
    } else if let Some(error) = v.get("error") {
        println!("❌ Error: {}", error);
    }

    Ok(())
}
