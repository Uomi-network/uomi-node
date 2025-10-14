//! Low-level illustrative EIP-7702 raw transaction submission (manual RLP).
//!
//! This creates an EIP-7702 transaction that authorizes setting code on an EOA.
//! Transaction structure: [chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, authorizationList, accessList]
//!
//! Env overrides:
//!   AUTH_ADDRESS       Address to authorize for code delegation (required for EIP-7702)
//!   RPC_HTTP           RPC endpoint (default http://127.0.0.1:9944)
//!   NONCE              Explicit nonce (decimal) else use remote nonce
//!   GAS_LIMIT          Decimal gas (default 100000)
//!   MAX_FEE            Decimal (default 1_000_000_000)
//!   MAX_PRIORITY_FEE   Decimal (default 1_000_000_000)
//!
//! Run: `AUTH_ADDRESS=0x... cargo run -p uomi --example eip7702_send`

use ethers::{core::types::{Signature, H160, H256, U256}, signers::{LocalWallet, Signer}};
use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use reqwest::blocking::Client;
use serde_json::json;
use std::{env, time::Duration};

const TX_TYPE_7702: u8 = 0x04; // Frontier TxType::EIP7702

fn main() -> eyre::Result<()> {
    let pk = "0x01ab6e801c06e59ca97a14fc0a1978b27fa366fc87450e0b65459dd3515b7391";
    let wallet: LocalWallet = pk.parse()?;
    let from = wallet.address();
    let rpc = env::var("RPC_HTTP").unwrap_or_else(|_| "http://127.0.0.1:9944".into());
    let chain_id = fetch_chain_id(&rpc).unwrap_or(42u64);
    let base_fee_opt = fetch_base_fee(&rpc);
    if let Some(bf) = base_fee_opt { println!(" baseFeePerGas={bf}"); }

    // Fetch current balance (wei) for diagnostics
    let balance_before = fetch_balance(&rpc, format!("0x{:x}", from).as_str());
    if let Some(bal) = balance_before {
        println!(" currentBalanceWei={bal} (~{:.6} ether)", as_eth(bal));
    } else {
        println!(" could_not_fetch_balance");
    }

    // Remote nonce (next transaction count) for diagnostics
    let remote_nonce = fetch_nonce(&rpc, format!("0x{:x}", from).as_str());
    // If NONCE not provided, use remote nonce (instead of always 0)
    let nonce = env::var("NONCE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(U256::from)
        .or_else(|| remote_nonce.map(U256::from))
        .unwrap_or_else(U256::zero);
    let mut max_priority_fee = env::var("MAX_PRIORITY_FEE").ok().and_then(|s| s.parse::<u64>().ok()).map(U256::from).unwrap_or(U256::from(1_000_000_000u64));
    let mut max_fee = env::var("MAX_FEE").ok().and_then(|s| s.parse::<u64>().ok()).map(U256::from).unwrap_or(U256::from(1_000_000_000u64));
    let auto_adjust = env::var("AUTO_ADJUST_GAS").ok().map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(true);
    if let Some(bf) = base_fee_opt {
        // EIP-1559 rule: require max_fee >= base_fee + max_priority_fee
        if max_fee < bf + max_priority_fee {
            if auto_adjust {
                // simple policy: set max_fee to bf * 2 + max_priority_fee (headroom)
                let headroom = bf.checked_mul(U256::from(2u64)).unwrap_or(bf) + max_priority_fee;
                println!(" adjusting max_fee from {} -> {} to satisfy base_fee+priority", max_fee, headroom);
                max_fee = headroom;
                // optionally adjust priority if it's absurdly high relative to base fee
                if max_priority_fee > bf && max_priority_fee > U256::from(5_000_000_000u64) {
                    println!(" capping max_priority_fee {} -> {}", max_priority_fee, bf);
                    max_priority_fee = bf;
                }
            } else {
                eprintln!("WARNING: max_fee {} < base_fee + priority {}. Transaction likely rejected (set AUTO_ADJUST_GAS=1 or raise MAX_FEE).", max_fee, bf + max_priority_fee);
            }
        }
    }
    let gas_limit = env::var("GAS_LIMIT").ok().and_then(|s| s.parse::<u64>().ok()).map(U256::from).unwrap_or(U256::from(100_000u64));
    let value = U256::zero();
    let data: Vec<u8> = vec![]; // input (unused for simple test)

    // Get the address to authorize (required for EIP-7702)
    let auth_address = env::var("AUTH_ADDRESS")
        .ok()
        .and_then(|s| s.trim_start_matches("0x").parse::<H160>().ok())
        .expect("AUTH_ADDRESS env var required (e.g., AUTH_ADDRESS=0x1234...)");

    // Create authorization tuple: [chain_id, address, nonce]
    // For EIP-7702, we need to sign an authorization message and include it
    // For simplicity, we'll use nonce 0 for the authorization
    let auth_nonce = U256::zero();

    // Create the authorization message to sign: keccak256(MAGIC || rlp([chain_id, address, nonce]))
    const MAGIC: u8 = 0x05; // EIP-7702 magic byte
    let mut auth_rlp = RlpStream::new_list(3);
    auth_rlp.append(&U256::from(chain_id));
    auth_rlp.append(&auth_address);
    auth_rlp.append(&auth_nonce);

    let auth_rlp_bytes = auth_rlp.out().to_vec();
    let mut auth_msg = Vec::with_capacity(1 + auth_rlp_bytes.len());
    auth_msg.push(MAGIC);
    auth_msg.extend_from_slice(&auth_rlp_bytes);
    let auth_hash = keccak(&auth_msg);

    // Sign the authorization
    let auth_sig: Signature = wallet.sign_hash(auth_hash.into())?;
    let auth_y_parity: u8 = (auth_sig.v - 27) as u8;

    // Unsigned payload list length = 10
    let mut payload = RlpStream::new_list(10);
    payload.append(&U256::from(chain_id)); // 0 chainId
    payload.append(&nonce);                // 1 nonce
    payload.append(&max_priority_fee);     // 2 maxPriorityFeePerGas
    payload.append(&max_fee);              // 3 maxFeePerGas
    payload.append(&gas_limit);            // 4 gasLimit
    payload.append(&from);                 // 5 to (self)
    payload.append(&value);                // 6 value
    payload.append(&data);                 // 7 data

    // 8 authorization list - single authorization
    payload.begin_list(1); // List of 1 authorization
    payload.begin_list(5); // Authorization tuple: [chain_id, address, nonce, y_parity, r, s]
    payload.append(&U256::from(chain_id));
    payload.append(&auth_address);
    payload.append(&auth_nonce);
    payload.append(&auth_y_parity);
    payload.append(&auth_sig.r);
    payload.append(&auth_sig.s);

    payload.begin_list(0);                 // 9 accessList [] (empty)

    let unsigned_bytes = payload.out().to_vec();
    let mut to_hash = Vec::with_capacity(1 + unsigned_bytes.len());
    to_hash.push(TX_TYPE_7702);
    to_hash.extend_from_slice(&unsigned_bytes);
    let sighash = keccak(&to_hash);
    let sig: Signature = wallet.sign_hash(sighash.into())?;
    let y_parity: u8 = (sig.v - 27) as u8; // normalize to 0/1

    // Signed list has unsigned_len + 3 = 13 elements.
    let mut signed = RlpStream::new_list(13);
    let rlp_unsigned = rlp::Rlp::new(&unsigned_bytes);
    for i in 0..rlp_unsigned.item_count().unwrap() {
        signed.append_raw(rlp_unsigned.at(i).unwrap().as_raw(), 1);
    }
    signed.append(&y_parity);
    signed.append(&sig.r);
    signed.append(&sig.s);

    let final_body = signed.out().to_vec();
    let mut full = Vec::with_capacity(1 + final_body.len());
    full.push(TX_TYPE_7702);
    full.extend_from_slice(&final_body);
    let raw_hex = format!("0x{}", hex::encode(&full));
    println!("Raw EIP-7702 tx (13 fields signed): {raw_hex}");
    if let Some(rn) = remote_nonce { println!(" remoteNonce(network)={rn}"); }
    // Upfront gas prepayment per EIP-1559 rules is gas_limit * max_fee + value
    let required_upfront = gas_limit * max_fee + value;
    println!(" chainId={chain_id} from=0x{:x} nonce={} gas={} value={} authAddr=0x{:x} authYParity={} yParity={} maxFee={} maxPrio={} baseFee={} requiredPrepay={} (~{:.6} ether)",
        from, nonce, gas_limit, value, auth_address, auth_y_parity, y_parity, max_fee, max_priority_fee, base_fee_opt.unwrap_or_default(), required_upfront, as_eth(required_upfront));
    if let Some(bal) = balance_before {
        if bal < required_upfront {
            println!(" WARNING: balance < gas_limit * max_fee ({} < {}) -> will trigger insufficient funds", bal, required_upfront);
        }
    }

    match Client::builder().timeout(Duration::from_secs(10)).build() {
        Ok(client) => {
            let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[raw_hex]});
            match client.post(&rpc).json(&body).send() {
                Ok(resp) => match resp.text() { Ok(t) => println!("Response: {t}"), Err(e) => eprintln!("Read body err: {e}") },
                Err(e) => eprintln!("RPC send error (non-fatal): {e}"),
            }
            // Optional: basic signature recovery check (ethers built-in)
            if let Ok(recovered) = sig.recover(sighash) {
                if recovered != from { println!(" WARNING: recovered address 0x{:x} != from 0x{:x}", recovered, from); }
            }
        }
        Err(e) => eprintln!("HTTP client build failed: {e}"),
    }
    Ok(())
}

fn fetch_chain_id(rpc: &str) -> Option<u64> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]});
    let client = Client::builder().timeout(Duration::from_secs(4)).build().ok()?;
    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: serde_json::Value = resp.json().ok()?;
    v.get("result").and_then(|r| r.as_str()).and_then(|hex_id| u64::from_str_radix(hex_id.trim_start_matches("0x"), 16).ok())
}

fn fetch_base_fee(rpc: &str) -> Option<U256> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest", false]});
    let client = Client::builder().timeout(Duration::from_secs(4)).build().ok()?;
    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: serde_json::Value = resp.json().ok()?;
    let bf_hex = v.get("result")?.get("baseFeePerGas")?.as_str()?;
    u64::from_str_radix(bf_hex.trim_start_matches("0x"),16).ok().map(U256::from)
}

fn keccak(data: &[u8]) -> H256 { H256::from_slice(Keccak256::digest(data).as_slice()) }

fn fetch_balance(rpc: &str, addr: &str) -> Option<U256> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[addr, "latest"]});
    let client = Client::builder().timeout(Duration::from_secs(4)).build().ok()?;
    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: serde_json::Value = resp.json().ok()?;
    let hex_bal = v.get("result")?.as_str()?;
    U256::from_str_radix(hex_bal.trim_start_matches("0x"), 16).ok()
}

fn as_eth(wei: U256) -> f64 {
    // crude conversion for logging only (lossy if very large)
    const WEI_IN_ETH: f64 = 1e18;
    // Convert lower 128 bits to f64 (sufficient for diagnostic scale here)
    let low = (wei & U256::from(u128::MAX)).low_u128() as f64;
    low / WEI_IN_ETH
}

fn fetch_nonce(rpc: &str, addr: &str) -> Option<u64> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":[addr, "latest"]});
    let client = Client::builder().timeout(Duration::from_secs(4)).build().ok()?;
    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: serde_json::Value = resp.json().ok()?;
    let hex_nonce = v.get("result")?.as_str()?;
    u64::from_str_radix(hex_nonce.trim_start_matches("0x"), 16).ok()
}

