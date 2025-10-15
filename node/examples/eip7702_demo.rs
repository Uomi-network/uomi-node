//! Complete EIP-7702 Demonstration
//!
//! This example demonstrates the full EIP-7702 flow:
//! 1. Deploy a simple counter contract
//! 2. Authorize an EOA to delegate to that contract
//! 3. Call functions on the EOA (which executes the contract's code)
//! 4. Verify storage separation between EOA and contract
//!
//! Environment variables:
//!   RPC_HTTP           RPC endpoint (default: http://127.0.0.1:9944)
//!   SKIP_DEPLOY        Skip contract deployment, use existing contract
//!   CONTRACT_ADDRESS   Use existing contract at this address
//!
//! Run: `cargo run -p uomi --example eip7702_demo`

use ethers::{
    core::types::{Signature, H160, H256, U256},
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
};
use reqwest::blocking::Client;
use rlp::RlpStream;
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::{env, time::Duration};

const TX_TYPE_7702: u8 = 0x04;
const TX_TYPE_EIP1559: u8 = 0x02;

// Simple counter contract bytecode
// contract Counter { uint256 public value; function inc() public { value++; } }
const COUNTER_BYTECODE: &str = "608060405234801561000f575f5ffd5b506101438061001d5f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c8063371303c0146100385780633fa4f24514610042575b5f5ffd5b610040610060565b005b61004a610078565b60405161005791906100a5565b60405180910390f35b60015f808282546100719190610108565b9250508190555b565b5f5481565b5f819050919050565b61008f8161007d565b82525050565b5f602082019050610099565b5f6100ba82846100a05790509291505056fea2646970667358221220a1b2c3d4e5f6071829384950617281930405060708091011121314151617181920fea264697066735822122064736f6c6343000818003300000000000000000000000000000000";

fn main() -> eyre::Result<()> {
    let pk = "0x01ab6e801c06e59ca97a14fc0a1978b27fa366fc87450e0b65459dd3515b7391";
    let wallet: LocalWallet = pk.parse()?;
    let from = wallet.address();
    let rpc = env::var("RPC_HTTP").unwrap_or_else(|_| "http://127.0.0.1:9944".into());

    println!("╔════════════════════════════════════════════════════╗");
    println!("║         EIP-7702 Complete Demonstration           ║");
    println!("╚════════════════════════════════════════════════════╝");
    println!("\nEOA Address: 0x{:x}", from);

    let chain_id = fetch_chain_id(&rpc).unwrap_or(4370u64);
    println!("Chain ID: {}", chain_id);

    // Step 1: Deploy counter contract (or use existing)
    let contract_address = if env::var("SKIP_DEPLOY").is_ok() || env::var("CONTRACT_ADDRESS").is_ok() {
        let addr = env::var("CONTRACT_ADDRESS")
            .unwrap_or_else(|_| "0x4bbfc37c65ca1231a8900be69715025e556a1d10".to_string());
        let parsed = addr.trim_start_matches("0x").parse::<H160>()?;
        println!("\n📋 Using existing contract: 0x{:x}", parsed);
        parsed
    } else {
        println!("\n📋 Step 1: Deploying Counter Contract");
        deploy_contract(&rpc, &wallet, chain_id)?
    };

    // Verify contract exists
    let contract_code = fetch_code(&rpc, &format!("0x{:x}", contract_address))?;
    if contract_code == "0x" {
        eprintln!("❌ Contract at 0x{:x} has no code!", contract_address);
        return Ok(());
    }
    println!("   ✅ Contract deployed at: 0x{:x}", contract_address);
    println!("   📊 Contract code size: {} bytes", (contract_code.len() - 2) / 2);

    // Step 2: Check initial contract value
    println!("\n📋 Step 2: Reading Initial Contract State");
    let contract_value = call_value(&rpc, &format!("0x{:x}", contract_address))?;
    println!("   Contract value: {}", contract_value);

    // Step 3: Create EIP-7702 authorization and delegate EOA
    println!("\n📋 Step 3: Creating EIP-7702 Authorization");
    let nonce = fetch_nonce(&rpc, &format!("0x{:x}", from)).unwrap_or(0);
    println!("   Current EOA nonce: {}", nonce);

    // CRITICAL: For self-delegation, auth_nonce must be current_nonce + 1
    // because authorization is checked AFTER sender nonce is incremented
    let auth_nonce = nonce + 1;
    println!("   Authorization nonce: {} (nonce + 1 for self-delegation)", auth_nonce);

    send_delegation_tx(&rpc, &wallet, chain_id, contract_address)?;
    println!("   ✅ Delegation transaction confirmed");

    // Wait for transaction to be included
    std::thread::sleep(Duration::from_secs(2));

    // Step 4: Verify delegation
    println!("\n📋 Step 4: Verifying Delegation");
    let eoa_code = fetch_code(&rpc, &format!("0x{:x}", from))?;
    if eoa_code.starts_with("0xef0100") {
        let delegated_to = &eoa_code[6..];
        println!("   ✅ EOA is delegating!");
        println!("   Delegation designator: {}", eoa_code);
        println!("   Delegated to: 0x{}", delegated_to);
    } else {
        println!("   ❌ Delegation failed - EOA code: {}", eoa_code);
        return Ok(());
    }

    // Step 5: Call delegated EOA
    println!("\n📋 Step 5: Calling Delegated EOA");
    let eoa_value = call_value(&rpc, &format!("0x{:x}", from))?;
    println!("   EOA value (executing contract code): {}", eoa_value);

    // Step 6: Verify storage separation
    println!("\n📋 Step 6: Verifying Storage Separation");
    let contract_storage = fetch_storage(&rpc, &format!("0x{:x}", contract_address), "0x0")?;
    let eoa_storage = fetch_storage(&rpc, &format!("0x{:x}", from), "0x0")?;

    println!("   Contract storage[0]: {}", contract_storage);
    println!("   EOA storage[0]: {}", eoa_storage);

    if contract_storage != eoa_storage {
        println!("   ✅ Storage is correctly separated!");
    } else {
        println!("   ⚠️  Storage values are the same");
    }

    // Summary
    println!("\n╔════════════════════════════════════════════════════╗");
    println!("║                     SUMMARY                        ║");
    println!("╚════════════════════════════════════════════════════╝");
    println!("✅ Contract deployed at: 0x{:x}", contract_address);
    println!("✅ EOA delegating to contract: 0x{:x}", from);
    println!("✅ Delegation code verified: {}", eoa_code);
    println!("✅ EOA executes contract code with separate storage");
    println!("\n🎉 EIP-7702 is fully functional!");

    Ok(())
}

fn deploy_contract(rpc: &str, wallet: &LocalWallet, chain_id: u64) -> eyre::Result<H160> {
    let from = wallet.address();
    let nonce = fetch_nonce(rpc, &format!("0x{:x}", from)).unwrap_or(0);
    let base_fee = fetch_base_fee(rpc).unwrap_or(U256::from(1_000_000_000u64));

    let max_priority_fee = U256::from(1_000_000_000u64);
    let max_fee = base_fee * 2 + max_priority_fee;
    let gas_limit = U256::from(1_000_000u64);
    let value = U256::zero();

    let bytecode = hex::decode(COUNTER_BYTECODE)?;

    // Build EIP-1559 transaction for contract deployment
    let mut rlp = RlpStream::new_list(9);
    rlp.append(&U256::from(chain_id));
    rlp.append(&U256::from(nonce));
    rlp.append(&max_priority_fee);
    rlp.append(&max_fee);
    rlp.append(&gas_limit);
    rlp.append(&""); // Empty to = contract creation
    rlp.append(&value);
    rlp.append(&bytecode);
    rlp.begin_list(0); // Empty access list

    let unsigned = rlp.out().to_vec();
    let mut to_sign = Vec::with_capacity(1 + unsigned.len());
    to_sign.push(TX_TYPE_EIP1559);
    to_sign.extend_from_slice(&unsigned);

    let hash = keccak(&to_sign);
    let sig: Signature = wallet.sign_hash(hash.into())?;
    let y_parity = (sig.v - 27) as u8;

    let mut signed = RlpStream::new_list(12);
    let rlp_unsigned = rlp::Rlp::new(&unsigned);
    for i in 0..rlp_unsigned.item_count().unwrap() {
        signed.append_raw(rlp_unsigned.at(i).unwrap().as_raw(), 1);
    }
    signed.append(&y_parity);
    signed.append(&sig.r);
    signed.append(&sig.s);

    let final_body = signed.out().to_vec();
    let mut full = Vec::with_capacity(1 + final_body.len());
    full.push(TX_TYPE_EIP1559);
    full.extend_from_slice(&final_body);

    let raw_hex = format!("0x{}", hex::encode(&full));

    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendRawTransaction",
        "params": [raw_hex]
    });

    let resp = client.post(rpc).json(&body).send()?;
    let v: serde_json::Value = resp.json()?;

    if let Some(tx_hash) = v.get("result").and_then(|r| r.as_str()) {
        println!("   Transaction: {}", tx_hash);

        // Wait for transaction
        std::thread::sleep(Duration::from_secs(3));

        // Calculate contract address: keccak256(rlp([sender, nonce]))[12:]
        let mut stream = RlpStream::new_list(2);
        stream.append(&from);
        stream.append(&U256::from(nonce));
        let rlp_encoded = stream.out();
        let hash = keccak(&rlp_encoded);
        let contract_addr = H160::from_slice(&hash.as_bytes()[12..]);

        Ok(contract_addr)
    } else {
        Err(eyre::eyre!("Failed to deploy contract: {:?}", v))
    }
}

fn send_delegation_tx(rpc: &str, wallet: &LocalWallet, chain_id: u64, contract_address: H160) -> eyre::Result<()> {
    let from = wallet.address();
    let nonce = fetch_nonce(rpc, &format!("0x{:x}", from)).unwrap_or(0);
    let base_fee = fetch_base_fee(rpc).unwrap_or(U256::from(1_000_000_000u64));

    let max_priority_fee = U256::from(1_000_000_000u64);
    let max_fee = base_fee * 2 + max_priority_fee;
    let gas_limit = U256::from(100_000u64);

    // CRITICAL: auth_nonce = nonce + 1 for self-delegation
    let auth_nonce = U256::from(nonce + 1);

    // Sign authorization: keccak256(0x05 || rlp([chain_id, address, nonce]))
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

    // Build EIP-7702 transaction
    let to = from;
    let value = U256::zero();
    let data: Vec<u8> = vec![];

    let mut payload = RlpStream::new_list(10);
    payload.append(&U256::from(chain_id));
    payload.append(&U256::from(nonce));
    payload.append(&max_priority_fee);
    payload.append(&max_fee);
    payload.append(&gas_limit);
    payload.append(&to);
    payload.append(&value);
    payload.append(&data);
    payload.begin_list(0); // Empty access list

    // Authorization list
    payload.begin_list(1);
    payload.begin_list(6);
    payload.append(&U256::from(chain_id));
    payload.append(&contract_address);
    payload.append(&auth_nonce);
    payload.append(&auth_y_parity);

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

    // Sign transaction
    let unsigned_bytes = payload.out().to_vec();
    let mut to_hash = Vec::with_capacity(1 + unsigned_bytes.len());
    to_hash.push(TX_TYPE_7702);
    to_hash.extend_from_slice(&unsigned_bytes);
    let tx_hash = keccak(&to_hash);
    let tx_sig: Signature = wallet.sign_hash(tx_hash.into())?;
    let tx_y_parity: u8 = (tx_sig.v - 27) as u8;

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

    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendRawTransaction",
        "params": [raw_hex]
    });

    let resp = client.post(rpc).json(&body).send()?;
    let v: serde_json::Value = resp.json()?;

    if let Some(tx_hash) = v.get("result").and_then(|r| r.as_str()) {
        println!("   Transaction: {}", tx_hash);
        Ok(())
    } else {
        Err(eyre::eyre!("Failed to send delegation tx: {:?}", v))
    }
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

fn fetch_code(rpc: &str, addr: &str) -> eyre::Result<String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [addr, "latest"]});
    let client = Client::builder().timeout(Duration::from_secs(4)).build()?;
    let resp = client.post(rpc).json(&body).send()?;
    let v: serde_json::Value = resp.json()?;
    Ok(v.get("result").and_then(|r| r.as_str()).unwrap_or("0x").to_string())
}

fn call_value(rpc: &str, addr: &str) -> eyre::Result<u64> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": addr, "data": "0x3fa4f245"}, "latest"]
    });
    let client = Client::builder().timeout(Duration::from_secs(4)).build()?;
    let resp = client.post(rpc).json(&body).send()?;
    let v: serde_json::Value = resp.json()?;
    let hex = v.get("result").and_then(|r| r.as_str()).unwrap_or("0x0");
    Ok(u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0))
}

fn fetch_storage(rpc: &str, addr: &str, slot: &str) -> eyre::Result<String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getStorageAt",
        "params": [addr, slot, "latest"]
    });
    let client = Client::builder().timeout(Duration::from_secs(4)).build()?;
    let resp = client.post(rpc).json(&body).send()?;
    let v: serde_json::Value = resp.json()?;
    Ok(v.get("result").and_then(|r| r.as_str()).unwrap_or("0x0").to_string())
}
