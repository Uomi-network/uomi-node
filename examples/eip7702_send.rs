//! Canonical-style raw EIP-7702 tx example (single authorization byte array, no list-of-delegates).
//! Mirrors the node example; kept in root `examples/` for quick diff / experimentation.
use ethers::{core::types::{Signature, H256, U256}, signers::{LocalWallet, Signer}};
use rlp::RlpStream;
use reqwest::blocking::Client;
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::{env, time::Duration};

const TX_TYPE_7702: u8 = 0x04;

fn main() -> eyre::Result<()> {
    let pk = "0x01ab6e801c06e59ca97a14fc0a1978b27fa366fc87450e0b65459dd3515b7391";
    let wallet: LocalWallet = pk.parse()?;
    let rpc = env::var("RPC_HTTP").unwrap_or_else(|_| "http://127.0.0.1:9944".into());
    let chain_id = fetch_chain_id(&rpc).unwrap_or(42u64);

    let nonce = U256::zero();
    let max_priority_fee = U256::from(1_000_000_000u64);
    let max_fee = U256::from(1_000_000_000u64);
    let gas_limit = U256::from(500_000u64);
    let value = U256::zero();
    let data: Vec<u8> = vec![];
    let auth_code: Vec<u8> = vec![]; // empty ephemeral code placeholder

    let mut payload = RlpStream::new_list(10);
    payload.append(&U256::from(chain_id));
    payload.append(&nonce);
    payload.append(&max_priority_fee);
    payload.append(&max_fee);
    payload.append(&gas_limit);
    payload.append(&"");
    payload.append(&value);
    payload.append(&data);
    payload.append(&auth_code);
    payload.begin_list(0);

    let unsigned = payload.out().to_vec();
    let mut to_hash = Vec::with_capacity(1 + unsigned.len());
    to_hash.push(TX_TYPE_7702);
    to_hash.extend_from_slice(&unsigned);
    let sighash = keccak(&to_hash);
    let sig: Signature = wallet.sign_hash(sighash.into())?;
    let y_parity: u8 = (sig.v - 27) as u8;

    let mut signed = RlpStream::new_list(13);
    let r = rlp::Rlp::new(&unsigned);
    for i in 0..r.item_count().unwrap() { signed.append_raw(r.at(i).unwrap().as_raw(), 1); }
    signed.append(&y_parity);
    signed.append(&sig.r);
    signed.append(&sig.s);

    let final_body = signed.out().to_vec();
    let mut full = Vec::with_capacity(1 + final_body.len());
    full.push(TX_TYPE_7702);
    full.extend_from_slice(&final_body);
    let raw_hex = format!("0x{}", hex::encode(full));
    println!("Raw 7702 tx: {raw_hex}");

    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
    let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[raw_hex]});
    let resp = client.post(&rpc).json(&body).send()?;
    println!("RPC response: {}", resp.text()?);
    Ok(())
}

fn fetch_chain_id(rpc: &str) -> Option<u64> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]});
    let client = Client::builder().timeout(Duration::from_secs(4)).build().ok()?;
    let resp = client.post(rpc).json(&body).send().ok()?;
    let v: serde_json::Value = resp.json().ok()?;
    v.get("result").and_then(|r| r.as_str()).and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok())
}

fn keccak(data: &[u8]) -> H256 { H256::from_slice(Keccak256::digest(data).as_slice()) }
