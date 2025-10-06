//! Minimal raw EIP-1559 (type 0x02) transaction sender for control testing against the EIP-7702 path.
//! Fields (unsigned): [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]
//! Then: yParity, r, s.
//! Env:
//!   RPC_HTTP (default http://127.0.0.1:9944)
//!   NONCE (decimal) if provided else fetch from network
//!   GAS_LIMIT (default 21000)
//!   MAX_FEE (default 1_000_000_000 then auto raised to base_fee*2+priority if AUTO_ADJUST_GAS=1)
//!   MAX_PRIORITY_FEE (default 1_000_000_000)
//!   TO (hex 0x..; default self-call)
//!   VALUE (decimal wei, default 0)
//!   AUTO_ADJUST_GAS=1 to enable base fee headroom logic (default on)
//!
//! Use this to verify that the account balance + nonce are accepted for standard type-2 txs. If this works while
//! the 7702 example fails with "insufficient funds" the issue is isolated to the 7702 variant decoding/fee logic.

use ethers::{core::types::{Signature, H256, U256, Address}, signers::{LocalWallet, Signer}};
use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use serde_json::json;
use reqwest::blocking::Client;
use std::{env, time::Duration};

const TX_TYPE_1559: u8 = 0x02;

fn main() -> eyre::Result<()> {
    let pk = "0x01ab6e801c06e59ca97a14fc0a1978b27fa366fc87450e0b65459dd3515b7391";
    let wallet: LocalWallet = pk.parse()?;
    let from = wallet.address();
    let rpc = env::var("RPC_HTTP").unwrap_or_else(|_| "http://127.0.0.1:9944".into());
    let chain_id = fetch_chain_id(&rpc).unwrap_or(42u64);
    let base_fee = fetch_base_fee(&rpc);
    if let Some(bf) = base_fee { println!(" baseFeePerGas={bf}"); }

    let balance = fetch_balance(&rpc, format!("0x{:x}", from).as_str());
    if let Some(b) = balance { println!(" balanceWei={b} (~{:.6} ether)", as_eth(b)); }

    let remote_nonce = fetch_nonce(&rpc, format!("0x{:x}", from).as_str());
    let nonce = env::var("NONCE").ok().and_then(|s| s.parse::<u64>().ok())
        .or(remote_nonce).unwrap_or(0);

    let mut max_priority_fee = env::var("MAX_PRIORITY_FEE").ok().and_then(|s| s.parse::<u64>().ok()).map(U256::from).unwrap_or(U256::from(1_000_000_000u64));
    let mut max_fee = env::var("MAX_FEE").ok().and_then(|s| s.parse::<u64>().ok()).map(U256::from).unwrap_or(U256::from(1_000_000_000u64));
    let auto_adjust = env::var("AUTO_ADJUST_GAS").ok().map(|v| v=="1" || v.eq_ignore_ascii_case("true")).unwrap_or(true);
    if let Some(bf) = base_fee { if max_fee < bf + max_priority_fee { if auto_adjust { let headroom = bf*U256::from(2) + max_priority_fee; println!(" adjusting max_fee {max_fee} -> {headroom}"); max_fee=headroom; }} }

    let gas_limit = env::var("GAS_LIMIT").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(21_000u64);
    let value = env::var("VALUE").ok().and_then(|s| s.parse::<u128>().ok()).map(U256::from).unwrap_or(U256::zero());
    let to_addr_env = env::var("TO").ok();
    let to: Address = to_addr_env
        .and_then(|h| h.strip_prefix("0x").map(|s| s.to_owned()).or(Some(h)))
        .and_then(|h| if h.len()==40 { hex::decode(&h).ok() } else { None })
        .map(|b| Address::from_slice(&b))
        .unwrap_or(from);

    // Build unsigned payload (list len 9)
    let mut payload = RlpStream::new_list(9);
    payload.append(&U256::from(chain_id));
    payload.append(&U256::from(nonce));
    payload.append(&max_priority_fee);
    payload.append(&max_fee);
    payload.append(&U256::from(gas_limit));
    payload.append(&to);
    payload.append(&value);
    payload.append(&Vec::<u8>::new()); // data
    payload.begin_list(0); // accessList

    let unsigned_bytes = payload.out().to_vec();
    let mut preimage = Vec::with_capacity(1+unsigned_bytes.len());
    preimage.push(TX_TYPE_1559);
    preimage.extend_from_slice(&unsigned_bytes);
    let sighash = keccak(&preimage);
    let sig: Signature = wallet.sign_hash(sighash.into())?;
    let y_parity: u8 = (sig.v - 27) as u8;

    let mut signed = RlpStream::new_list(12);
    let rlp_unsigned = rlp::Rlp::new(&unsigned_bytes);
    for i in 0..rlp_unsigned.item_count().unwrap() { signed.append_raw(rlp_unsigned.at(i).unwrap().as_raw(),1); }
    signed.append(&y_parity); signed.append(&sig.r); signed.append(&sig.s);
    let final_body = signed.out().to_vec();
    let mut full = Vec::with_capacity(1+final_body.len());
    full.push(TX_TYPE_1559); full.extend_from_slice(&final_body);
    let raw_hex = format!("0x{}", hex::encode(&full));
    println!("Raw EIP-1559 tx: {raw_hex}");
    if let Some(rn)=remote_nonce { println!(" remoteNonce(network)={rn}"); }
    let required = U256::from(gas_limit)*max_fee + value;
    println!(" chainId={chain_id} from=0x{:x} nonce={nonce} gas={gas_limit} yParity={y_parity} maxFee={max_fee} maxPrio={max_priority_fee} baseFee={} value={value} requiredPrepay={required} (~{:.6} ether)", from, base_fee.unwrap_or_default(), as_eth(required));

    let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[raw_hex]});
    if let Ok(client) = Client::builder().timeout(Duration::from_secs(10)).build() {
        if let Ok(resp) = client.post(&rpc).json(&body).send() { if let Ok(t)=resp.text() { println!("Response: {t}"); } }
    }
    Ok(())
}

fn keccak(data:&[u8])->H256 { H256::from_slice(Keccak256::digest(data).as_slice()) }
fn fetch_chain_id(rpc:&str)->Option<u64>{ let body=json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}); Client::builder().timeout(Duration::from_secs(4)).build().ok()?.post(rpc).json(&body).send().ok()?.json::<serde_json::Value>().ok()?.get("result")?.as_str().and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"),16).ok()) }
fn fetch_base_fee(rpc:&str)->Option<U256>{ let body=json!({"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest", false]}); let v=Client::builder().timeout(Duration::from_secs(4)).build().ok()?.post(rpc).json(&body).send().ok()?.json::<serde_json::Value>().ok()?; let bf=v.get("result")?.get("baseFeePerGas")?.as_str()?; u64::from_str_radix(bf.trim_start_matches("0x"),16).ok().map(U256::from) }
fn fetch_balance(rpc:&str, addr:&str)->Option<U256>{ let body=json!({"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[addr, "latest"]}); let v=Client::builder().timeout(Duration::from_secs(4)).build().ok()?.post(rpc).json(&body).send().ok()?.json::<serde_json::Value>().ok()?; let hb=v.get("result")?.as_str()?; U256::from_str_radix(hb.trim_start_matches("0x"),16).ok() }
fn fetch_nonce(rpc:&str, addr:&str)->Option<u64>{ let body=json!({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":[addr, "latest"]}); let v=Client::builder().timeout(Duration::from_secs(4)).build().ok()?.post(rpc).json(&body).send().ok()?.json::<serde_json::Value>().ok()?; let hn=v.get("result")?.as_str()?; u64::from_str_radix(hn.trim_start_matches("0x"),16).ok() }
fn as_eth(wei:U256)->f64{ const WEI:f64=1e18; let low=(wei & U256::from(u128::MAX)).low_u128() as f64; low/WEI }
