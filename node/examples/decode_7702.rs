//! Helper to introspect a raw type-0x04 (EIP-7702) transaction's RLP structure.
//!
//! Usage:
//!   RAW_TX=0x04f8... cargo run -p uomi --example decode_7702
//!
//! It will:
//!   * Strip the leading 0x04 type byte
//!   * Parse the following RLP list
//!   * Print item count and each element's raw hex, length, and a few heuristic decodes
//!   * Attempt (best-effort) numeric interpretation (u256) for small elements
//!
//! This is intended to troubleshoot field misalignment causing misleading
//! "insufficient funds" errors while crafting manual EIP-7702 transactions.

use hex::FromHex;
use rlp::Rlp;
use std::env;
use ethers::core::types::{H160, U256};

fn main() -> eyre::Result<()> {
    let raw = env::var("RAW_TX")
        .expect("RAW_TX env var required (hex string starting with 0x04)");
    let raw = raw.trim();
    let bytes = if let Some(stripped) = raw.strip_prefix("0x") { Vec::from_hex(stripped)? } else { Vec::from_hex(raw)? };
    if bytes.is_empty() || bytes[0] != 0x04 { eyre::bail!("Not a type-0x04 transaction (first byte {:02x})", bytes.get(0).cloned().unwrap_or(0)); }
    let body = &bytes[1..];
    let rlp = Rlp::new(body);
    if !rlp.is_list() { eyre::bail!("Expected RLP list after type byte"); }
    let count = rlp.item_count()?;
    println!("RLP item count (INCLUDING signature parts) = {count}");
    for i in 0..count { 
        let elem = rlp.at(i)?;
        let raw_elem = elem.as_raw();
        let hex_elem = format!("0x{}", hex::encode(raw_elem));
        let mut annotations: Vec<String> = Vec::new();
        // Heuristics
        if raw_elem.len() == 20 { annotations.push("(20 bytes -> possible address)".into()); }
        if raw_elem.len() == 0 { annotations.push("(empty)".into()); }
        // Try u256 decode (ignore big failures)
        if let Ok(u) = elem.as_val::<U256>() { 
            // Filter out huge numbers that are clearly code blobs (arbitrary heuristic: > 2^200)
            if u.bits() < 200 { annotations.push(format!("(u256={})", u)); }
        }
        // Attempt address decode for 20-byte element
        if raw_elem.len() == 20 { annotations.push(format!("as_addr=0x{:x}", H160::from_slice(raw_elem))); }
        println!("[{i:02}] len={:>4} {} {}", raw_elem.len(), hex_elem, if annotations.is_empty() { String::new() } else { annotations.join(" ") });
    }
    println!("Done. Use this map to align fields vs expected schema.");
    Ok(())
}
