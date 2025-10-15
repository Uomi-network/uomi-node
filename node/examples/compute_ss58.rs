use sp_core::crypto::{Ss58Codec, Ss58AddressFormat};
use sp_core::sr25519;

// Existing SS58 address from chain_spec for the test EVM private key account
const EXISTING_SS58: &str = "5FQedkNQcF2fJPwkB6Z1ZcMgGti4vcJQNs6x85YPv3VhjBBT";
const CUSTOM_PREFIX: u16 = 87; // Your runtime SS58Prefix

fn main() {
    // Decode as sr25519 public key
    let pubkey = sr25519::Public::from_ss58check(EXISTING_SS58)
        .expect("valid existing ss58 address");

    // Re-encode with custom prefix 87
    let custom_fmt = Ss58AddressFormat::custom(CUSTOM_PREFIX);
    let ss58_pref_87 = pubkey.to_ss58check_with_version(custom_fmt);

    // Also show raw bytes
    println!("Raw public key (32 bytes): 0x{}", hex::encode(pubkey.0));
    println!("Existing SS58 (given): {EXISTING_SS58}");
    println!("Re-encoded SS58 with prefix {CUSTOM_PREFIX}: {ss58_pref_87}");
    if EXISTING_SS58 == ss58_pref_87 {
        println!("(Note: Existing address already uses prefix {CUSTOM_PREFIX}.)");
    } else {
        println!("(They differ: the chain UI using prefix {CUSTOM_PREFIX} will display: {ss58_pref_87})");
    }
}
