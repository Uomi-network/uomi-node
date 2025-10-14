use ethers::signers::{LocalWallet};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha3::{Digest, Keccak256};
use std::str::FromStr;

fn main() {
    // Private key from chain_spec comment (no 0x prefix)
    let sk_hex = "01ab6e801c06e59ca97a14fc0a1978b27fa366fc87450e0b65459dd3515b7391";
    let wallet: LocalWallet = LocalWallet::from_str(sk_hex).expect("valid privkey");
    let pubkey = wallet.signer().verifying_key();
    let uncompressed = pubkey.to_encoded_point(false);
    let uncompressed_bytes = uncompressed.as_bytes(); // 65 bytes (0x04 + X(32) + Y(32))
    // Compute address the usual way: keccak256 of X||Y (skip leading 0x04), take last 20 bytes
    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed_bytes[1..]);
    let hash = hasher.finalize();
    let address = &hash[12..];

    println!("Private Key: 0x{}", sk_hex);
    println!("Public Key (uncompressed): 0x{}", hex::encode(uncompressed_bytes));
    // Compressed form from k256
    let compressed = pubkey.to_encoded_point(true);
    println!("Public Key (compressed): 0x{}", hex::encode(compressed.as_bytes()));
    println!("Derived Ethereum Address: 0x{}", hex::encode(address));
}
