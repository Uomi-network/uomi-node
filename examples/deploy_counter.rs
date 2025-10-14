//! Example: Deploy and interact with a simple Counter Solidity contract using ethers on the local dev chain.
//! Prerequisites: node running with --dev exposing http rpc at 127.0.0.1:9944
//! NOTE: This is a native example (requires std). Build with `cargo run --example deploy_counter`.

use ethers::{
    abi::AbiParser,
    contract::ContractFactory,
    core::{types::{Address, U256, TransactionRequest, Chain}, utils::AnvilHardfork},
    middleware::SignerMiddleware,
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
    solc::{ConfigurableContractArtifact, Solc},
};
use std::{convert::TryFrom, sync::Arc, time::Duration, path::PathBuf};

// Embedded solidity source (small enough to inline)
const COUNTER_SOL: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Counter {
    uint256 public value;
    event Increment(uint256 newValue);
    function inc() external {
        value += 1;
        emit Increment(value);
    }
}"#;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Private key imported in chain spec comment (dev funded)
    let pk = "0x01ab6e801c06e59ca97a14fc0a1978b27fa366fc87450e0b65459dd3515b7391";
    let wallet: LocalWallet = pk.parse::<LocalWallet>()?.with_chain_id(Chain::Named("dev"));

    // Frontier dev RPC
    let provider = Provider::<Http>::try_from("http://127.0.0.1:9944")?
        .interval(Duration::from_millis(200));
    let client = Arc::new(SignerMiddleware::new(provider, wallet));

    // Compile Solidity in-memory.
    // We write to a temp dir because ethers-solc wants a file.
    let tmp = tempfile::tempdir()?;
    let contract_path = tmp.path().join("Counter.sol");
    std::fs::write(&contract_path, COUNTER_SOL)?;

    let compiled = Solc::default().compile_source(&contract_path)?;
    if compiled.has_error() { eyre::bail!("Compiler errors: {:#?}", compiled.output().errors); }

    let artifact: ConfigurableContractArtifact = compiled
        .get(contract_path.to_string_lossy(), "Counter")
        .expect("Counter artifact")
        .clone();

    let abi = artifact.abi.expect("ABI");
    let bin = artifact.bytecode.expect("Bytecode").object.into_bytes().expect("bytecode bytes");

    let factory = ContractFactory::new(abi.clone(), bin, client.clone());

    println!("Deploying Counter...");
    let deployer = factory.deploy(())?; // constructor()
    let contract = deployer.send().await?;
    let addr = contract.address();
    println!("Deployed at: 0x{:x}", addr);

    // Read initial value (eth_call)
    let initial: U256 = contract.method::<_, U256>("value", ())?.call().await?;
    println!("Initial value = {initial}");

    // Send inc transaction
    let pending = contract.method::<_, ()>("inc", ())?.send().await?;
    let receipt = pending.await?.expect("receipt");
    println!("inc tx included in block {:?}", receipt.block_number);

    // Read again
    let new_val: U256 = contract.method::<_, U256>("value", ())?.call().await?;
    println!("New value = {new_val}");

    if new_val != initial + U256::from(1u64) { eyre::bail!("Counter did not increment"); }
    println!("Success: Counter incremented.");
    Ok(())
}
