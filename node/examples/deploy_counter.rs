//! Example: Deploy and interact with a simple Counter contract.
//! Run with: `cargo run -p uomi --example deploy_counter`

use ethers::{
    contract::ContractFactory,
    core::types::U256,
    middleware::SignerMiddleware,
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
    solc::Solc,
};
use ethers::providers::Middleware; // bring trait methods like get_chainid/get_block_number into scope
use std::{convert::TryFrom, env, sync::Arc, time::Duration};

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
    println!("Starting deploy_counter example...");
    // Allow overrides via env:
    //   EXAMPLE_PRIVATE_KEY - hex private key
    //   EXAMPLE_RPC         - HTTP RPC endpoint (Frontier HTTP default often 9944)
    let pk = env::var("EXAMPLE_PRIVATE_KEY")
        .unwrap_or_else(|_| "0x01ab6e801c06e59ca97a14fc0a1978b27fa366fc87450e0b65459dd3515b7391".into());
    let rpc = env::var("EXAMPLE_RPC")
        .unwrap_or_else(|_| "http://127.0.0.1:9944".into()); // 9944 = HTTP (Frontier default)

    let provider = Provider::<Http>::try_from(rpc.clone())?
        .interval(Duration::from_millis(250));

    // We don't know chain id a priori; fetch it so the wallet signs correctly.
    // Fallback to 42 if the RPC isn't up yet (will be retried below).
    let mut tries = 0u8;
    let chain_id = loop {
        match provider.get_chainid().await {
            Ok(id) => break id.as_u64(),
            Err(_) if tries < 20 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => eyre::bail!("Could not fetch chain id from {rpc}: {e}"),
        }
    };
    let wallet: LocalWallet = pk.parse::<LocalWallet>()?.with_chain_id(chain_id);
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet));

    println!("Using chain id {chain_id} and account 0x{:x}", client.address());

    // Light readiness probe: ensure at least one block exists.
    let mut ready_tries = 0u8;
    while provider.get_block_number().await.is_err() && ready_tries < 20 {
        ready_tries += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if ready_tries == 20 { eyre::bail!("RPC {rpc} not ready after waiting"); }

    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("Counter.sol");
    std::fs::write(&path, COUNTER_SOL)?;
    println!("Successfully wrote Counter.sol to {}", path.display());

    // Attempt compile; if solc missing, emit a clear hint. (ethers-solc 2.x does not expose find_or_install())
    let compiled = match Solc::default().compile_source(&path) {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("No such file or directory") || msg.contains("not found") {
                eprintln!("ERROR: solc not found. Please install a 0.8.x compiler, e.g.\n  brew update && brew install solidity\nOr set SOLC_PATH=/full/path/to/solc and re-run. Original error: {msg}");
            }
            return Err(e.into());
        }
    };
    println!("Solidity compiled successfully.");
    if compiled.has_error() {
        eyre::bail!("Solidity compile errors: {:#?}", compiled.errors);
    }

    // Borrow the path cow & access artifact API compatible with ethers-solc 2.x
    let artifact = compiled
        .get(&path.to_string_lossy(), "Counter")
        .expect("Counter contract artifact present")
        .clone();
    let abi = artifact.abi.expect("ABI");
    let bytecode = artifact
        .bytecode()
        .expect("bytecode present")
        .clone();
    println!("Creation bytecode length: {} bytes", bytecode.len());

    let deploy_bytecode = bytecode.clone();
    let factory = ContractFactory::new(abi.clone(), deploy_bytecode, client.clone());
    let force_legacy = env::var("EXAMPLE_FORCE_LEGACY").ok().as_deref() == Some("1");
    let manual_deploy = env::var("EXAMPLE_MANUAL_DEPLOY").ok().as_deref() == Some("1");
    println!("Deploying Counter (legacy={})...", force_legacy);
    if manual_deploy {
        use ethers::types::{TransactionRequest, Bytes};
        let nonce = client.get_transaction_count(client.address(), None).await?;
        println!("Manual deploy mode enabled. Nonce {nonce}");
        // Provide a generous gas limit; pallet-evm will cap if needed.
        let gas_limit = U256::from(3_000_000u64);
    println!("Sending raw create tx with gas_limit={gas_limit} data_len={} bytes", bytecode.len());
        let tx = TransactionRequest::new()
            .from(client.address())
            .data(Bytes::from(bytecode.clone().0))
            .gas(gas_limit)
            .nonce(nonce)
            .value(U256::zero());
        let pending = client.send_transaction(tx, None).await?;
        let receipt = pending.await?.ok_or_else(|| eyre::eyre!("No receipt for manual deploy"))?;
        if let Some(addr) = receipt.contract_address { println!("Deployed at: 0x{:x}", addr); } else { eyre::bail!("Receipt missing contract_address"); }
        // Re-bind contract handle using factory ABI for subsequent calls if needed.
        let contract_addr = receipt.contract_address.expect("checked");
        let contract = ethers::contract::Contract::new(contract_addr, abi.clone(), client.clone());
        // Continue with interaction section below using this contract handle.
        run_interaction(contract).await?;
        return Ok(());
    } else {
        let mut deploy_builder = factory.deploy(())?;
        if force_legacy { deploy_builder = deploy_builder.legacy(); }
        // Ethers will internally estimate gas & fees when sending.
        let contract = deploy_builder.send().await?;
        println!("Deployed at: 0x{:x}", contract.address());
        run_interaction(contract).await?;
        return Ok(());
    }
}

async fn run_interaction(contract: ethers::contract::Contract<SignerMiddleware<Provider<Http>, LocalWallet>>) -> eyre::Result<()> {
    let skip_reads = std::env::var("EXAMPLE_SKIP_VALUE_READ").ok().as_deref() == Some("1");
    let initial = if skip_reads {
        println!("Skipping initial eth_call (EXAMPLE_SKIP_VALUE_READ=1)");
        U256::zero()
    } else {
        let v: U256 = contract.method::<_, U256>("value", ())?.call().await?;
        println!("Initial value: {v}");
        v
    };
    let inc_call = contract.method::<_, ()>("inc", ())?;

    // Optional debug path: dump raw signed RLP of the inc() transaction before sending to node
    // Enable with EXAMPLE_DUMP_RLP=1
    let dump_rlp = std::env::var("EXAMPLE_DUMP_RLP").ok().as_deref() == Some("1");
    let client = contract.client();
    let pending_tx = if dump_rlp {
        use ethers::providers::Middleware as _;
        use ethers::signers::Signer as _;
        use ethers::types::{TransactionRequest, Bytes};
        use ethers::types::transaction::eip2718::TypedTransaction;
        // Inner scope ensures client borrow ends before we return
        let pending = {
            let calldata = inc_call.calldata().expect("calldata");
            let to = contract.address();
            let client_arc = contract.client();
            let from = client_arc.default_sender().expect("have default sender");
            let nonce = client_arc.get_transaction_count(from, None).await?;
            let gas_limit = U256::from(300_000u64);
            let gas_price = client_arc.get_gas_price().await.unwrap_or_else(|_| U256::from(1_000_000_000u64));
            let tx_req = TransactionRequest::new()
                .to(to)
                .from(from)
                .data(Bytes::from(calldata.0.clone()))
                .gas(gas_limit)
                .gas_price(gas_price)
                .nonce(nonce)
                .value(U256::zero());
            let typed: TypedTransaction = tx_req.clone().into();
            let signer = client_arc.signer();
            let sig = signer.sign_transaction(&typed).await?;
            let rlp = typed.rlp_signed(&sig);
            let rlp_hex: String = {
                let mut s = String::with_capacity(2 + rlp.len() * 2);
                s.push_str("0x");
                for b in &rlp { use core::fmt::Write; write!(s, "{:02x}", b).unwrap(); }
                s
            };
            println!("[DEBUG] Raw signed inc() tx RLP: {rlp_hex}");
            println!("[DEBUG] nonce={nonce} gas_limit={gas_limit} gas_price={gas_price} to=0x{:x} from=0x{:x}", to, from);
            
            // Send raw RLP bytes directly
            client.provider().send_raw_transaction(Bytes::from(rlp)).await?
        };
        pending
    } else {
        inc_call.send().await?
    };
    let receipt = pending_tx.await?.expect("transaction receipt missing (dropped?)");
    println!("Inc tx mined in block {:?}", receipt.block_number);
    if skip_reads {
        println!("Skipped post-inc eth_call; cannot verify increment without read.");
    } else {
        let after: U256 = contract.method::<_, U256>("value", ())?.call().await?;
        println!("Value after inc: {after}");
        if after != initial + U256::from(1u64) { eyre::bail!("Counter did not increment"); }
    }
    println!("Success.");
    Ok(())
}
