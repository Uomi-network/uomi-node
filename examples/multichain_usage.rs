// Example: Multi-Chain Transaction Flow
// This demonstrates how to use the new multi-chain TSS functionality

use pallet_tss::{Pallet as TssPallet, types::*};
use frame_support::dispatch::DispatchResult;

// Example 1: Check if a chain is supported
fn check_chain_support() {
    let ethereum_supported = TssPallet::<Runtime>::is_chain_supported(1);
    let bsc_supported = TssPallet::<Runtime>::is_chain_supported(56);
    let polygon_supported = TssPallet::<Runtime>::is_chain_supported(137);
    
    println!("Ethereum supported: {}", ethereum_supported);  // true
    println!("BSC supported: {}", bsc_supported);           // true
    println!("Polygon supported: {}", polygon_supported);   // true
}

// Example 2: Get all supported chains
fn list_supported_chains() {
    let chains = TssPallet::<Runtime>::get_supported_chains();
    
    println!("Supported chains:");
    for (chain_id, name) in chains {
        println!("  Chain ID {}: {}", chain_id, name);
    }
}

// Example 3: Build a transaction for Ethereum
fn build_ethereum_transaction() -> Result<Vec<u8>, &'static str> {
    let chain_id = 1; // Ethereum
    let to = "0x742d35Cc6634C0532925a3b8D40aE677";
    let value = 1_000_000_000_000_000_000u64; // 1 ETH in wei
    let data = &[]; // No contract data
    let gas_limit = 21000u64; // Standard ETH transfer
    let gas_price = 20_000_000_000u64; // 20 gwei
    let nonce = 42u64; // Current nonce
    
    TssPallet::<Runtime>::build_chain_transaction(
        chain_id, to, value, data, gas_limit, gas_price, nonce
    )
}

// Example 4: Submit a multi-chain transaction
fn submit_transaction_example(
    origin: OriginFor<Runtime>,
    signed_transaction: Vec<u8>
) -> DispatchResult {
    let chain_id = 1; // Ethereum
    
    // Submit the transaction
    TssPallet::<Runtime>::submit_multi_chain_transaction(
        origin,
        chain_id,
        signed_transaction,
    )
}

// Example 5: Update chain configuration
fn update_chain_config_example(
    origin: OriginFor<Runtime>
) -> DispatchResult {
    let chain_id = 1;
    let name = b"Ethereum Mainnet".to_vec();
    let rpc_url = b"https://rpc.ankr.com/eth".to_vec();
    let is_testnet = false;
    
    TssPallet::<Runtime>::update_chain_config(
        origin,
        chain_id,
        name,
        rpc_url,
        is_testnet,
    )
}

// Example 6: Manage agent nonces
fn manage_agent_nonce(
    origin: OriginFor<Runtime>,
    agent_nft_id: NftId,
    chain_id: u32,
) -> DispatchResult {
    // Get current nonce (for display purposes)
    TssPallet::<Runtime>::get_agent_nonce(
        origin.clone(),
        agent_nft_id.clone(),
        chain_id,
    )?;
    
    // Increment nonce after transaction
    TssPallet::<Runtime>::increment_agent_nonce(
        origin,
        agent_nft_id,
        chain_id,
    )
}

// Example 7: Complete multi-chain transaction workflow
fn complete_multichain_workflow() -> Result<(), &'static str> {
    println!("=== Multi-Chain TSS Transaction Workflow ===");
    
    // 1. Check supported chains
    println!("1. Checking supported chains...");
    check_chain_support();
    
    // 2. List all chains
    println!("\n2. Listing all supported chains...");
    list_supported_chains();
    
    // 3. Build transaction
    println!("\n3. Building Ethereum transaction...");
    let tx_data = build_ethereum_transaction()?;
    println!("   Transaction built: {} bytes", tx_data.len());
    
    // 4. In a real scenario, you would:
    //    - Sign the transaction using TSS
    //    - Submit the signed transaction
    //    - Monitor transaction status
    
    println!("\n4. Transaction ready for TSS signing and submission!");
    
    // 5. Chain-specific information
    println!("\n5. Chain-specific RPC endpoints:");
    println!("   Ethereum: https://rpc.ankr.com/eth");
    println!("   BSC: https://rpc.ankr.com/bsc");
    println!("   Polygon: https://rpc.ankr.com/polygon");
    println!("   Avalanche: https://rpc.ankr.com/avalanche");
    println!("   Arbitrum: https://rpc.ankr.com/arbitrum");
    println!("   Optimism: https://rpc.ankr.com/optimism");
    println!("   Fantom: https://rpc.ankr.com/fantom");
    
    Ok(())
}

// Example 8: Event handling
fn handle_multichain_events() {
    // In your runtime, you would listen for these events:
    
    // MultiChainTransactionSubmitted(chain_id, tx_hash)
    // - Emitted when a transaction is successfully submitted
    
    // MultiChainTransactionConfirmed(chain_id, tx_hash)  
    // - Emitted when a transaction is confirmed on-chain
    
    // MultiChainTransactionFailed(chain_id, tx_hash)
    // - Emitted when a transaction fails
    
    // ChainConfigurationUpdated(chain_id)
    // - Emitted when chain configuration is updated
    
    println!("Event handlers should be implemented in your runtime");
}

// Example 9: Error handling
fn handle_errors() {
    // Common error scenarios:
    
    // UnsupportedChain - when trying to use an unsupported chain ID
    // TransactionSubmissionFailed - when RPC submission fails
    // InvalidChainConfig - when chain configuration is invalid
    // ChainConnectionFailed - when cannot connect to RPC endpoint
    // InvalidTransactionData - when transaction data is malformed
    // InsufficientGasLimit - when gas limit is too low
    // InvalidNonce - when nonce is incorrect
    
    println!("Always handle errors appropriately in production code");
}

// Main example function
fn main() {
    println!("Multi-Chain TSS Pallet Usage Examples");
    println!("=====================================");
    
    // Run the complete workflow
    match complete_multichain_workflow() {
        Ok(()) => println!("\n✅ Workflow completed successfully!"),
        Err(e) => println!("\n❌ Error: {}", e),
    }
    
    // Additional examples
    handle_multichain_events();
    handle_errors();
    
    println!("\n🎉 Multi-chain TSS functionality is ready to use!");
}
