# Multi-Chain TSS Pallet Implementation

## Overview
This implementation adds multi-chain transaction support to the TSS (Threshold Signature Scheme) pallet, with integrated Ankr RPC functionality for connecting to multiple blockchain networks.

## Key Features Implemented

### 1. Multi-Chain Support
- **Supported Networks**: Ethereum, Binance Smart Chain, Polygon, Avalanche, Arbitrum, Optimism, Fantom
- **Ankr RPC Integration**: Pre-configured RPC endpoints for all supported chains
- **Chain Configuration Management**: Storage and validation of chain configurations

### 2. Transaction Management
- **Transaction Building**: Ethereum-compatible transaction construction
- **Multi-Chain Signing**: TSS signature support across different blockchains
- **Nonce Management**: Per-agent, per-chain nonce tracking
- **Transaction Status Tracking**: Complete lifecycle monitoring

### 3. Storage Extensions
- **MultiChainTransactions**: Maps (chain_id, tx_hash) -> transaction_status
- **ChainConfigs**: Stores chain configurations (name, rpc_url, testnet_flag)
- **AgentNonces**: Tracks nonces per agent per chain

### 4. New Extrinsics (Dispatchable Functions)
- `submit_multi_chain_transaction`: Submit signed transactions to specific chains
- `update_chain_config`: Update chain configurations
- `get_agent_nonce`: Retrieve current nonce for an agent on a specific chain
- `increment_agent_nonce`: Increment nonce for an agent on a specific chain

### 5. Events
- `MultiChainTransactionSubmitted`: Emitted when transaction is submitted
- `MultiChainTransactionConfirmed`: Emitted when transaction is confirmed
- `MultiChainTransactionFailed`: Emitted when transaction fails
- `ChainConfigurationUpdated`: Emitted when chain config is updated

## File Structure

### Core Files
- `src/multichain.rs`: Multi-chain RPC client and transaction builder
- `src/fsa.rs`: Enhanced with multi-chain transaction processing
- `src/types.rs`: Extended with chain configuration and status types
- `src/lib.rs`: Main pallet with new extrinsics and storage

### Key Components

#### 1. SupportedChain Enum
```rust
pub enum SupportedChain {
    Ethereum,
    BinanceSmartChain,
    Polygon,
    Avalanche,
    Arbitrum,
    Optimism,
    Fantom,
}
```

#### 2. MultiChainRpcClient
- Chain configuration management
- Transaction submission via Ankr RPC
- Transaction status checking
- Block number retrieval

#### 3. TransactionBuilder
- Ethereum-compatible transaction construction
- Gas limit and price handling
- Nonce management
- Chain-specific formatting

## Usage Examples

### Submit a Multi-Chain Transaction
```rust
// Build transaction for Ethereum (chain_id = 1)
let tx_data = Pallet::<T>::build_chain_transaction(
    1, // Ethereum chain ID
    "0x742d35Cc6634C0532925a3b8D",
    1000000000000000000, // 1 ETH in wei
    &[],
    21000, // gas limit
    20000000000, // gas price (20 gwei)
    nonce,
)?;

// Submit the signed transaction
let result = Pallet::<T>::submit_multi_chain_transaction(
    origin,
    1, // chain_id
    signed_tx_data,
)?;
```

### Update Chain Configuration
```rust
let result = Pallet::<T>::update_chain_config(
    origin,
    1, // chain_id
    b"Ethereum".to_vec(),
    b"https://rpc.ankr.com/eth".to_vec(),
    false, // not testnet
)?;
```

### Check Supported Chains
```rust
let chains = Pallet::<T>::get_supported_chains();
// Returns: Vec<(u32, &'static str)>
// [(1, "Ethereum"), (56, "Binance Smart Chain"), ...]
```

## Integration Points

### 1. Ankr RPC Endpoints
- **Ethereum**: `https://rpc.ankr.com/eth`
- **BSC**: `https://rpc.ankr.com/bsc`
- **Polygon**: `https://rpc.ankr.com/polygon`
- **Avalanche**: `https://rpc.ankr.com/avalanche`
- **Arbitrum**: `https://rpc.ankr.com/arbitrum`
- **Optimism**: `https://rpc.ankr.com/optimism`
- **Fantom**: `https://rpc.ankr.com/fantom`

### 2. OPOC (Off-chain Processing Output Consumer)
- Enhanced to handle multi-chain transaction actions
- Supports `transaction` and `multi_chain_transaction` action types
- Automatic chain validation and configuration

### 3. TSS Integration
- Works with existing TSS key generation and signing
- Maintains compatibility with existing DKG sessions
- Extends signing sessions for multi-chain support

## Error Handling

### New Error Types
- `UnsupportedChain`: Chain ID not supported
- `TransactionSubmissionFailed`: Transaction submission failed
- `InvalidChainConfig`: Invalid chain configuration
- `ChainConnectionFailed`: Failed to connect to chain
- `InvalidTransactionData`: Invalid transaction data format
- `InsufficientGasLimit`: Gas limit too low
- `InvalidNonce`: Nonce validation failed

## Security Considerations

1. **Chain Validation**: All chain IDs are validated before processing
2. **Configuration Validation**: RPC URLs and chain names are validated
3. **Nonce Management**: Proper nonce handling prevents replay attacks
4. **Gas Limit Validation**: Prevents stuck transactions
5. **Transaction Status Tracking**: Complete audit trail

## Future Enhancements

1. **Dynamic Chain Addition**: Support for adding new chains via governance
2. **Gas Price Oracle**: Automatic gas price estimation
3. **Transaction Retry Logic**: Automatic retry with higher gas prices
4. **Batch Transactions**: Support for batching multiple transactions
5. **Cross-Chain Bridges**: Integration with bridge protocols
6. **Fee Estimation**: Dynamic fee calculation based on network conditions

## Testing

The implementation includes:
- Compilation tests
- Chain configuration validation
- Transaction building tests
- RPC client simulation
- Error handling verification

## Deployment Notes

1. Ensure proper chain configurations are set before use
2. Monitor gas prices and adjust accordingly
3. Set up monitoring for transaction status tracking
4. Consider rate limiting for RPC calls
5. Implement proper key management for signing

## Compatibility

- **Substrate Version**: Compatible with current Substrate framework
- **Polkadot Version**: Compatible with current Polkadot SDK
- **Ethereum Compatibility**: Supports EIP-155 and EIP-1559 transactions
- **Other Chains**: Supports Ethereum-compatible chains

This implementation provides a solid foundation for multi-chain transaction support in the TSS pallet, with room for future enhancements and optimizations.
