# Multi-Chain TSS Pallet Implementation

## Overview
This implementation adds multi-chain transaction support to the TSS (Threshold Signature Scheme) pallet, with integrated Ankr RPC functionality for connecting to multiple blockchain networks.

## Key Features Implemented

### 1. Multi-Chain Support
- **Supported Networks**: Ethereum, Binance Smart Chain, Polygon, Avalanche, Arbitrum, Optimism, Fantom, Uomi (local chain_id 4386), Base
- **Ankr RPC Integration**: Pre-configured RPC endpoints for major public chains
- **Chain Configuration Management**: Storage and validation of chain configurations

### 2. Transaction Management
- **Transaction Preimage Building**: Distinguishes clearly between the SIGNING PREIMAGE and the FINAL RAW transaction bytes.
    - Legacy (EIP-155) preimage: RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
    - EIP-1559 preimage: 0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])
- **Finalization**: Raw broadcastable tx is reconstructed on-chain after signature via finalize helpers (not stored in OPOC output).
- **Structured Action Builder**: Automatically constructs the appropriate preimage (legacy or EIP-1559) from action fields.
- **Fallback Handling**: If structured build fails (e.g. invalid address, malformed numbers) we fall back to the provided raw data bytes.
- **Nonce Management**: Per-agent, per-chain nonce tracking (future improvement: dynamic retrieval via RPC already scaffolded).
- **Transaction Status Tracking**: Lifecycle monitoring through `MultiChainTransactions`.

### 3. Storage Extensions
- **MultiChainTransactions**: Maps (chain_id, tx_hash) -> transaction_status
- **ChainConfigs**: Stores chain configurations (name, rpc_url, testnet_flag)
- **AgentNonces**: Tracks nonces per agent per chain
- **Outputs (engine pallet)**: Tuple expanded to `(Data, executions, consensus_round, nft_id)` to cryptographically bind produced actions to an authoritative NFT identity and prevent spoofing.

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
    Uomi,
}
```

#### 2. MultiChainRpcClient
- Chain configuration management
- Transaction submission via Ankr RPC
- Transaction status checking
- Block number retrieval

#### 3. TransactionBuilder
Key helper functions:

```rust
// Legacy (EIP-155) preimage only
build_ethereum_transaction(to, value, data: &[u8], gas_limit, gas_price, nonce, chain_id) -> Vec<u8>

// EIP-1559 preimage only (type 0x02 + 9-field RLP list)
build_eip1559_transaction(to, value, data: &[u8], gas_limit, max_fee, max_priority, nonce, chain_id) -> Vec<u8>

// Finalization (performed after TSS signature collection)
legacy_finalize_raw(..., r, s, recid) -> Vec<u8>
eip1559_finalize_raw(..., r, s, recid) -> Vec<u8>
```

The builder intentionally returns PREIMAGE bytes (the exact digestable message) not a broadcastable raw tx. Finalization inserts signature components (v / y_parity, r, s) and re-encodes the transaction structure.

EIP-1559 preimage includes the type byte (0x02) followed by the RLP payload to mirror metamask / ethers signing flows which hash `0x02 || rlp(list)`.

## Request ID Based Linking & Deduplication (Recent Update)

Previously, pending FSA (follow‑up signing action) transaction data was keyed implicitly by `(nft_id, message)` when creating signing sessions. This created two limitations:

1. An NFT (agent identity) could not have more than one concurrent signing request for different messages without risk of accidental deduplication.
2. Duplicate detection required full message byte equality checks, which is more expensive and semantically weaker than using the authoritative engine-produced identifier.

The pallet now uses the authoritative OPOC / Engine `request_id` (a `U256`) as the primary linkage and uniqueness handle across the whole pipeline.

### Updated Storage Mapping

```
// lib.rs
pub type FsaTransactionRequests<T: Config> = StorageMap<
    _, Blake2_128Concat, U256, (NftId, u32 /* chain_id */, BoundedVec<u8, MaxMessageSize>)
>;
```

`SigningSession` struct now includes a `request_id: U256` field. Multiple signing sessions may exist for the same `nft_id` so long as each has a distinct `request_id`.

### Lifecycle Overview

1. Off‑chain worker (or external submitter) derives / discovers actionable OPOC engine outputs and their `request_id`s.
2. Unsigned extrinsic `create_signing_session_unsigned` is submitted with payload `{ request_id, nft_id (U256 form), chain_id, message, public }`.
3. Pallet checks for existing in‑progress session with same `request_id`; if found, it skips creating a duplicate (idempotent behavior).
4. If new, pallet inserts into `FsaTransactionRequests` and creates a `SigningSession` referencing the DKG session for the NFT (must already exist & be `DKGComplete`).
5. Once enough partial signatures are aggregated, the session moves to `SigningComplete` and `process_completed_signatures` consumes the stored `(nft_id, chain_id, tx_bytes)` tuple, submits outbound transaction (mock / future RPC), then removes the `request_id` entry from storage.

### Duplicate Detection Rule

Only `request_id` is used for deduplication. Different messages for the same nft may coexist if their `request_id`s differ. This enables parallel / pipelined transaction flows per agent.

### Advantages

* O(1) uniqueness check keyed by a compact 32‑byte ID.
* Eliminates accidental suppression of distinct actions sharing identical message bytes.
* Clear audit trail: engine output ID is the canonical reference across pallets.
* Simplifies potential future migrations / pruning logic (single key space ordered by `request_id`).

### Test Coverage Added

New unit tests (see `pallets/tss/src/tests.rs`) validate the behavior:

* `request_id_deduplication_and_storage` – ensures duplicate unsigned submissions with identical `request_id` do not create additional sessions.
* `request_id_cleanup_after_signature_processing` – verifies storage entry removal after signature finalization.
* `multiple_distinct_request_ids_same_nft_create_multiple_sessions` – confirms multiple concurrent sessions for the same NFT with distinct IDs are allowed.

### Migration Notes

If an earlier on‑chain deployment stored pending signing requests keyed by `nft_id`, a runtime storage migration would be required to re‑encode those entries under unique `request_id`s. This codebase update does not include that migration (intentionally deferred). For a fresh deployment (or after clearing old state) no migration work is required. A future migration plan should:

1. Iterate old map `(nft_id) -> (chain_id, message, ...)` producing deterministic synthetic `request_id`s (e.g., hash(nft_id || message) truncated into U256) when the original engine IDs are unavailable.
2. Populate new `FsaTransactionRequests` with tuples `(nft_id, chain_id, message)` keyed by synthesized IDs.
3. Backfill `SigningSessions` with the new `request_id` value.
4. Bump pallet storage version & gate logic to avoid re‑migrating.

Until that migration is implemented and executed, deploying this version onto a chain with legacy state will result in orphaned or inaccessible legacy entries. Plan a coordinated upgrade if necessary.

### Observability

Log lines now include `request_id` for duplicate suppression and storage insertion events:

```
[TSS] Stored FSA transaction request for request_id 0x... on chain <id>
[TSS] Skipping duplicate signing session request for request_id 0x...
```

These aid in tracing idempotent submissions and cleanup timing.


## Structured Action Processing

The OPOC → TSS pipeline now supports structured JSON actions that describe an EVM transaction. The pallet converts these into a signing preimage automatically.

### Action Schema
```jsonc
{
    "action_type": "transaction" | "multi_chain_transaction",
    "chain_id": 1,
    "data": "0xabcdef" ,            // Hex string (may be "0x" for empty)
    "to": "0x........20bytes........",
    "value": "0x3e8",               // Hex or decimal string (optional, default 0)
    "gas_limit": "21000",           // Hex or decimal (default 21000)
    "gas_price": "0x3b9aca00",      // Legacy only (default 1 gwei)
    "tx_type": "legacy" | "eip1559", // Default: eip1559 if omitted
    "max_fee_per_gas": "0x77359400", // EIP-1559 (default: legacy gas_price if absent)
    "max_priority_fee_per_gas": "0x3b9aca00", // EIP-1559 (default 1 gwei)
    "nonce": "0x0"                  // Optional (default 0)
}
```

### Defaults & Fallbacks
- Missing numeric fields → sensible defaults (gas_limit 21000, gas_price 1 gwei, priority 1 gwei, value 0, nonce 0).
- `tx_type` omitted → treated as EIP-1559 (modern default).
- Malformed hex in `data` (odd length or invalid chars) → logs a warning and treats data as empty.
- Invalid `to` address or failed builder → fall back to raw decoded `data` bytes (still signed as provided).

### Example (Legacy)
```json
{
    "actions": [
        {"action_type":"transaction","chain_id":1,"data":"0x","to":"0x1111111111111111111111111111111111111111","value":"0x3e8","gas_limit":"21000","gas_price":"0x3b9aca00","nonce":"0x0","tx_type":"legacy"}
    ]
}
```

### Example (EIP-1559)
```json
{
    "actions": [
        {"action_type":"multi_chain_transaction","chain_id":1,"data":"0x","to":"0x2222222222222222222222222222222222222222","value":"0x0","gas_limit":"21000","tx_type":"eip1559","max_fee_per_gas":"0x77359400","max_priority_fee_per_gas":"0x3b9aca00","nonce":"0x1"}
    ]
}
```

### Preimage vs Final Raw Tx
1. Structured action → builder creates preimage bytes only.
2. TSS signs keccak256(preimage) (implementation-dependent).
3. Pallet reconstructs final raw transaction using finalize helper + signature parts before dispatching RPC submission.

## Usage Examples

### Submit a Multi-Chain Transaction
```rust
// Build LEGACY signing preimage (example only — usually produced automatically from a structured action)
let preimage = Pallet::<T>::build_chain_transaction(
    1, // Ethereum chain ID
    "0x742d35Cc6634C0532925a3b8D742d35Cc6634C0532925a3b8D742d35Cc6634", // (example shortened / validate length in real usage)
    1_000_000_000_000_000_000u64, // 1 ETH
    &[],
    21_000,
    20_000_000_000, // 20 gwei
    nonce,
)?; // Returns PREIMAGE bytes, not raw tx

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

### Builder / Processing Errors
- `UnsupportedChain`: Chain ID not supported
- `InvalidChainConfig`: Chain configuration invalid (id/name/url)
- `InvalidEthereumAddress`: Address parsing failure (implicit via builder error)
- `MalformedHexData`: Logged (not a hard error) → data treated as empty
- `TransactionSubmissionFailed`: RPC error during broadcast
- `InsufficientGasLimit` / `InvalidNonce`: Reserved for enhanced validation (future)

### Fallback Strategy
If any structured build step fails, we log the reason and fall back to signing the raw provided `data` bytes (post hex decoding). This ensures resilience and observability.

## Security Considerations

1. **NFT Binding**: Inclusion of `nft_id` in engine `Outputs` storage eliminates spoofing of agent identity in downstream TSS processing.
2. **Chain Validation**: All chain IDs validated before any build/sign step.
3. **Configuration Validation**: RPC URL format & presence enforced.
4. **Preimage Integrity**: Separation of preimage vs raw tx ensures signatures cannot be misapplied to altered payloads.
5. **Graceful Fallback**: Malformed structured fields do not stall pipeline; audit logs capture anomalies.
6. **Replay Mitigation (Planned)**: Enhanced nonce fetching / caching & mismatch detection.

## Future Enhancements

1. **Dynamic Chain Addition**: Governance-based registration & removal.
2. **Gas Price / Fee Oracle**: Adaptive EIP-1559 fee suggestion & legacy gas price fallback.
3. **Transaction Retry Logic**: Re-broadcast with escalated fees after timeout windows.
4. **Batch Transactions**: Aggregate multiple structured actions into a single signing session.
5. **Cross-Chain Bridges**: Proof / attestation support for bridging operations.
6. **Advanced Access Lists**: Populate EIP-2930 / EIP-1559 access list dynamically.
7. **Signature Caching**: Avoid recomputation for identical preimages across sessions.

## Testing

Included test coverage now spans:
1. Legacy & EIP-1559 preimage vs finalized raw differentiation.
2. Structured action → expected preimage (legacy & EIP-1559).
3. Fallback on invalid address (returns raw data bytes).
4. Default-field inference for minimal structured actions.
5. Malformed hex `data` handling (graceful empty decode + successful build).
6. Storage tuple (with `nft_id`) propagation through pipeline.

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

This implementation provides a solid and extensible foundation for multi-chain transaction support in the TSS pallet, emphasizing clarity between signing preimages and broadcast raw transactions while enabling structured, human-readable action definitions.
