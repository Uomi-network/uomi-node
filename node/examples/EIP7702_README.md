# EIP-7702 Examples

This directory contains examples demonstrating EIP-7702 (Set EOA account code for one transaction) functionality in the Uomi blockchain.

## What is EIP-7702?

EIP-7702 allows an Externally Owned Account (EOA) to temporarily delegate its execution logic to a smart contract. When an EOA has an authorization in place, calling the EOA will execute the contract's code, but using the EOA's own storage.

Key features:
- **Code delegation**: EOA can execute smart contract logic
- **Storage separation**: EOA maintains its own storage, separate from the delegated contract
- **Temporary**: Delegation can be revoked or changed
- **Authorization-based**: Requires signature from the EOA owner

## Examples

### 1. `eip7702_demo.rs` - Complete Demonstration

A comprehensive example showing the full EIP-7702 workflow:

```bash
# Run with existing contract
SKIP_DEPLOY=1 CONTRACT_ADDRESS=0x4bbfc37c65ca1231a8900be69715025e556a1d10 cargo run -p uomi --example eip7702_demo

# Run with automatic contract deployment
cargo run -p uomi --example eip7702_demo
```

This example:
1. Deploys a simple counter contract (or uses existing)
2. Creates an EIP-7702 authorization
3. Sends delegation transaction
4. Verifies the delegation
5. Calls functions on the delegated EOA
6. Demonstrates storage separation

### 2. `test_eip7702.rs` - Simple Delegation Test

Creates an EIP-7702 transaction to delegate an EOA to a contract:

```bash
CONTRACT_ADDRESS=0x4bbfc37c65ca1231a8900be69715025e556a1d10 cargo run -p uomi --example test_eip7702
```

### 3. `verify_delegation.rs` - Delegation Verification

Verifies if an EOA has delegation code and checks the delegated contract:

```bash
cargo run -p uomi --example verify_delegation
```

### 4. `list_contracts.rs` - Find Deployed Contracts

Lists all contracts deployed on the blockchain:

```bash
cargo run -p uomi --example list_contracts
```

## Critical Implementation Detail: Self-Delegation Nonce

⚠️ **IMPORTANT**: When creating an authorization for self-delegation (when the transaction sender is authorizing their own address), you must use `authorization_nonce = current_nonce + 1`.

### Why?

Per the EIP-7702 specification:
> "The authorization list is processed **after** the sender's nonce is incremented."

This means:
1. Transaction begins execution
2. **Sender nonce is incremented** (N → N+1)
3. Authorization list is processed
4. Authorization nonce is checked against current account nonce

For self-delegation:
- If account nonce is 10 before the transaction
- The transaction increments it to 11
- Authorization check reads nonce = 11
- Therefore, `authorization_nonce` must be 11 (not 10)

### Code Example

```rust
// Fetch current nonce
let nonce = fetch_nonce(&rpc, &format!("0x{:x}", from)).unwrap_or(0);

// CRITICAL: For self-delegation, auth_nonce = nonce + 1
let auth_nonce = U256::from(nonce + 1);

// Sign authorization with this nonce
let mut auth_rlp = RlpStream::new_list(3);
auth_rlp.append(&U256::from(chain_id));
auth_rlp.append(&contract_address);
auth_rlp.append(&auth_nonce);  // Use nonce + 1
```

### For Third-Party Delegation

If authorizing a **different** address (not the transaction sender), use the target account's current nonce without incrementing.

## Transaction Structure

An EIP-7702 transaction (type `0x04`) has the following structure:

```
0x04 || rlp([
  chain_id,
  nonce,
  max_priority_fee_per_gas,
  max_fee_per_gas,
  gas_limit,
  to,
  value,
  data,
  access_list,
  authorization_list,  // EIP-7702 specific
  signature_y_parity,
  signature_r,
  signature_s
])
```

### Authorization List Format

Each authorization in the `authorization_list` is:

```
[
  chain_id,              // U256: Chain ID or 0 for any chain
  address,               // H160: Contract address to delegate to
  nonce,                 // U256: Nonce of authorizing account
  y_parity,              // u8: Signature recovery id (0 or 1)
  r,                     // U256: Signature r value
  s                      // U256: Signature s value
]
```

### Authorization Signature

The authorization is signed over:

```
keccak256(0x05 || rlp([chain_id, address, nonce]))
```

Where `0x05` is the EIP-7702 magic byte.

## Delegation Designator Format

When an EOA is delegating, its code is set to the EIP-7702 delegation designator:

```
0xef0100 + <20-byte contract address>
```

Example:
```
0xef01004bbfc37c65ca1231a8900be69715025e556a1d10
  ^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  prefix 20-byte contract address
```

## Verification

You can verify delegation using standard Ethereum RPC methods:

### Check if account is delegating:

```bash
curl -H "Content-Type: application/json" -d '{
  "jsonrpc":"2.0",
  "id":1,
  "method":"eth_getCode",
  "params":["0xaaafb3972b05630fccee866ec69cdadd9bac2771","latest"]
}' http://127.0.0.1:9944
```

Response for delegating account:
```json
{"result":"0xef01004bbfc37c65ca1231a8900be69715025e556a1d10"}
```

### Call function on delegated EOA:

```bash
curl -H "Content-Type: application/json" -d '{
  "jsonrpc":"2.0",
  "id":1,
  "method":"eth_call",
  "params":[{
    "to":"0xaaafb3972b05630fccee866ec69cdadd9bac2771",
    "data":"0x3fa4f245"
  },"latest"]
}' http://127.0.0.1:9944
```

This executes the contract's code using the EOA's storage.

## Storage Separation

EIP-7702 ensures complete storage separation:
- Contract storage at `contract_address` is independent
- EOA storage at `eoa_address` is independent
- Calling the EOA executes contract **code** but uses EOA **storage**

Example:
```
Contract at 0x4bbf... has storage[0] = 1
EOA at 0xaaaf... delegating to 0x4bbf... has storage[0] = 0

Calling value() on contract returns: 1
Calling value() on EOA returns: 0
```

## Troubleshooting

### Delegation not working?

1. **Check nonce**: For self-delegation, use `current_nonce + 1`
2. **Verify chain ID**: Authorization chain ID must match or be 0
3. **Check signature**: Authorization must be signed by the authorizing account
4. **Verify account state**: Account must not have non-delegation code already

### How to revoke delegation?

Send another EIP-7702 transaction with:
- `address = 0x0000000000000000000000000000000000000000` (zero address)
- This clears the delegation code

## References

- [EIP-7702 Specification](https://eips.ethereum.org/EIPS/eip-7702)
- [Ethereum Pectra Upgrade](https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/pectra.md)
- EVM version: 0.43.4 with EIP-7702 support
- Frontier integration: polkadot-evm/frontier master branch
