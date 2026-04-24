# UOMI Threshold Signature Scheme - Code-Based Security Audit

You are a blockchain cryptography and Rust security expert. Audit the UOMI TSS implementation by examining the actual code (not documentation). The system uses a **hybrid approach**: FROST Ed25519 for distributed key generation (DKG) + multi-party ECDSA (secp256k1) for transaction signing across 9 EVM chains.

## System Architecture (As Actually Implemented)

### On-Chain: Substrate Pallet TSS
**Crate**: `pallets/tss` (~7,500 lines total)
**Key files**:
- `lib.rs` (2,610 lines) - 21 extrinsics managing DKG sessions, signing, multi-chain TX, validator reporting
- `multichain.rs` (755 lines) - Real HTTP RPC client (9 chain URLs hardcoded) + RLP transaction builder (legacy + EIP-1559)
- `fsa.rs` (511 lines) - Finite State Automaton processing OPOC (Off-chain Processing Output Consumer) outputs
- `sessions.rs` (251 lines) - DKG session state machine (Pending → DKGInProgress → DKGComplete → DKGSuperseded/DKGFailed)
- `types.rs` (102 lines) - `DKGSession`, `NonceState`, `ChainConfig`, `TransactionStatus`
- `tests.rs` (2,886 lines) - Test suite with property-based tests

**What actually happens**:
1. Validators call `create_dkg_session(nft_id, threshold)` to start DKG
2. Off-chain workers use FROST Ed25519 to generate shared key for `nft_id`
3. Result submitted via `submit_dkg_result(session_id, aggregated_key)`
4. OPOC engine (pallet_uomi_engine) produces `Action` structs in `Outputs` storage
5. FSA processor fetches actions, builds EVM transaction preimages (RLP-encoded)
6. `submit_multi_chain_transaction()` signs and broadcasts to RPC endpoints

### Off-Chain: TSS Client
**Crate**: `client/tss` (~10,000 lines total)
**Key modules**:
- `dkground1.rs`, `dkground2.rs`, `dkground3.rs` - FROST Ed25519 three-round DKG (using `frost_ed25519::keys::dkg::part{1,2,3}()`)
- `ecdsa/operations.rs` - Multi-party ECDSA keygen, sign, reshare (using `multi_party_ecdsa::dmz21::{KeyGenPhase, SignPhase, ReshareKeyPhase}`)
- `session/manager.rs` (537 lines) - Session coordination state machine
- `ecdsa/message_processor.rs` (792 lines) - ECDSA protocol message handling and state transitions
- `gossip/router.rs` (494 lines) - P2P message broadcasting via sc-network-gossip
- `session/message_processor.rs` (661 lines) - Message buffering and routing

**What actually happens**:
1. Client receives DKG session created event
2. Calls `frost_ed25519::keys::dkg::part1()` → broadcasts Round 1 commitment
3. Collects Round 1 packages from all k participants
4. Calls `frost_ed25519::keys::dkg::part2()` → generates Round 2 shares
5. Calls `frost_ed25519::keys::dkg::part3()` → derives shared public key
6. Client also implements multi-party ECDSA for transaction signing
7. Messages buffered if out-of-order (maps to handle early messages)

## Specific Audit Points (Based on Actual Code)

### 1. FROST DKG Implementation (ED25519)

**Files**: `client/tss/src/dkground{1,2,3}.rs`, `client/tss/src/dkghelpers.rs`

**Questions to answer by reading code**:
- [ ] What is the threshold `k` value used? Is it correct for the validator set?
- [ ] Line-by-line verification of `dkground1.rs`:
  - What does `frost_ed25519::keys::dkg::part1()` actually return? (Verify in frost-core docs)
  - Is the returned commitment correctly broadcast to all participants?
  - Are secret shares protected (not logged, not serialized carelessly)?
- [ ] Line-by-line verification of `dkground2.rs`:
  - Does `frost_ed25519::keys::dkg::part2()` verify commitments from all participants?
  - What proofs are checked? (Look for verif* functions)
  - What happens if one participant's commitment is invalid? (Does it fail immediately or can be recovered?)
  - Are share values securely erased after use?
- [ ] Line-by-line verification of `dkground3.rs`:
  - Does `part3()` correctly combine shares to derive the shared public key?
  - Can the aggregated key be derived deterministically from commitments without access to secret shares? (This is the correct behavior)
  - Is the public key format correct? (33 bytes compressed or 65 bytes uncompressed?)
- [ ] Look at `dkghelpers.rs`:
  - What is `sha2::Sha256` used for? (Hashing transcript?)
  - Is transcript hashing part of FROST or custom logic?
  - Any constants or hardcoded values that should be questioned?

**Potential vulnerabilities to hunt**:
- Polynomial degree mismatch (threshold `k` not matching actual shares)
- Commitment verification skipped or bypassed
- Shares reconstructed in plaintext (look for reconstructing secret from shares)
- Determinism issues (randomness sources not properly seeded)

### 2. Multi-Party ECDSA (SECP256K1)

**Files**: `client/tss/src/ecdsa/operations.rs`, `client/tss/src/ecdsa/message_processor.rs`

**Questions to answer by reading code**:
- [ ] What version of `multi_party_ecdsa` is used? (`0.1.3` from Cargo.toml)
  - Is this the official OpenTSS crate or a fork?
  - Line 1 of operations.rs: What does `multi_party_ecdsa::dmz21::KeyGenPhase::new()` require?
  - What inputs are passed? (participant index, threshold, total participants)
- [ ] Keygen phase (`KeyGenPhase`):
  - How many rounds? (Check message flow)
  - What Paillier assumptions are made? (Key size? Security level?)
  - Are homomorphic proofs verified? (Look for verify calls)
  - Can one participant force keygen failure?
- [ ] Signing phase (`SignPhase`):
  - Line-by-line: What messages are exchanged?
  - Is nonce reuse possible? (Check if `SignPhase::new()` is called for each signature)
  - Does signature finalization include proper `r` and `s` recovery? (secp256k1 has 4 possible pubkeys per (r,s))
  - How is recovery ID (v_parity) determined?
- [ ] Reshare phase (`ReshareKeyPhase`):
  - When is resharing triggered? (On validator set change via `create_reshare_dkg_session()`)
  - Can old key shares be used after reshare?
  - Are participants atomically transitioned to new key or is there a window where both work?

**Potential vulnerabilities to hunt**:
- Nonce reuse in ECDSA signing (catastrophic, leaks private key)
- Incorrect recovery ID encoding (signature validation fails on some chains)
- Paillier modulus too small (breaks semantic security assumption)
- Reshare protocol allows old and new keys simultaneously (leads to duplicate signatures)
- Multi-party-ecdsa crate has known vulns (search GitHub issues)

### 3. RLP Transaction Encoding (EVM Transaction Signing)

**Files**: `pallets/tss/src/multichain.rs` (RLP building + RPC calls)

**Lines to examine**:
- [ ] `build_ethereum_transaction()` function:
  - **Legacy**: RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
  - Is the field order EXACTLY correct? (Off-by-one field order would create invalid TX)
  - Are all fields u64/U256 or some are wrong types? (Gas price should be uint256)
  - Is `chainId` included? (Essential for replay protection across EVM chains)
  - Are trailing `0, 0` included for signature placeholder? (EIP-155 requirement)
  - How are fields serialized? (Check RLP encoder for integer encoding - big-endian? Little-endian? Variable length?)

- [ ] `build_eip1559_transaction()` function:
  - EIP-1559 format: `0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])`
  - Is type byte `0x02` prepended correctly?
  - Is field count exactly 9?
  - Are `maxPriorityFeePerGas` and `maxFeePerGas` both present?
  - How is access list handled? (Empty array by default?)

- [ ] Signature finalization:
  - After ECDSA produces (r, s), how is v/v_parity calculated?
  - Legacy: v = 27 + chainId*2 + 0/1 (parity)? Or v = 0x1b/0x1c?
  - EIP-1559: v = 0/1 (parity only)?
  - Look for "finalize" functions - do they exist?
  - **CRITICAL**: Is the preimage signed the same as the broadcast transaction? (Preimage vs final TX confusion is common attack)

**Test cases to look for**:
- [ ] Are there tests comparing generated RLP to MetaMask/ethers.js output?
- [ ] Do tests verify signature on actual EVM network? (Or just round-trip encode/decode?)
- [ ] Are edge cases tested? (Gas price overflow? Oversized data field? Address validation?)

**Potential vulnerabilities to hunt**:
- RLP field ordering wrong (invalid TX)
- Signature finalization missing or wrong (TX cannot be broadcast)
- Preimage/final TX confusion (sign wrong bytes)
- Chainid not included in legacy (replay across chains)
- v_parity encoding wrong (signature validation fails)

### 4. Multi-Chain Nonce Management

**Files**: `pallets/tss/src/types.rs` (NonceState struct), `pallets/tss/src/multichain.rs` (nonce tracking logic)

**Examine NonceState**:
```rust
pub struct NonceState {
    pub last_allocated: Option<u64>,      // Highest nonce ever allocated
    pub last_accepted: Option<u64>,       // Highest CONFIRMED nonce
    pub pending: BoundedVec<PendingNonce, MaxPendingNonces>,  // Max 64 pending
}
```

**Questions**:
- [ ] **Nonce Window Size**: Max 64 pending nonces. Is this sufficient?
  - If TX takes 12 blocks to confirm, how many TXs are in flight? (Could exceed 64 easily)
  - What happens when window fills? (Does allocation fail or overwrite?)
  - Look for code handling BoundedVec capacity exceeded
- [ ] **Nonce Gaps**: If allocated nonce 0, 1, 3 (missing 2), does RPC accept TX with nonce 3?
  - Ethereum requires sequential nonces
  - Can a stuck/failed TX block all future ones?
  - Look for logic handling unconfirmed nonces below last_accepted
- [ ] **Status Transitions**:
  - `FailedTemp(retry_count)` - does it ever auto-transition to Allocated for retry?
  - Or does it stay FailedTemp forever?
  - Who clears FailedTemp nonces?
- [ ] **Concurrent Signing**: Can two parallel signing sessions allocate same nonce?
  - Look at `increment_agent_nonce()` - is it atomic?
  - Is there a race between check and increment?

**Potential vulnerabilities to hunt**:
- Nonce collision (two TXs with same nonce = one fails, funds at risk)
- Window saturation causing DoS (can't allocate new nonce)
- Failed nonces blocking future ones (stuck state)
- Non-deterministic behavior on nonce wraparound (u64::MAX + 1)

### 5. FSA & OPOC Integration

**Files**: `pallets/tss/src/fsa.rs` (OPOC processor)

**Understand the flow**:
```
pallet_uomi_engine::Outputs<T> storage
    ↓
fsa.rs::process_opoc_requests() fetches by request_id
    ↓
Parses Action JSON: {action_type, data, chain_id, to, from, value, gas_limit, nonce, tx_type}
    ↓
build_ethereum_transaction() creates preimage
    ↓
ECDSA signature collected off-chain
    ↓
finalize_ethereum_transaction() adds signature
    ↓
submit_multi_chain_transaction() sends to RPC
```

**Questions**:
- [ ] **JSON Parsing** (line: `miniserde::json::from_str()`):
  - What if `Action` JSON is malformed?
  - Current: logs warning, returns `Ok(None)` - is this safe?
  - Can attacker cause parser error that blocks subsequent actions?
  - Look for: does `from_str()` validate all required fields?

- [ ] **Field Extraction** in Action:
  - `to` address: is it validated as 20 bytes? (Line with `to.parse()`)
  - `data`: is hex string properly decoded? (Even length? Valid chars?)
  - `value`, `gas_limit`, `nonce`: are they parsed as decimal or hex?
  - What if hex decoding fails? (Fallback to raw bytes?)

- [ ] **Request ID Deduplication**:
  - `LastOpocRequestId` tracks last processed ID
  - Loop processes max 10 requests per call: `for _ in 0..10u8`
  - What if request IDs are: 1, 2, 4, 5? (Missing 3)
  - Does it skip missing IDs or stop?
  - Look for: `if !pallet_uomi_engine::Outputs::<T>::contains_key(&current) { continue; }`
  - So it DOES skip missing IDs - is this correct behavior?

- [ ] **Transaction Building Fallback** (lines in multichain.rs):
  - If structured action build fails, does it fall back to raw `data`?
  - What if builder succeeds but produces invalid RLP?
  - Is fallback signed/broadcast without validation?

**Potential vulnerabilities to hunt**:
- JSON parsing DoS (malformed action blocks processor)
- Field extraction errors (silent data loss)
- Hex decoding silently drops invalid input
- Request ID skip causing missed transactions
- Fallback mechanism signing wrong data

### 6. Session State Machines

**Files**: `pallets/tss/src/sessions.rs`, `client/tss/src/session/manager.rs`, `client/tss/src/ecdsa/message_processor.rs`

**State machine transitions to verify**:

**DKG Session (On-chain)**:
```
Pending → DKGInProgress → DKGComplete → DKGSuperseded (or DKGFailed)
```

- [ ] Can state transition be triggered by anyone or only participants?
- [ ] Once DKGComplete, is it immutable? (Can't change to DKGFailed?)
- [ ] Expiration: Sessions timeout after 100 blocks
  - Look at `check_expired_sessions()` - does it clean up ALL state?
  - Can expired session data orphan storage?
  - Are related entries (AggregatedPublicKeys, DkgSessions, SessionState) kept in sync?

**ECDSA Message Processor (Off-chain)**:
- [ ] Look at `message_processor.rs` state machine
  - Transitions between: KeyGen → Sign → SignOnline?
  - Can messages for different phases be mixed?
  - Is phase validation enforced (error if wrong phase)?
  - What happens to buffered messages if session times out?

**Potential vulnerabilities to hunt**:
- State transition without proper validation (skip DKGInProgress → straight to DKGComplete)
- Race condition: session expires while being processed
- Storage orphans (DKGFailed session leaves aggregate key in storage)
- Buffered messages processed after session expiration

### 7. Validator Reporting & Slashing

**Files**: `pallets/tss/src/lib.rs` (report_participant, report_tss_offence extrinsics), `pallets/tss/src/validators.rs`

**Understand the slashing mechanism**:
- [ ] Threshold to slash: 2/3 of validators must report same participant
  - How is "same" defined? (Same session ID? Same violation type?)
  - Look for: `ReportedParticipants` storage
- [ ] `ParticipantReportCount`: tracks reports per participant
  - Who can increment? (Any validator?)
  - Is there a minimum threshold before penalty? (No - increments on every report?)
  - What happens at count = 1, 2, etc.?

**Potential vulnerabilities to hunt**:
- Spam reporting (any validator can report, no cost)
- False positives (innocent validator reported and slashed)
- Collusion (2 validators collude to slash 1 honest validator if < 3 total validators)

### 8. Message Buffering & Out-of-Order Handling

**Files**: `client/tss/src/session/message_processor.rs`

**Questions**:
- [ ] Buffer data structure: `HashMap<SessionId, Vec<TssMessage>>`
  - Is buffer size bounded?
  - What if 1000 Round 2 messages arrive before Round 1?
  - Does buffer grow unbounded → OOM?
- [ ] Processing order:
  - When session reaches Round 2, are buffered messages processed in FIFO?
  - Or are they processed in arrival order (which might be random)?
  - Can attacker reorder buffered messages by controlling network?
- [ ] Buffer cleanup:
  - When is buffer cleared? (Only when session completes?)
  - Can orphaned buffers from failed sessions leak memory?

**Potential vulnerabilities to hunt**:
- Buffer saturation DoS (attacker fills buffer)
- Out-of-order processing (LIFO instead of FIFO)
- Orphaned buffers (failed sessions leave messages in buffer forever)

### 9. Cryptographic Libraries & Versions

**Check**: Verify crate versions and known issues

- [ ] `frost-ed25519 = "2.1.0"`:
  - Any GitHub issues? (https://github.com/ZcashFoundation/frost)
  - Is this the official Zcash Foundation crate?
  - Any security advisories?

- [ ] `multi_party_ecdsa = "0.1.3"`:
  - Is this the OpenTSS fork or official?
  - Any known vulnerabilities?
  - Last updated when?

- [ ] `rlp = "0.6"`:
  - Is RLP encoding correct for EVM?
  - Any edge cases with integer encoding?

### 10. Attack Scenarios to Model

**Simulate these attacks on paper**:

1. **Nonce Collision Attack**: Attacker controls network, can they make two TXs have same nonce?
   - Trace through code: `increment_agent_nonce()` → `NonceState::last_allocated` → increment → store
   - Is there a race window?

2. **Signature Replay Attack**: Can attacker take a signature from Ethereum and replay on Polygon?
   - Check: does preimage include `chainId`?
   - Check: is `chainId` signed (part of keccak256)?
   - Trace through signing to finalization

3. **DKG Denial of Service**: Can attacker force DKG to fail?
   - Send invalid Round 1 commitment → does it abort?
   - Or does it mark that participant as failed and continue with k-1?

4. **Off-Chain / On-Chain Divergence**: What if off-chain DKG completes but `submit_dkg_result` TX fails?
   - Result: off-chain thinks key is ready, on-chain doesn't
   - Can TXs be broadcast using non-existent key?

## Testing & Validation Points

Look for test files (`tests.rs`, `prop_tests.rs`, `test_framework.rs`):
- [ ] Are there tests for RLP encoding? (Compare to known good values)
- [ ] Are there tests for multi-chain nonce management?
- [ ] Are there Byzantine adversary tests? (What if k-1 participants are malicious?)
- [ ] Are there replay attack tests?
- [ ] Do tests actually call real RPC endpoints or mock them?

## Red Flags - Things That Should NOT Exist

- [ ] `unsafe` blocks in crypto code
- [ ] `todo!()`, `unimplemented!()`, `panic!()` in critical paths
- [ ] Secrets in logs, debug output, or error messages
- [ ] Hardcoded private keys or nonces
- [ ] Comments like "FIXME", "TODO", "XXX" in crypto modules
- [ ] Conditional crypto logic (e.g., `#[cfg(debug)]` that changes security)

---

## Deliverables

For each finding, provide:
1. **File & Line**: Exact location
2. **Code Snippet**: Quote the problematic code
3. **Why It's A Problem**: Security impact
4. **Attack Proof**: How to exploit it
5. **Fix**: Specific code change

Order by severity: CRITICAL → HIGH → MEDIUM → LOW

Focus on **implementa actual code you see**, not theoretical problems. If a potential vulnerability isn't present in code, say so. If code looks correct, explain why.
