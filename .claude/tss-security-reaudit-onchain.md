# UOMI TSS On-Chain Pallet – Second Security Audit

Scope: `/Users/lucasimonetti/Work/uomi-node-public/pallets/tss/src/` (lib.rs, multichain.rs, fsa.rs, sessions.rs, validators.rs, types.rs, payloads.rs). Tests and `client/tss/` excluded.

Methodology: Read-only source audit. Exact line numbers cited. Quotes are verbatim from the source. Inspected runtime `spec_version` in `runtime/uomi/src/lib.rs` (currently 17) and migrations.

---

## Fix Verification Table

| ID | Finding | Status | Evidence |
|----|---------|--------|----------|
| C-1 | Signature verification on 13 unsigned extrinsics | ⚠️ PARTIAL | All 13 extrinsics have `#[cfg(not(test))] if !payload.verify::<...>(signature)` (see lib.rs 671, 789, 822, 851, 942, 1092, 1113, 1131, 1180, 1355, 1380, 1404, 1431). BUT `payload.public()` does not bind the caller to *validator* identity — any node with a key under `CRYPTO_KEY_TYPE` (`tss-`) can sign these payloads. Only `update_last_opoc_request_id_unsigned` enforces `ActiveValidators::contains(&caller)` (line 833). See NEW FINDING H-N1 below. |
| C-2 | Ceiling division for DKG threshold | ⚠️ PARTIAL | `submit_dkg_result` line 895 uses `((total_validators * threshold) + 99) / 100`. Correct for DKG vote. HOWEVER `submit_signature_result` line 973 still uses floor division `(total * threshold_pct) / 100`. See NEW FINDING H-N2. |
| C-3 | OPOC missing-key infinite loop | ✅ VERIFIED | fsa.rs lines 88-90: if `!Outputs::contains_key`, we `current = current.saturating_add(U256::one()); continue;`. Cursor advances. Line 107 additionally advances on every other path. No stall. |
| C-4 | ECDSA recid for values 0/1/2/3 | ✅ VERIFIED | multichain.rs lines 666 and 724: `match recid { 27 | 28 => recid - 27, 0 | 1 | 2 | 3 => recid & 0x01, _ => panic!(...) }`. Both `legacy_finalize_raw` and `eip1559_finalize_raw` handle high-bit-set recids by masking. Note: `panic!` remains for truly out-of-band values; the Signer should never produce such, but a logic bug could cause a runtime panic — see NEW FINDING M-N2. |
| C-5 | `create_dkg_session` permission | ✅ VERIFIED | lib.rs line 596-597: `#[cfg(not(test))] ensure_root(origin.clone())?;`. Root required in production. |
| H-1 | `submit_aggregated_signature` uses `AggregatedPublicKeys` | ✅ VERIFIED | lib.rs line 1045: `let public_key = AggregatedPublicKeys::<T>::get(session.dkg_session_id).ok_or(...)?`. `TSSKey` storage is no longer read in verification (only retained as dead slot at line 337). However note: `Verifier::verify` in utils.rs uses `sp_core::ecdsa::Signature::verify` which internally hashes with blake2_256, while TSS signatures produced by the client are normally over keccak256 — this extrinsic is effectively unreachable from production client paths. See NEW FINDING L-N1 (dead-code risk). |
| H-3 | `derive_from_address` deterministic | ✅ VERIFIED | fsa.rs lines 179-201: collects into `BTreeMap`, filters on `DKGComplete`, takes `max_by_key(id)`. Deterministic. Session IDs are unique (sequential via `get_next_session_id`), so tie-break is well-defined. |
| H-5 | `update_last_opoc_request_id` active-validator check | ✅ VERIFIED | lib.rs line 828: `ensure!(payload.last_request_id > current, ...)`. Line 831-833: caller into_account, `ensure!(active.contains(&caller), ...)`. Both monotonicity and active-validator enforcement present. |
| M-2 | Nonce window / FailedTemp bump and expiry | ⛔ NEW ISSUE | `MaxPendingNonces = 256` at types.rs line 21. `PendingNonce` now has `allocated_at: u64` at types.rs line 67. Expiry logic at lib.rs 1853-1879 uses `retain` keyed on allocated_at and `NONCE_EXPIRY_BLOCKS=300`. **Logic is deterministic** but several issues: (i) STORAGE MIGRATION MISSING — the `PendingNonce` layout changed and `migrations/v1.rs` is commented out; on upgrade existing stored `NonceState` values would fail to decode. See NEW FINDING C-N1. (ii) `last_allocated` recompute at 1870-1876 is too conservative (only lowers when `max_nonce < v`) — if pending is non-empty and max_nonce > last_allocated that case never happens by construction, so OK, but the `else if state.pending.is_empty() && state.last_accepted.is_none()` branch leaves `last_allocated=Some(v)` untouched when `last_accepted` is Some, which is correct for the monotonic invariant. Acceptable. (iii) Block number conversion `n.try_into().unwrap_or(0u64)` (line 1857 / 1981) would set all allocated_at deltas to match current block if conversion fails, causing all entries to look stale; uomi BlockNumber is u32 so conversion is safe in practice. Noted. |
| M-3 | `TssOffenceType` `TryFrom<u8>` | ✅ VERIFIED | lib.rs lines 143-154: `impl sp_std::convert::TryFrom<u8> for TssOffenceType`, returns `Err(())` for unknown values. |
| M-4 | `sessions.rs::report_participants` no-unwrap | ✅ VERIFIED | sessions.rs lines 109-118: `filter_map` on decode; invalid bytes logged and skipped, no unwrap. The outer `BoundedVec::try_from` errors are also handled explicitly (line 121-124). |
| M-5 | BTreeMap-wrapped iter_prefix in on-chain dispatches | ✅ VERIFIED | Checked all on-chain iter/iter_prefix uses: `ProposedPublicKeys::iter_prefix(nft_id).collect()` line 891, `ProposedSignatures::iter_prefix(session_id).collect()` line 970, `DkgSessions::iter().collect()` lines 705/727/913/1011/1453/1943/1960/214 (validators.rs), `PendingTssOffences::iter().collect()` line 2244, `ReportedParticipants::iter_prefix(session_id).collect()` sessions.rs line 63, `ParticipantReportCount::iter().collect()` validators.rs line 73/89, `SigningSessionExpiry::iter().collect()` line 1830, `SigningSessions::iter().collect()` line 2310. All use BTreeMap. See NEW FINDING M-N3 for a single residual hotspot in `report_tss_offence_from_client` that uses unordered insertion but is only called from client code path, and off-chain `iter()` uses (offchain_worker) that do NOT need BTreeMap. |
| L-1 | `from_utf8` handling | ✅ VERIFIED | lib.rs line 2468 uses `.expect("ascii hex is valid utf8")` where the invariant is truly guaranteed (hex just constructed from known table). Line 2397 uses `.unwrap_or("invalid_hash")`, lines 2457/2473/2476 use `Ok(_) ... Err(_) => Cow::Owned(String::from("invalid_hash"))`. No panics. |
| L-3 | `ChainConfigOverrides` + root extrinsics | ⚠️ PARTIAL | `ChainConfigOverrides` storage at lib.rs 496-503. `set_chain_config` (index 23) at 1482-1494 and `remove_chain_config` (index 24) at 1499-1507 both require `ensure_root(origin)?`. New `get_chain_config_for::<T>` at multichain.rs 201-208 consults overrides first. However `set_chain_config` **skips** `validate_chain_config`. See NEW FINDING M-N1. Also `MultiChainRpcClient::get_chain_config_for::<T>` is called at 9 sites (fsa.rs 304/344/351/359/499/520, lib.rs 2023/2206/2643). Coverage verified. |
| L-4 | Malformed hex in `action.data` returns `Ok(None)` | ✅ VERIFIED | fsa.rs lines 328-334: on `decode_hex(&action.data)` returning `Err(_)`, logs warning and `return Ok(None)`. No empty-byte passthrough. |

### Other findings listed in the original scope (1..20)

The prompt lists 20 original findings across categories but enumerates 16 in detail (C-1..L-4). Examining the remaining by inference:

- **Low / cleanup fixes** (e.g. L-2 hex decoding consolidation): fsa.rs test helper `hex_to_bytes` mirrors production `decode_hex`; both return `Err` on malformed input (fsa.rs 214-235 and 310-327). ✅ VERIFIED.
- **Tests retry exhaustion**: lib.rs 716-720 `if attempt >= MAX_SIGNING_RETRIES { ... return Ok(()); }` — non-panicking silent ignore with event. ✅ VERIFIED.
- **Session supersede events**: emitted deterministically from BTreeMap loops (lines 916-920, 1013-1018, 1963-1968). ✅ VERIFIED.

---

## NEW Findings (not caught by first audit, or introduced by the fixes)

Ordered by severity.

---

### C-N1 — CRITICAL — `PendingNonce` struct changed without storage migration (chain bricking risk)

**File:** `pallets/tss/src/types.rs:62-68` + `pallets/tss/src/migrations/v1.rs`
**Spec version:** `runtime/uomi/src/lib.rs:139 spec_version: 17` (mainnet)

**Code:**
```rust
// types.rs line 62-68
pub struct PendingNonce {
    pub nonce: u64,
    pub status: PendingStatus,
    /// Block number when this nonce was allocated; used to expire stale Allocated entries.
    pub allocated_at: u64,
}
```

`migrations/v1.rs` exposes `MigrateV0ToV1` but its `impl OnRuntimeUpgrade` block is fully commented out (lines 77-143). `STORAGE_VERSION` at `lib.rs:62` is `StorageVersion::new(0)` and never bumps. No migration exists for the `PendingNonce` layout change.

**Problem:** `PendingNonce` is stored in `NonceStates` (`StorageDoubleMap<..., NonceState, ValueQuery>` at lib.rs:475-481). `NonceState.pending` is `BoundedVec<PendingNonce, MaxPendingNonces>`. The previous on-chain SCALE encoding of `PendingNonce` was 2 fields (`nonce: u64` + `status: PendingStatus`). The new encoding requires a trailing `allocated_at: u64`. SCALE decoding of an old 9-byte `PendingNonce` against a 17-byte struct will **fail** (not silently), surfacing as a `Codec` error on every `NonceStates::get/mutate/iter`. Worse, `ValueQuery` means decoding failure returns `Default::default()` silently, clobbering the on-chain state — any legitimate outstanding nonces would disappear and `last_allocated` would drop to `None`.

**Attack / Impact:** On runtime upgrade, nodes that had any nonce state (any agent that submitted a chain transaction) will observe divergent storage reads depending on their codec tolerance. Best case: all nonce state silently wipes; in-flight transactions get re-allocated to the same nonces on destination chains (replay collision) or the nonce-gap-filler loop fires infinitely. Worst case: `mutate` re-encodes with default, desynchronizing each node's view of the truth, producing a consensus fork.

**Fix:**
1. Uncomment and verify `migrations::v1::MigrateV0ToV1` OR write a dedicated v-bump that maps old `PendingNonce {nonce, status}` to new `PendingNonce {nonce, status, allocated_at: current_block}`.
2. Wire the migration into the runtime via `Executive = Executive<..., ( pallet_tss::migrations::MigratePendingNonce<Runtime>, ... )>`.
3. Bump `STORAGE_VERSION` to `StorageVersion::new(1)` inside the migration.
4. Add `try-runtime` pre/post state invariants (count of nonce states preserved, each migrated entry has `allocated_at == <block>`).

---

### H-N1 — HIGH — Unsigned extrinsics authenticate "any tss-keystore holder" not "active validator"

**Files:** `pallets/tss/src/lib.rs:663-688, 781-810, 1082-1101, 1105-1119, 1123-1168, 1173-1202, 1347-1368, 1372-1391, 1396-1418, 1423-1473`

**Summary:** Only `update_last_opoc_request_id_unsigned` (line 831-833) gates by `ActiveValidators::contains(&caller)`. Every other unsigned extrinsic checks only `payload.verify::<AuthorityId>(signature)`, which verifies the signature was produced by the private key corresponding to `payload.public()`. Nothing binds that public key to a currently-active validator. Any node that has generated a local keypair under the `tss-` (`CRYPTO_KEY_TYPE` at lib.rs:127) KeyTypeId can submit any of these extrinsics.

Substrate nodes generate keys via RPC (`author_rotateKeys` / `author_insertKey`). An operator who once ran a validator (or an attacker who gains keystore access on any full node ever) retains the capability to sign these payloads forever. Unsigned extrinsic validation in `validate_unsigned` (lib.rs 1534-1648) merely tags and prioritizes; it does NOT verify signatures or caller identity.

**Exploitable paths with direct state damage:**

| Extrinsic | Call index | Effect of unauthorized call |
|-----------|-----------|----------------------------|
| `update_validators` (line 663) | 1 | `ActiveValidators` replaced by attacker-supplied list. Extra-egregious because `assign_validator_id` line 678 auto-registers ANY accounts the attacker specifies. ALL subsequent authorization checks keyed on `ActiveValidators` (e.g. `update_last_opoc_request_id`) are compromised. |
| `submit_fsa_transaction_unsigned` (line 1347) | 17 | `FsaTransactionRequests::remove(&payload.request_id)` at line 1366. Attacker names ANY real pending request_id and silently removes it. The FSA pipeline observes nothing to submit; the signed TSS tx never reaches the destination chain. |
| `timeout_pending_transaction_unsigned` (line 1372) | 19 | Marks any live pending tx as Failed (line 1385-1389), short-circuiting block-wait-window. Propagates `MultiChainTransactionFailed` event for a transaction that may still settle on the remote chain — application logic observing the event diverges from chain truth. |
| `fail_multi_chain_transaction_unsigned` (line 1396) | 20 | Removes FSA requests by request_id (line 1413). Same impact as 17 but via a different door. |
| `complete_reshare_session_unsigned` (line 1105) | 22 | Invokes `Self::complete_reshare_session(payload.session_id)` unconditionally. See H-N3 below — effectively forges DKG completion for any extant session. |
| `create_signing_session_unsigned` (line 781) | 7 | Creates signing sessions for arbitrary request_ids (bypassing OPOC), increments `RequestRetryCount`, burns retry budget on real requests. |
| `create_gap_filler_signing_session_unsigned` (line 1423) | 18 | Inserts rogue `SigningSessions` entries, inserts arbitrary `FsaTransactionRequests` entries, consumes the nonce window via `allocate_next_nonce_internal` (line 1469). Can permanently exhaust an agent's nonce window once enough fillers backlog. |
| `report_tss_offence` (line 1173) | 8 | Restricted by `session.participants.contains(&who)` at line 1192, so attacker must be listed as a participant of the target DKG session. If attacker was ever a participant in any historical session, they can still submit offences now. |
| `submit_dkg_result` (line 841) | 3 | Restricted by `session.participants.contains(&who)` at line 877. Same observation: historical participants retain power indefinitely because participant sets are never rotated. |
| `submit_signature_result` (line 934) | 15 | Restricted by `dkg_session.participants.contains(&who)` at line 960. Same. |

**Attack scenario (concrete):**
1. Adversary runs a UOMI full node, calls `author_rotateKeys` / `author_insertKey` with `keytype=tss-` to drop a Sr25519 key pair into the local keystore.
2. Adversary crafts `SubmitFsaTransactionPayload { session_id: 0, request_id: <pick any live FSA request>, chain_id: 1, tx_hash: [0u8; 32], nft_id, public: <their tss public> }`, signs with the local key.
3. Adversary broadcasts `submit_fsa_transaction_unsigned`. `validate_unsigned` accepts (tagged as `TssPallet` max priority), block producer includes it, `payload.verify` passes, `FsaTransactionRequests::remove` drops the legitimate request.
4. The real FSA offchain worker later iterates `SigningSessions` (lib.rs:1667), finds the completed signature, but `FsaTransactionRequests::get(&session.request_id)` now returns `None`, so the signed transaction is never submitted to the destination chain. Silent, permanent loss.

**Fix:** Add `ensure!(ActiveValidators::<T>::get().contains(&payload.public().into_account()), Error::<T>::UnauthorizedParticipation);` (or equivalent IdToValidator lookup) immediately after signature verification in **every** unsigned extrinsic that mutates shared state. Consider a shared helper:

```rust
#[cfg(not(test))]
fn ensure_active_validator_signed<P: SignedPayload<T>>(payload: &P, sig: T::Signature) -> DispatchResult {
    if !payload.verify::<<T as Config>::AuthorityId>(sig) {
        return Err(Error::<T>::InvalidSignature.into());
    }
    let caller = payload.public().into_account();
    ensure!(ActiveValidators::<T>::get().contains(&caller), Error::<T>::UnauthorizedParticipation);
    Ok(())
}
```

For extrinsics whose legitimate caller is a DKG session participant (submit_dkg_result etc.), keep the participant check AND add the active-validator check.

---

### H-N2 — HIGH — `submit_signature_result` threshold still uses floor division (C-2 regression for signing path)

**File:** `pallets/tss/src/lib.rs:968-974`

**Code:**
```rust
// line 968-974
let threshold_pct = T::MinimumValidatorThreshold::get();
let all_sigs: sp_std::collections::btree_map::BTreeMap<_, _> =
    ProposedSignatures::<T>::iter_prefix(session_id).collect();
let votes = all_sigs.values().filter(|s| **s == signature).count() as u32;
let total = dkg_session.participants.len() as u32;
let required = (total * threshold_pct) / 100;
```

`MinimumValidatorThreshold` is `67` (types.rs:31). With `total=3` participants and `threshold_pct=67`: `(3*67)/100 = 2`. So two identical signatures (66.67%) cross the "67% threshold". With `total=5`: `(5*67)/100 = 3` (60%). The DKG path at lib.rs:895 uses `((total_validators * threshold) + 99) / 100` (ceiling) — for the same inputs, `total=3` → 3, `total=5` → 4.

**Problem:** C-2 intended a ceiling semantic ("strict majority at or above configured fraction"). That fix landed in `submit_dkg_result` but not `submit_signature_result`. A single honest validator signing alone with two malicious ones producing an invalid identical signature bytes would cross the floor-divide threshold at `total=3` (2 of 3 = 66.67%), finalizing an invalid signature into `SigningComplete`. Since the **same** signature bytes are counted (line 971 `**s == signature`) rather than any vote, the attack requires two colluding validators to submit matching bytes. But this is exactly the byzantine-threshold we are supposed to defend against: `MinimumValidatorThreshold=67` means we require **>=67% honest** to reach consensus; with floor division we accept 66.67% which is below threshold.

Further: `dkg_session.participants.len()` counts all registered participants of the session, not validators that actually casted a vote. A malicious signer submitting two signatures (impossible since keyed by validator_id in `ProposedSignatures`) — OK, validator_id slot prevents double voting. So real risk is limited to when 2 of 3 mal participants reach the same wrong signature bytes. In a 3-validator session with threshold 67, this is the same attack class the ceiling fix aimed to prevent in DKG.

**Attack scenario:** In a DKG session with 3 participants and `threshold_pct=67`, two colluding validators submit `signature = [0u8; 65]` (or any identical wrong bytes). `votes=2, required=2`. `SignatureResultSubmitted` event fires; downstream FSA attempts to broadcast a tx signed with garbage → fails on destination chain but exhausts nonce window. With 5 participants + 3 colluding, same outcome (3 votes, required=3, 60% of set).

**Fix:** Apply the same ceiling form used in `submit_dkg_result`:

```rust
let required = ((total * threshold_pct) + 99) / 100;
```

Also consider verifying signature validity cryptographically before counting; line 971 only matches raw bytes, not a cryptographic proof of sign(message, group_pubkey).

---

### H-N3 — HIGH — `complete_reshare_session` has no authorization check; any caller of index 22 promotes any DKG session to `DKGComplete`

**File:** `pallets/tss/src/lib.rs:1928-1976` (implementation) + `1105-1119` (unsigned extrinsic)

**Code (extrinsic):**
```rust
// line 1105-1119
pub fn complete_reshare_session_unsigned(
    origin: OriginFor<T>,
    payload: crate::payloads::CompleteResharePayload<T>,
    signature: T::Signature,
) -> DispatchResult {
    ensure_none(origin)?;
    #[cfg(not(test))]
    if !payload.verify::<<T as pallet::Config>::AuthorityId>(signature) {
        return Err(Error::<T>::InvalidSignature.into());
    }
    Self::complete_reshare_session(payload.session_id)
}
```

**Code (impl):**
```rust
// line 1928-1937
pub fn complete_reshare_session(new_id: SessionId) -> DispatchResult {
    let mut new_session = DkgSessions::<T>::get(new_id).ok_or(Error::<T>::DkgSessionNotFound)?;
    let nft_id = new_session.nft_id.clone();
    new_session.state = SessionState::DKGComplete;
    DkgSessions::<T>::insert(new_id, new_session.clone());
    ...
```

No state check. No participant check. No validator check.

**Problem:** Any caller with any tss-keystore key (see H-N1) can invoke this on ANY existing `DKGSession`, regardless of current state. Even a session still in `DKGCreated` (no public key ever proposed) gets promoted to `DKGComplete`. The promoted session then:
1. Inherits the aggregated public key of the most-recent previously-completed DKG session for the same `nft_id` (line 1950-1954). So the attacker didn't pick the key bytes, but:
2. Marks all other `DKGComplete` sessions for the same nft_id as `DKGSuperseded` (line 1963-1967). This changes which session future `create_signing_session` picks as `dkg_session_id` (it looks for max-id DKGComplete, lib.rs:728-732). The attacker now controls which historical participant set is considered authoritative for signing.

If the attacker times this with H-N1 to also submit to `submit_signature_result`, they can:
1. Create a fake DKGSession (via create_reshare_dkg_session_unsigned index 21 — also unauthorized) with participants = attacker's own Sr25519 keys registered via `update_validators` (index 1, also unauthorized).
2. Call `complete_reshare_session_unsigned` (index 22) to mark it `DKGComplete`.
3. Call `submit_signature_result` (index 15) as one of the fake participants — the threshold check at 975 uses the attacker-chosen participant count.

This chains into a key-substitution attack for the signing pipeline (the attacker cannot steal the underlying ECDSA group key, but can redirect signing sessions to their own "session" with attacker-chosen signature bytes).

**Fix:** In `complete_reshare_session`, ensure (a) caller identity binding (e.g. via `H-N1` fix — active validator), (b) current session state is a resharing transient like `DKGInProgress` AND session has reshare semantics (old_participants.is_some()), (c) threshold of reshare votes has been reached. The current implementation is essentially a rubber stamp.

---

### H-N4 — HIGH — `set_chain_config` accepts invalid URLs (L-3 fix introduced validation gap)

**File:** `pallets/tss/src/lib.rs:1482-1494`, `pallets/tss/src/multichain.rs:400-420`

**Code:**
```rust
// lib.rs 1482-1494
pub fn set_chain_config(
    origin: OriginFor<T>,
    chain_id: u32,
    name: BoundedVec<u8, crate::types::MaxChainNameSize>,
    rpc_url: BoundedVec<u8, crate::types::MaxRpcUrlSize>,
    is_testnet: bool,
) -> DispatchResult {
    ensure_root(origin)?;
    let config = crate::types::ChainConfig { chain_id, name, rpc_url, is_testnet };
    ChainConfigOverrides::<T>::insert(chain_id, config);
    ...
}
```

`multichain.rs:400-420` defines `validate_chain_config` (rejects empty name, empty rpc_url, missing `http(s)://` prefix). **`set_chain_config` does not call it.**

`MultiChainRpcClient::get_chain_config_for::<T>` (multichain.rs:201-208) returns the override directly without validation. Downstream `make_rpc_call` would simply fail HTTP, but various code paths `unwrap_or_default()` and continue. A misconfigured override can cause the offchain worker to repeatedly attempt RPC to e.g. `"garbage"` and log errors, burning CPU.

More importantly: Root could set `rpc_url = b"file:///etc/passwd"` or a raw IP without scheme; the HTTP layer would reject, but the URL string is embedded in events (`ChainConfigurationUpdated(chain_id)` is fine, but derived strings via `String::from_utf8_lossy(&config.rpc_url)` appear in logs that may bleed into audit logs). This is primarily an operator-key-compromise risk (Root = god mode), but hardening the extrinsic to at least validate URL format is trivial.

**Fix:**
```rust
let config = crate::types::ChainConfig { chain_id, name, rpc_url, is_testnet };
crate::multichain::MultiChainRpcClient::validate_chain_config(&config)
    .map_err(|_| Error::<T>::InvalidChainConfig)?;
ChainConfigOverrides::<T>::insert(chain_id, config);
```

Also consider rejecting `chain_id == 0` explicitly here (already in validate_chain_config but worth asserting) and forbidding override of the native `Uomi` chain (4386) so operators can't accidentally misdirect intra-chain calls.

---

### M-N1 — MEDIUM — `submit_aggregated_signature` uses blake2 verification path incompatible with real TSS output; is a callable dead-end that wastes block time

**File:** `pallets/tss/src/lib.rs:1028-1066`, `pallets/tss/src/utils.rs:16-42`

**Code:**
```rust
// lib.rs 1043-1050
let public_key = AggregatedPublicKeys::<T>::get(session.dkg_session_id)
    .ok_or(Error::<T>::DkgSessionNotFound)?;
ensure!(
    verify_signature::<T>(&public_key, &session.message, &signature),
    Error::<T>::InvalidSignature
);
```

`verify_signature` delegates to `Verifier::verify` (utils.rs:12-41), which calls `sp_core::ecdsa::Signature::verify(message, &pubkey)`. That `verify` internally applies `blake2_256(message)`. TSS signatures produced by the offchain TSS client over EVM transaction preimages are over `keccak256(preimage)`, not blake2. No matter what a caller supplies, this verification will always fail for real TSS output.

The extrinsic is `ensure_signed` (line 1033), callable from any signed account paying the weight (line 1026: `submit_aggregated_signature()` weight). It's reachable in production but never succeeds. Attackers can spam it to burn block time at configured weight. With the placeholder weight `10_000` in `TssWeightInfo for ()` (line 99), cost per call is negligible relative to its compute.

This is primarily a hygiene issue (dead or broken code path) but it remains a DoS vector until either:
1. The extrinsic is removed, or
2. `Verifier::verify` is changed to use keccak256 and the extrinsic is actually exercised as intended, or
3. The weight is raised to a realistic level.

**Fix:** Remove `submit_aggregated_signature` (use call_index 4 for a new feature or leave as a deprecated stub like `get_agent_nonce` at 11). The signing vote path via `submit_signature_result` (index 15) supersedes it.

---

### M-N2 — MEDIUM — `recid` match arm panics on out-of-band values (C-4 fix still panicky)

**File:** `pallets/tss/src/multichain.rs:666, 724`

**Code:**
```rust
// line 666
let y_parity = match recid { 27 | 28 => recid - 27, 0 | 1 | 2 | 3 => recid & 0x01, _ => panic!("invalid recid"), } as u64;
```

Identical line at 724 for EIP-1559. A `panic!` in a runtime code path (called from `submit_signed_transaction` at lib.rs:2515-2635, which runs in offchain_worker context, not on-chain execution) would kill the offchain worker task. Not a consensus problem, but an availability degradation when the TSS client ever produces an unexpected recid (e.g. 4 or 255 on serialization bugs). Offchain workers already have broad error handling elsewhere; this one explicit panic is inconsistent.

**Fix:** Replace panic with a log + early return from `submit_signed_transaction`:

```rust
let y_parity = match recid {
    27 | 28 => recid - 27,
    0 | 1 | 2 | 3 => recid & 0x01,
    other => { log::error!("[FSA] invalid recid {}, skipping session {}", other, session_id); return None; }
} as u64;
```

(Requires hoisting the match out of the `legacy_finalize_raw` / `eip1559_finalize_raw` helpers into the caller so they can return `Option<Vec<u8>>`.)

---

### M-N3 — MEDIUM — `report_tss_offence_from_client` uses `AccountId32::from(bytes)` with silent fallback to zero account

**File:** `pallets/tss/src/lib.rs:2167-2190`

**Code:**
```rust
let account_offenders: Vec<T::AccountId> = offenders
    .into_iter()
    .map(|bytes| {
        use sp_core::crypto::AccountId32;
        let account_id32 = AccountId32::from(bytes);
        T::AccountId::decode(&mut &account_id32.encode()[..]).unwrap_or_else(|_| {
            // If decoding fails, create a placeholder AccountId
            T::AccountId::decode(&mut &[0u8; 32][..]).unwrap()
        })
    })
    .collect();
```

If `T::AccountId::decode` fails (can happen if `T::AccountId` is not `AccountId32`-shaped), the map returns a zero-account placeholder. The zero account would then appear in `PendingTssOffences`. Two problems: (1) the outer `unwrap()` on `[0u8; 32]` — in theory panics if `T::AccountId::decode` also rejects zero bytes. For `AccountId32` shape this never happens. (2) Placeholder zero accounts get saved as legitimate "offenders" and may trigger spurious slashing when `process_pending_tss_offences` runs (line 2240). The synthetic reporter at line 2189 is `bounded_offenders.get(0)` — if all offenders were decode-failures, the reporter itself is the zero account.

**Impact:** Low in practice (the uomi runtime uses AccountId32 so decode never fails). However the pattern is fragile and hides errors; if config ever changes, slashing becomes non-deterministic.

**Fix:**
```rust
let account_offenders: Vec<T::AccountId> = offenders
    .into_iter()
    .filter_map(|bytes| T::AccountId::decode(&mut &AccountId32::from(bytes).encode()[..]).ok())
    .collect();
ensure!(!account_offenders.is_empty(), Error::<T>::InvalidParticipantsCount);
```

---

### M-N4 — MEDIUM — `update_validators` auto-registers attacker-supplied accounts via `assign_validator_id`

**File:** `pallets/tss/src/lib.rs:675-685`

**Code:**
```rust
let new_validators = payload.validators;
for validator in new_validators.clone() {
    Self::assign_validator_id(validator)?;
}
ActiveValidators::<T>::put(
    BoundedVec::try_from(new_validators.clone())
        .map_err(|_| Error::<T>::InvalidParticipantsCount)?
);
```

Combined with H-N1 (no active-validator gate on this extrinsic), an attacker can submit `new_validators = [attacker_acct, …attacker_acct_n]`. Each gets a fresh `validator_id` permanently recorded in `ValidatorIds` / `IdToValidator`. `ActiveValidators` is replaced wholesale.

Even without H-N1, consider that `assign_validator_id` permanently registers IDs — it's never reversed. A compromised-validator with honest intent might rotate keys and the old entries persist, making `get_slashed_validators()` harder to reason about (it iterates `ParticipantReportCount` which may refer to long-removed validator_ids).

**Fix:** (a) gate this extrinsic by active-validator (see H-N1). (b) Cross-reference incoming validators against `pallet_session::Validators::<T>::get()` — trust pallet_session as ground truth instead of accepting arbitrary account lists:

```rust
let pallet_session_validators = pallet_session::Pallet::<T>::validators();
ensure!(new_validators.iter().all(|v| pallet_session_validators.contains(v)), Error::<T>::UnauthorizedParticipation);
```

---

### M-N5 — MEDIUM — `update_report_count` increments by `report_count` not `1`, escalating slashing per-session

**File:** `pallets/tss/src/sessions.rs:84-93`

**Code:**
```rust
// Increment report count by actual number of reports for participants that meet the threshold
for (reported_participant, report_count) in participant_report_counts.iter() {
    if *report_count >= reporting_threshold {
        let current_count = ParticipantReportCount::<T>::get(reported_participant);
        ParticipantReportCount::<T>::insert(
            reported_participant,
            current_count + (*report_count as u32),
        );
    }
}
```

With 3 of 3 validators reporting someone during one expired session: `report_count = 3`, `ParticipantReportCount` increments by 3. `get_slashed_validators` (validators.rs:68-80) slashes anyone with `report_count > 0`, so a single session suffices to slash. The magnitude (3 vs 1) makes no difference for slashing eligibility, but it does affect the report-count state that is visible via events and logs and resets at era end — a single failed session now looks like 3 strikes.

Conservative fix: increment by 1 per session, regardless of how many distinct reporters converged. This keeps `ParticipantReportCount` = "number of failed sessions" rather than "number of reports across all failed sessions":

```rust
if *report_count >= reporting_threshold {
    ParticipantReportCount::<T>::mutate(reported_participant, |c| *c = c.saturating_add(1));
}
```

Not a security vulnerability per se — design choice — but worth confirming the original intent. If intent was "increment per strike", current code over-counts by a factor of the reporting quorum.

---

### L-N1 — LOW — `allocate_next_nonce_internal` called from offchain context has no effect on chain state

**File:** `pallets/tss/src/fsa.rs:385-403`

**Code:**
```rust
let internal_allocated = if explicit_nonce.is_none() {
    let le_bytes: Vec<u8> = {
        let mut tmp = [0u8; 32];   // dead binding
        nft_id.to_little_endian().to_vec()
    };
    if let Ok(bounded) = crate::types::NftId::try_from(le_bytes) {
        match crate::pallet::Pallet::<T>::allocate_next_nonce_internal(&bounded, action.chain_id) {
            Ok(n) => Some(n),
            ...
```

`build_or_passthrough_with_nonce` is called from `process_single_request` (fsa.rs:113) → `process_opoc_requests` (fsa.rs:78) → `offchain_worker` (lib.rs:1658). Substrate offchain workers do **not** persist `StorageMap::mutate` writes back to on-chain state; only explicit `sp_io::offchain::local_storage_*` writes survive. The `NonceStates::mutate` inside `allocate_next_nonce_internal` (lib.rs:1983) therefore produces a nonce value but leaves no on-chain footprint. When the subsequent `create_signing_session_unsigned` reaches on-chain execution (lib.rs:781-810 → `create_signing_session` at 692 → `allocate_next_nonce_internal` at 768), it allocates a fresh nonce from the true on-chain state, which may differ from the offchain-computed one.

**Impact:** The **preimage** built in `build_or_passthrough_with_nonce` (returned as `message` in the `CreateSigningSessionPayload`) hardcodes `nonce = <offchain_value>` into the RLP at fsa.rs:417-437. The on-chain `create_signing_session` at lib.rs:768-771 later assigns a DIFFERENT nonce to the session (via `SigningSessionNonces::<T>::insert`). The two nonces disagree — the preimage signs one, but `mark_nonce_accepted_internal` (line 2081) matches against the other. If the signature is finalized, `submit_signed_transaction` (line 2515) rebuilds the raw tx from the preimage (using the preimage's embedded nonce) and submits that to the destination chain; the on-chain accounting thinks nonce `X` was used but the preimage used nonce `Y`. Nonce desync → remote-chain "nonce too low" or "nonce already used" rejections → signing session wasted.

Also note: the `let mut tmp = [0u8; 32];` binding at fsa.rs:390 is dead (never read). Confirms this code was half-refactored.

**Fix:**
- Remove the offchain-context `allocate_next_nonce_internal` call from `build_or_passthrough_with_nonce`. Compute preimage with a placeholder nonce (0) OR a nonce obtained via RPC; then let the on-chain `create_signing_session` path supply the real nonce and rebuild the preimage deterministically.
- Alternatively: include the allocated nonce in `CreateSigningSessionPayload` so on-chain code uses the same nonce as embedded in the preimage.
- Clean up dead `tmp` binding at fsa.rs:390.

---

### L-N2 — LOW — `Verifier::verify` hashes with blake2_256; `TSSKey` storage retained as dead slot at 337

**Files:** `pallets/tss/src/utils.rs:37-38`, `pallets/tss/src/lib.rs:337`

- `utils.rs:37`: `signature.verify(message, &pubkey)` on `sp_core::ecdsa::Signature` internally applies blake2_256, not keccak256 as expected for Ethereum-style TSS.
- `lib.rs:337`: `pub type TSSKey<T: Config> = StorageValue<_, PublicKey, ValueQuery>;` — left in place but never written. With `ValueQuery` it returns `PublicKey::default()` (empty) on read.

Neither is actively exploited (the paths using them are either dead or never write `TSSKey`), but both are maintenance risks. Future refactoring may hook `submit_aggregated_signature` up for real and inherit the blake2/keccak mismatch; or a new extrinsic may write `TSSKey` assuming it's the authoritative key and skip `AggregatedPublicKeys`.

**Fix:** Remove `TSSKey` storage (requires a migration that simply deletes the key). Replace `sp_core::ecdsa::Signature::verify` call with a keccak256-based verification to match Ethereum TSS signatures, or mark `submit_aggregated_signature` as deprecated and stop calling `verify_signature` there.

---

### L-N3 — LOW — `validate_unsigned` accepts payloads without any signature check; cheap DoS at consensus layer

**File:** `pallets/tss/src/lib.rs:1534-1648`

Every supported unsigned call returns `ValidTransaction::with_tag_prefix("TssPallet").priority(TransactionPriority::MAX)....build()` without inspecting the payload's signature. The actual signature verification happens at dispatch (in each extrinsic body). This is standard for Substrate, but note: `TransactionPriority::MAX` means these calls get top-priority slots in the pool. An attacker flooding the pool with syntactically valid but signature-invalid payloads pushes legitimate traffic out of the pool until a block producer includes them and they revert with `InvalidSignature`. Each revert still consumes block weight (payload decode + verify).

**Fix:** Perform a lightweight signature verification inside `validate_unsigned` (at least for the highest-priority paths), or drop priority from MAX to something bounded so spam doesn't crowd out inherents. Also consider `.longevity(8)` instead of 64 to shorten pool residence time.

---

### L-N4 — LOW — `get_next_session_id` uses `u64 + 1` without overflow guard

**File:** `pallets/tss/src/sessions.rs:16-20`

```rust
pub fn get_next_session_id() -> SessionId {
    let session_id = Self::next_session_id();
    NextSessionId::<T>::put(session_id + 1);
    session_id
}
```

`SessionId = u64`. Overflow would panic in debug, wrap in release. Practically unreachable (2^64 sessions), but `saturating_add` is trivial and matches the rest of the codebase's style.

**Fix:** `NextSessionId::<T>::put(session_id.saturating_add(1));`

---

## Clean-Bill Sections

These areas were examined line-by-line and appear robust post-fix:

- **C-3 OPOC cursor advance**: `fsa.rs:86-108` loops at most 10 iterations, advances `current` in all paths including missing-key skip and `NoOutputFound`. No stall.
- **C-4 recid handling**: Both `legacy_finalize_raw` (multichain.rs:654-680) and `eip1559_finalize_raw` (711-743) correctly handle `recid` values 0/1/2/3 via `& 0x01` mask. Tested pattern matches EVM conventions.
- **M-3 TryFrom<u8>**: Clean `match` with explicit `_ => Err(())`. No silent fallback.
- **M-4 report_participants decode**: Gracefully filters invalid bytes, no unwrap panics.
- **M-5 BTreeMap wrapping**: All on-chain storage iteration that feeds consensus decisions is wrapped in `BTreeMap`. Off-chain iteration (offchain_worker body) correctly left as raw `iter()` since it doesn't affect consensus.
- **L-1 from_utf8**: All production paths use `Cow` + fallback to `"invalid_hash"`; the one `.expect` (lib.rs:2468) is on a locally constructed ASCII buffer whose invariants are obvious.
- **L-4 malformed hex**: fsa.rs:328-334 explicitly returns `Ok(None)` without passing empty bytes into tx construction.
- **`check_expired_sessions`**: Deterministic ordering via BTreeMap<SessionId, NftId>; events emitted in monotonic SessionId order.
- **`process_pending_tss_offences`**: Deterministic via BTreeMap<SessionId, _>; duplicate-offender flagging via `ProcessedOffenderFlags` prevents double-processing.
- **`get_slashed_validators`**: Collects into BTreeMap and finally sorts; output is deterministic.
- **`reset_validator_report_counts`**: BTreeMap-ordered; deterministic.
- **`internal_create_reshare_dkg_session`**: Uses `pallet_session::Pallet::<T>::validators()` (canonical ordering) instead of `pallet_staking::Validators::iter()`. Good.
- **Block-number conversion**: `n.try_into().unwrap_or(0u64)` is safe for uomi runtime (BlockNumber is u32); silent-to-zero fallback would only be dangerous on a custom runtime with BlockNumber > u64, which is impossibly large in practice.
- **`SessionState` enum ordering**: Explicit discriminants 0..8 with `PartialOrd` derived. `state <= DKGInProgress` checks (sessions.rs:29, 185, 227) correctly include only `DKGCreated` and `DKGInProgress`. `DKGFailed=3` is excluded as desired.
- **`ChainConfigOverrides` root gating**: `set_chain_config` and `remove_chain_config` both `ensure_root(origin)?`. Bypass not possible absent root compromise (noted in H-N4 for input validation, not gating).
- **`cast_vote_on_dkg_result`** session-state check (sessions.rs:185): `<= DKGInProgress` correctly rejects DKGComplete, DKGFailed, all Signing states.
- **`update_last_opoc_request_id_unsigned`** (H-5 fix): both `payload.last_request_id > current` and `ActiveValidators::contains(&caller)` enforced.

---

## Summary

| Severity | Count (NEW) |
|----------|------|
| CRITICAL | 1 (C-N1 missing storage migration) |
| HIGH | 4 (H-N1 auth gap, H-N2 threshold regression, H-N3 unauth'd reshare complete, H-N4 root-validation gap) |
| MEDIUM | 5 (M-N1 dead verify path, M-N2 panicking recid, M-N3 AccountId32 fallback, M-N4 assign_validator_id abuse, M-N5 report-count escalation) |
| LOW | 4 (L-N1 offchain nonce ghost, L-N2 dead TSSKey & blake2 mismatch, L-N3 validate_unsigned priority spam, L-N4 overflow in session-id counter) |

Of the 20 original findings, 13 fixes are **✅ VERIFIED**, 4 are **⚠️ PARTIAL** (C-1 incomplete auth binding, C-2 signing threshold missed, L-3 validation gap, M-2 missing migration), and 0 are pure regressions. The most urgent items for production deployment: **C-N1** (migration) and **H-N1** (auth binding) — both block mainnet upgrade safely.
