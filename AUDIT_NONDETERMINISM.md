# Audit: Remaining Non-Determinism Sources in uomi-engine, TSS, and IPFS Pallets

**Date:** 2026-03-05  
**Error:** `"Digest item must match that calculated"` → state root divergence between validators  
**Scope:** On-chain code paths only (`on_initialize`, `on_finalize`, extrinsics, inherents)

---

## CRITICAL ISSUES (Active non-determinism in on-chain execution paths)

### ISSUE 1 — `ipfs_operations()`: `CidsStatus::iter()` into unsorted Vec (INHERENT)

**File:** `pallets/ipfs/src/lib.rs` lines 745–768  
**Severity:** **CRITICAL**  
**Code:**
```rust
fn ipfs_operations(current_block: U256) -> Result<(...), DispatchError> {
    let mut usable: Vec<...> = Vec::new();
    let mut to_remove: Vec<...> = Vec::new();

    for (cid, (expires_at, usable_from)) in CidsStatus::<T>::iter() {  // ← NON-DETERMINISTIC ORDER
        if expires_at != U256::zero() && current_block > expires_at {
            to_remove.push((cid, (expires_at, usable_from)));
        }
    }
    for (cid, (expires_at, usable_from)) in CidsStatus::<T>::iter() {  // ← NON-DETERMINISTIC ORDER
        if Self::is_majority_pinned(&cid) && usable_from == U256::zero() {
            usable.push((cid, (expires_at, U256::from(0))));
        }
    }
    Ok((usable, to_remove))
}
```

**Why it's non-deterministic:**  
`CidsStatus` is a `StorageMap`. Its `iter()` order depends on the trie key hash, which can differ between native and WASM execution. This function is called by **both** `create_inherent` (block author, typically native) and `check_inherent` (validators, typically WASM). While `check_inherent` does set-based comparison (so the inherent passes validation), the **content of the Vecs inside the inherent extrinsic** has non-deterministic ordering. All validators execute the same inherent extrinsic from the block so state writes are the same, **however** if there's any edge case where `is_majority_pinned()` fluctuates (e.g., race between block author and importer seeing different `NodesPins` due to a reorg), the two calls produce different SETS — causing `check_inherent` to reject the block, which then hits the `on_finalize` assert, halting the chain.

**Fix:** Sort both Vecs before returning, or collect into a BTreeMap first:
```rust
fn ipfs_operations(current_block: U256) -> Result<(...), DispatchError> {
    let all_cids: sp_std::collections::btree_map::BTreeMap<_, _> = CidsStatus::<T>::iter().collect();

    let mut usable = Vec::new();
    let mut to_remove = Vec::new();

    for (cid, (expires_at, usable_from)) in all_cids.iter() {
        if *expires_at != U256::zero() && current_block > *expires_at {
            to_remove.push((cid.clone(), (expires_at.clone(), usable_from.clone())));
        }
    }
    for (cid, (expires_at, usable_from)) in all_cids.iter() {
        if Self::is_majority_pinned(cid) && *usable_from == U256::zero() {
            usable.push((cid.clone(), (expires_at.clone(), U256::from(0))));
        }
    }
    Ok((usable, to_remove))
}
```

---

### ISSUE 2 — `internal_create_reshare_dkg_session`: Raw `DkgSessions::iter()` for `prev_id`

**File:** `pallets/tss/src/validators.rs` lines 205–210  
**Severity:** **CRITICAL** — runs inside on-chain extrinsic AND `on_initialize` era transition  
**Code:**
```rust
let mut prev_id: SessionId = 0;
for (sid, existing) in crate::pallet::DkgSessions::<T>::iter() {     // ← NOT collected into BTreeMap
    if existing.nft_id == nft_id && matches!(existing.state, crate::pallet::SessionState::DKGComplete) {
        if sid > prev_id { prev_id = sid; }
    }
}
```

**Why it's non-deterministic:**  
While the `max` logic means the *result* (`prev_id`) is the same regardless of order, this is fragile. More importantly, this function is called during `handle_era_transition()` → `create_reshare_session_for_validator_change()` → `internal_create_reshare_dkg_session()`, which runs from `on_initialize`. If any future refactor adds early-exit logic or additional side effects, the non-deterministic order would cause state divergence. Also, the comment style elsewhere in the codebase explicitly warns about this pattern.

**Fix:**
```rust
let all_sessions: sp_std::collections::btree_map::BTreeMap<_, _> = crate::pallet::DkgSessions::<T>::iter().collect();
let prev_id = all_sessions.iter()
    .filter(|(_, existing)| existing.nft_id == nft_id && matches!(existing.state, crate::pallet::SessionState::DKGComplete))
    .map(|(sid, _)| *sid)
    .max()
    .unwrap_or(0);
```

---

### ISSUE 3 — `create_signing_session`: `SigningSessions::iter()` + `DkgSessions::iter()` not collected

**File:** `pallets/tss/src/lib.rs` lines 678–712  
**Severity:** **HIGH** — runs on-chain via unsigned extrinsic `create_signing_session_unsigned`  
**Code:**
```rust
// Line 680
for (_sid, existing) in SigningSessions::<T>::iter() {          // ← NON-DETERMINISTIC
    if existing.request_id == request_id {
        match existing.state {
            SessionState::SigningInProgress => { has_in_progress = true; break; }
            _ => {}
        }
    }
}

// Line 708
let dkg_session_id = DkgSessions::<T>::iter()                  // ← NON-DETERMINISTIC
    .filter(|(_, s)| s.nft_id == nft_id && s.state == SessionState::DKGComplete)
    .max_by_key(|(id, _)| *id)
    .map(|(id, _)| id)
    .ok_or(Error::<T>::DkgSessionNotFound)?;
```

**Why it's non-deterministic:**  
The `SigningSessions::iter()` with `break` introduces order-dependency — while the final boolean value is the same, different execution paths through the iterator cause different amounts of storage reads. In native vs WASM, the amount of trie traversal differs, which can affect weight metering. The `DkgSessions::iter()` with `max_by_key` is technically safe but inconsistent with the project-wide pattern of collecting into BTreeMap first.

**Fix:**
```rust
// For duplicate check:
let sessions: sp_std::collections::btree_map::BTreeMap<_, _> = SigningSessions::<T>::iter().collect();
let has_in_progress = sessions.values().any(|s| s.request_id == request_id && s.state == SessionState::SigningInProgress);

// For DKG lookup:
let dkg_sessions: sp_std::collections::btree_map::BTreeMap<_, _> = DkgSessions::<T>::iter().collect();
let dkg_session_id = dkg_sessions.iter()
    .filter(|(_, s)| s.nft_id == nft_id && s.state == SessionState::DKGComplete)
    .max_by_key(|(id, _)| *id)
    .map(|(id, _)| *id)
    .ok_or(Error::<T>::DkgSessionNotFound)?;
```

---

### ISSUE 4 — `create_gap_filler_signing_session_unsigned`: Raw `DkgSessions::iter()` + `SigningSessions::iter()`

**File:** `pallets/tss/src/lib.rs` lines 1353 and 1876  
**Severity:** **HIGH** — on-chain extrinsic  
**Code:**
```rust
// Line 1353
let dkg_session_id = DkgSessions::<T>::iter()
    .filter_map(|(sid, sess)| if sess.nft_id == nft_id { Some((sid, sess)) } else { None })
    .max_by_key(|(sid, _)| *sid)
    .map(|(sid, _)| sid)
    .ok_or(Error::<T>::DkgSessionNotFound)?;

// Line 1876
for (_sid, sess) in SigningSessions::<T>::iter() {
    if sess.request_id == req_id { exists = true; break; }
}
```

**Same issue as #3.** Collect into BTreeMap first.

---

### ISSUE 5 — `complete_reshare_session`: Raw `DkgSessions::iter()` for `maybe_prev`

**File:** `pallets/tss/src/lib.rs` lines 1767–1770  
**Severity:** **HIGH** — on-chain extrinsic via `complete_reshare_session_unsigned`  
**Code:**
```rust
let maybe_prev = DkgSessions::<T>::iter()
    .filter(|(id, s)| *id != new_id && s.nft_id == nft_id && s.state == SessionState::DKGComplete)
    .max_by_key(|(id, _)| *id)
    .map(|(id, _)| id);
```

**Fix:** Collect into BTreeMap first, consistent with other places.

---

### ISSUE 6 — `get_slashed_validators`: `ParticipantReportCount::iter()` into unsorted Vec

**File:** `pallets/tss/src/validators.rs` lines 69–77  
**Severity:** **MEDIUM** — result used for `.contains()` checks only (currently safe), but fragile  
**Code:**
```rust
pub fn get_slashed_validators() -> Vec<T::AccountId> {
    let mut slashed_validators = Vec::new();
    for (validator, report_count) in ParticipantReportCount::<T>::iter() {   // ← NON-DETERMINISTIC
        if report_count > 0 {
            slashed_validators.push(validator);
        }
    }
    slashed_validators
}
```

**Fix:** Collect into BTreeSet or sort the Vec:
```rust
pub fn get_slashed_validators() -> Vec<T::AccountId> {
    let mut slashed: Vec<_> = ParticipantReportCount::<T>::iter()
        .filter(|(_, count)| *count > 0)
        .map(|(v, _)| v)
        .collect();
    slashed.sort();
    slashed
}
```

---

### ISSUE 7 — `reset_validator_report_counts`: `ParticipantReportCount::iter()` into unsorted Vec

**File:** `pallets/tss/src/validators.rs` lines 83–100  
**Severity:** **MEDIUM** — writes are independent per validator, but log ordering and events (if any) may differ  
**Code:**
```rust
let reported_validators: Vec<(T::AccountId, u32)> = ParticipantReportCount::<T>::iter()
    .filter(|(_, count)| *count > 0)
    .collect();                                                            // ← NON-DETERMINISTIC ORDER
```

**Fix:** Collect into BTreeMap:
```rust
let reported_validators: sp_std::collections::btree_map::BTreeMap<T::AccountId, u32> =
    ParticipantReportCount::<T>::iter()
        .filter(|(_, count)| *count > 0)
        .collect();
```

---

### ISSUE 8 — `opoc_get_outputs`: `NodesOutputs::iter_prefix().find()` instead of `contains_key`

**File:** `pallets/uomi-engine/src/opoc.rs` lines 1210–1213  
**Severity:** **MEDIUM** — functionally correct but non-deterministic traversal order  
**Code:**
```rust
let is_validator_output =
    NodesOutputs::<T>
        ::iter_prefix(*request_id)
        .find(|(account_id, _output_data)| account_id == &validator) != None;
```

**Why it's problematic:**  
`iter_prefix` traverses trie keys in an order that differs between native/WASM. Using `.find()` means different amounts of trie traversal occur on different nodes, which affects metering and potentially PoV size accounting. Use `contains_key` instead.

**Fix:**
```rust
let is_validator_output = NodesOutputs::<T>::contains_key(*request_id, &validator);
```

---

## MEDIUM ISSUES (Defensive improvements needed)

### ISSUE 9 — `update_report_count`: `ReportedParticipants::iter_prefix` nested iteration

**File:** `pallets/tss/src/sessions.rs` lines 57–79  
**Severity:** **MEDIUM** — logic bug (duplicate counting) and non-deterministic iteration  
**Code:**
```rust
for (_reporter, reported_list) in ReportedParticipants::<T>::iter_prefix(session_id) {
    for reported_participant in reported_list.iter() {
        let mut report_count = 0;
        for (_, inner_reported_list) in ReportedParticipants::<T>::iter_prefix(session_id) {
            // ...
        }
        if report_count == reporting_threshold {
            let current_count = ParticipantReportCount::<T>::get(reported_participant);
            ParticipantReportCount::<T>::insert(reported_participant, current_count + 1);
        }
    }
}
```

**Why it's problematic:**  
1. The outer `iter_prefix` is non-deterministic in order
2. A participant reported by N reporters gets their count incremented N times (once per outer-loop iteration that mentions them), which is a **logic bug** (should be +1 total)
3. The increments are cumulative: each `current_count + 1` reads the storage which may already be incremented by a previous iteration

While the **final count** is deterministic (same N reporters × same +1 per reporter), this is fragile and confusing. Collect the outer iteration into a BTreeMap and deduplicate participants before incrementing.

---

### ISSUE 10 — `ProcessedOpocTimeoutEraResets::iter_prefix` in `reset_validators_current_era_points_for_current_era`

**File:** `pallets/uomi-engine/src/opoc.rs` lines 1593–1601  
**Severity:** **LOW** — writes are independent per validator, final state is order-independent  
**Code:**
```rust
let processed_validators: Vec<T::AccountId> =
    <crate::pallet::ProcessedOpocTimeoutEraResets<T>>::iter_prefix(current_era)
        .map(|(validator, _)| validator).collect();   // ← NON-DETERMINISTIC ORDER
```

**Fix:** Collect into BTreeMap or sort the Vec. Each call to `reset_validator_current_era_points` is independent, but sorting makes the behavior explicit.

---

### ISSUE 11 — `opoc_nodes_works_operations_count`: Logic bug overcounting works

**File:** `pallets/uomi-engine/src/opoc.rs` lines 1299–1312  
**Severity:** **LOW** (not non-deterministic, but a logic bug affecting validator selection)  
**Code:**
```rust
fn opoc_nodes_works_operations_count(...) -> u32 {
    let works_count_storage = NodesWorks::<T>::iter_prefix(validator).count() as u32;
    let works_count_operations = match nodes_works_operations.get(&validator) {
        Some(works) => works.iter().filter(|(_, &is_work)| is_work).count() as u32,
        None => 0,
    };
    works_count_storage + works_count_operations  // ← OVERCOUNTS: doesn't subtract false entries
}
```

**Why it's wrong:**  
Operations with `is_work = false` mean "remove from storage". The count should be `storage_count - false_count + true_count`, not `storage_count + true_count`. This causes validators to appear busier than they are, affecting the `first_free` selection logic. Not a non-determinism issue (all nodes compute the same wrong value), but a correctness bug.

---

## SUMMARY TABLE

| # | File | Line | Severity | On-chain? | Fix Required |
|---|------|------|----------|-----------|--------------|
| 1 | `pallets/ipfs/src/lib.rs` | 745–768 | **CRITICAL** | Inherent | Sort or BTreeMap |
| 2 | `pallets/tss/src/validators.rs` | 205–210 | **CRITICAL** | on_initialize | BTreeMap |
| 3 | `pallets/tss/src/lib.rs` | 678–712 | **HIGH** | Extrinsic | BTreeMap |
| 4 | `pallets/tss/src/lib.rs` | 1353, 1876 | **HIGH** | Extrinsic | BTreeMap |
| 5 | `pallets/tss/src/lib.rs` | 1767–1770 | **HIGH** | Extrinsic | BTreeMap |
| 6 | `pallets/tss/src/validators.rs` | 69–77 | **MEDIUM** | Extrinsic | Sort Vec |
| 7 | `pallets/tss/src/validators.rs` | 83–100 | **MEDIUM** | on_initialize | BTreeMap |
| 8 | `pallets/uomi-engine/src/opoc.rs` | 1210–1213 | **MEDIUM** | on_finalize | `contains_key` |
| 9 | `pallets/tss/src/sessions.rs` | 57–79 | **MEDIUM** | on_initialize | BTreeMap + dedup |
| 10 | `pallets/uomi-engine/src/opoc.rs` | 1593–1601 | **LOW** | on_finalize | Sort Vec |
| 11 | `pallets/uomi-engine/src/opoc.rs` | 1299–1312 | **LOW** | on_finalize | Fix count logic |

---

## ADDITIONAL RECOMMENDATIONS

1. **Ensure WASM runtime blob matches native binary.** The error "Digest item must match that calculated" is often caused by a WASM/native code mismatch. After applying ALL non-determinism fixes, do a **runtime upgrade** to deploy the new WASM blob on-chain.

2. **Run with `--execution=wasm` on all validators** as a temporary mitigation until all issues are fixed. This forces all validators to use the same WASM runtime, eliminating native/WASM divergence.

3. **Grep for remaining `::iter()` patterns** in ALL pallets to catch any missed instances:
   ```bash
   grep -rn '::iter()' pallets/*/src/*.rs | grep -v 'test' | grep -v '//' | grep -v 'BTreeMap'
   ```

4. **Consider adding a CI lint** that flags `StorageMap::iter()` / `StorageDoubleMap::iter()` usage without an immediately following `.collect::<BTreeMap>()`.
