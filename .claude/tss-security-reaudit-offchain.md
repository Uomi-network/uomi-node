# UOMI TSS Off-Chain Client — Second Security Re-audit

**Scope:** `/Users/lucasimonetti/Work/uomi-node-public/client/tss/src/` (excluding `test_framework*` and `tests/`).
**Date:** 2026-04-24.
**Goals:** (1) Verify prior fixes for H-2, M-1, M-6. (2) Hunt NEW vulnerabilities in the FROST Ed25519 DKG/signing code, multi-party ECDSA code, gossip, session management, keystore/panic paths, and logging.

---

## Executive Summary

The H-2 and M-1 fixes are effective. The M-6 fix is **partially effective in one verification path but is NOT applied in the production path** (see H-N1). In addition, 8 new findings were identified:

| # | Severity | Title |
|---|----------|-------|
| C-N1 | CRITICAL | Remote DoS via panics in `Announce` processing (`sr25519::Public::from_slice().unwrap()` and `try_into().unwrap()` on attacker-controlled lengths) |
| H-N1 | HIGH    | M-6 fix is bypassed in production: the real Announce verification path (session/message_processor.rs) does **not** include `challenge_answer` in the payload |
| H-N2 | HIGH    | PeerMapper can be poisoned — no check that Announce's `public_key_data` matches outer `sender_public_key`, allowing attacker to bind victim's PeerId → attacker's pubkey |
| H-N3 | HIGH    | Block-number replay protection is disabled (commented out in `TssValidator::validate`); captured signed messages can be replayed forever |
| H-N4 | HIGH    | Challenge-response anti-replay is a no-op — received `challenge_answer` is never compared to the nonce that was sent in GetInfo |
| M-N1 | MEDIUM  | ECDSA private keys (cl_sk, ec_sk, share_sk) and FROST signing shares are persisted to disk in **plaintext**, no zeroization, no file permissions hardening |
| M-N2 | MEDIUM  | Global-buffer check `buf.len() < MAX_BUFFERED_SESSIONS` is miscoded: once 64 sessions exist, even messages for an **already-buffered** session are dropped → amplifies DoS window |
| M-N3 | MEDIUM  | `get_key_package`, `get_signing_nonces`, `get_pubkey` in `dkghelpers.rs` perform `.map_err(...).unwrap()` — a storage read error panics the node |
| M-N4 | MEDIUM  | Sensitive data in logs: `TssMessage::DKGRound2(bytes, ...)` is printed with `{:?}` (line 245 session/message_processor.rs); FROST `signature_shares` printed via `log::info!` (signing_message_processor.rs:499) |
| L-N1 | LOW     | `log::debug!("[TSS] My Id is {:?}", _id)` leaks internal FROST identifier (ecdsa/message_processor.rs:668) — fingerprinting risk |
| L-N2 | LOW     | `println!` statements in production code paths (dkghelpers.rs:835, ecdsa/handler.rs:12) write to stdout bypassing log filtering |
| L-N3 | LOW     | `PeerMapper::add_peer` unconditionally overwrites existing mappings; combined with H-N2 this enables silent identity re-mapping |

---

## 1. Verification of Prior Fixes

### H-2 (private key JSON in debug logs) — **VERIFIED**

- `client/tss/src/ecdsa/message_processor.rs:492`
  ```rust
  log::debug!("[TSS] ECDSA Keygen successful, storing keys (redacted)");
  ```
- `client/tss/src/ecdsa/message_processor.rs:554`
  ```rust
  log::debug!("[TSS] ECDSA Reshare successful, storing keys (redacted)");
  ```

Both lines no longer print `msg` (which is the JSON blob containing `privkey.cl_sk`, `ec_sk`, `share_sk`). A broader sweep of `log::*` calls in `client/tss/src/` found no other site dumping `msg` for keygen/reshare success results.

However, note the **related M-N4 finding**: other `log::debug!` sites still print message bodies containing encrypted secret packages (DKG round1/round2) and signature shares.

### M-1 (unbounded message buffer) — **VERIFIED (with caveat M-N2)**

- `client/tss/src/session/message_processor.rs:8–10`
  ```rust
  const MAX_BUFFERED_PER_SESSION: usize = 128;
  const MAX_BUFFERED_SESSIONS: usize = 64;
  ```
- All 3 push sites (lines 173–184, 206–216, 259–276) are guarded by both `if buf.len() < MAX_BUFFERED_SESSIONS` and `if entry.len() < MAX_BUFFERED_PER_SESSION`. When capacity is reached, the code logs a warning and **does not push**. Verified.

Caveat: the global-buffer check has a subtle coding bug described in M-N2 that makes the DoS window worse, but the immediate memory growth is bounded.

### M-6 (announcement replay via `challenge_answer=0` bypass) — **PARTIALLY EFFECTIVE — SEE H-N1**

The fix *is* correctly implemented in:
- `client/tss/src/gossip/router.rs::process_announcement` (lines 153–157): always appends `challenge_answer.to_le_bytes()` to the signed payload.
- `client/tss/src/utils.rs::sign_announcment` (line 36): always appends `challenge_answer.to_le_bytes()`.

**But** `gossip/router.rs::process_announcement` is **never invoked in production** (see H-N1). The production path in `session/message_processor.rs` does NOT include `challenge_answer` in the reconstructed payload. Although the **outer** `SignedTssMessage.signature` still binds `challenge_answer` via `message.encode()`, the in-memory challenge accounting never cross-checks the value (H-N4), so the intended replay-protection logic is ineffective.

---

## 2. New Findings (ordered by severity)

### C-N1 — Remote DoS via panics when processing an Announce (CRITICAL)

**File / lines:** `client/tss/src/session/message_processor.rs:440`, `454`, `467`.

```rust
let public_key = &sr25519::Public::from_slice(&&public_key_data[..]).unwrap();
// ...
sr25519_verify(
    &signature[..].try_into().unwrap(),     // line 454 (test) and 467 (prod)
    &payload,
    public_key,
)
```

`sp_core::sr25519::Public::from_slice` returns `Err` when the input is not exactly 32 bytes. `signature[..].try_into::<[u8; 64]>` panics when `signature.len() != 64`. `TssMessage::Announce` carries the inner `public_key_data: TSSPublic (=Vec<u8>)` and `signature: TSSSignature (=Vec<u8>)` — both are length-unconstrained at decode time.

**Exploit path:**
1. Any validator V with access to the keystore can sign a `SignedTssMessage` whose inner message is `TssMessage::Announce(nonce, peer_id_bytes, /* pubkey */ vec![0u8; 10], /* sig */ vec![0u8; 32], 0)`.
2. Other nodes accept the outer signature (it's a normal sr25519 signature from V over `message.encode() || V_pubkey || block_number`), then reach line 440 and panic.
3. One malicious block-producing validator can thus crash **every other TSS-participating node** with a single gossip message.

The bounds checking must happen **before** unwrapping:
```rust
let public_key = match sr25519::Public::from_slice(&public_key_data[..]) {
    Ok(pk) => pk,
    Err(_) => { log::warn!("[TSS] Invalid Announce pubkey length"); return; }
};
let sig_bytes: [u8; 64] = match signature[..].try_into() {
    Ok(s) => s,
    Err(_) => { log::warn!("[TSS] Invalid Announce signature length"); return; }
};
```

The existing code in `gossip/router.rs::process_announcement` (lines 142–163) handles both cases correctly — the fix is to mirror that style inside `session/message_processor.rs` and **delete** the duplicated inner-verification block there (delegate to `process_announcement`).

---

### H-N1 — M-6 fix is bypassed in the production code path (HIGH)

**Files / lines:**
- `client/tss/src/session/message_processor.rs:449–452` (test branch) and `462–465` (non-test branch).
- `client/tss/src/gossip/router.rs:123–188` — the fixed function is here but is **dead in production**.

```rust
// session/message_processor.rs, lines 462–471 (non-test, production):
let mut payload = Vec::new();
payload.extend_from_slice(&public_key_data[..]);
payload.extend_from_slice(&peer_id_bytes[..]);
payload.extend_from_slice(&nonce.to_le_bytes());
// NOTE: challenge_answer is NOT included here.
sr25519_verify(
    &signature[..].try_into().unwrap(),
    &payload,
    public_key,
)
```

**Wiring check.** The production flow:
1. `GossipHandler::poll` → `process_gossip_notification` decodes the blob as `SignedTssMessage` and calls `handler.forward_to_session_manager(...)`.
2. That pushes the message to the session manager. The `GossipHandler::handle_announcment` (which calls `process_announcement`) is **never invoked** outside tests (confirmed by `grep -rn handle_announcment`).
3. The real Announce verification + `peer_mapper.add_peer(...)` happens in `session/message_processor.rs` (line 492) after the local reconstruction of the payload **without** `challenge_answer`.

**Impact.** While the outer `SignedTssMessage` signature still covers `message.encode()` (which includes `challenge_answer`), the intended replay-defense-in-depth inside the inner `sr25519::Signature` is absent. Combined with H-N4 (no value check on the challenge answer), the Announce remains effectively unbound to the outstanding GetInfo nonce. Also: the duplicated implementation is a code-smell divergence that will tempt further drift.

**Fix.** Remove the inline re-verification in `session/message_processor.rs` and call `process_announcement` instead (it already handles length errors, challenge binding, LRU replay cache). Alternatively, at minimum, mirror the exact payload construction including `challenge_answer.to_le_bytes()` at both call sites (test and non-test) of `session/message_processor.rs`.

---

### H-N2 — PeerMapper identity poisoning: no check that Announce `public_key_data` matches outer `sender_public_key` (HIGH)

**Files / lines:**
- `client/tss/src/session/message_processor.rs:432–517` (Announce handler).
- `client/tss/src/network/peer_mapper.rs:228–231` (`add_peer` blindly overwrites).

The Announce handler verifies only that an `sr25519` signature exists on `(public_key_data, peer_id_bytes, nonce)` with `public_key_data` as the verifier. It does **not** check `public_key_data == signed_message.sender_public_key`.

**Exploit.** Attacker A (validator, possibly one of the N TSS nodes):
1. Constructs `TssMessage::Announce(nonce, V.peer_id_bytes, A.pubkey, A.sign_inner(A.pubkey||V.peer_id_bytes||nonce||0), 0)`.
2. Wraps it in a `SignedTssMessage` signed by A's own keystore. Outer signature verifies (A_pubkey binds A.signature_outer).
3. Honest node receives this, runs the Announce branch, decides `is_valid_signature = true`, calls `peer_mapper.add_peer(V.peer_id, A.pubkey)`.
4. Because `add_peer` (`network/peer_mapper.rs:228`) uses `.insert()` with no rekey protection, any previously correct `V.peer_id → V.pubkey` binding is **silently overwritten**.

**Impact.** Afterwards, when V (the real victim) sends an ECDSA keygen message that arrives with `network_sender_peer_id = V.peer_id`, the session manager looks up `get_account_id_from_peer_id(V.peer_id)` and gets **A's** account_id. V's legitimate messages are then attributed to A, breaking DKG/signing correctness, offence reporting (A would be reported instead of actual offenders), and retry mechanism accounting. This interacts with on-chain slashing (the session manager calls `report_tss_offence`) — an attacker can get the wrong party slashed.

**Fix.** Add:
```rust
if public_key_data != &signed_message.sender_public_key[..] {
    log::warn!("[TSS] Announce inner pubkey != outer sender; rejecting");
    return;
}
```
(and similarly in `gossip/router.rs::process_announcement`). Also consider rejecting `add_peer` when an existing different pubkey is registered for the same `peer_id` — or at least logging a warning and requiring an explicit rebind flow.

---

### H-N3 — Block-number replay protection is disabled (HIGH)

**File:** `client/tss/src/validation/validator.rs:109–114`.

```rust
// Check block number to prevent replay attacks
// let current_block = (self.get_block_number)();
// if !verification::is_block_number_valid(&signed_message, current_block, self.max_message_age_blocks) {
//     log::warn!("[TSS]: Message block number invalid or too old from {}", sender.to_base58());
//     return ValidationResult::Discard;
// }
```

The comment in `session/message_processor.rs:52` states: "Block-age validation is performed in the gossip validator stage." But the gossip validator has this block commented out. `is_block_number_valid` exists (security/verification.rs:54) but has **no caller** in production.

**Impact.** A signed `TssMessage` from any time in the past remains valid forever. Captured DKG round 1/2 messages, SigningCommitments, or ECDSARetryRequests can be replayed against the same session (which is bounded by `session_timeout = 3600 s`) OR against a brand-new session if session IDs collide after cleanup. Most critical: the ANNOUNCE message is broadcast-and-accepted even if its block number is ancient, allowing an adversary to replay old Announces from retired validators to pollute `peer_mapper`.

**Fix.** Uncomment and re-enable the block-number check. The current value of `max_message_age_blocks = 100` (≈5 min at 3 s blocks) is reasonable. Consider also a per-`(sender, block_number)` dedup cache inside the validator so exact replays are discarded even within the freshness window.

---

### H-N4 — Challenge-response is a no-op: `challenge_answer` value is never compared to the issued nonce (HIGH)

**File:** `client/tss/src/session/message_processor.rs:474–489`.

```rust
if is_valid_signature {
    // Validate challenge if one existed
    {
        let mut outstanding = session_manager.outstanding_challenges.lock().unwrap();
        if let Some(sent_nonce) = outstanding.remove(&peer_id_bytes.clone()) {
            log::debug!("[TSS] Matching announcement to prior challenge nonce {}", sent_nonce);
            // Track satisfaction (bounded list of 512)
            let mut satisfied = session_manager.satisfied_challenges.lock().unwrap();
            satisfied.push((peer_id_bytes.clone(), sent_nonce));
            if satisfied.len() > 512 { satisfied.remove(0); }
        } else {
            log::debug!("[TSS] Announcement arrived without outstanding challenge (unsolicited or replay)");
        }
    }
    // If this announcement carries a challenge answer, ensure no spoof (optional future enhancement)
    if *challenge_answer != 0 { log::debug!("[TSS] Announcement includes challenge answer {}", challenge_answer); }
    // Add the peer to our peer_mapper
    ...
}
```

When the node sent a `GetInfo(validator_key, nonce)` challenge to a suspicious peer, it is supposed to only accept a subsequent Announce where `challenge_answer == nonce`. The code fetches `sent_nonce` from the map, logs it, but **never compares it with the received `challenge_answer`**. The `if *challenge_answer != 0` check is purely a debug log — an attacker can send `challenge_answer = 0` (or any arbitrary value) and still be admitted.

**Impact.** Combined with H-N3 (no block-age) and H-N2 (no pubkey/sender binding), the challenge-response anti-replay is effectively unimplemented.

**Fix.**
```rust
if let Some(sent_nonce) = outstanding.remove(&peer_id_bytes.clone()) {
    if *challenge_answer != sent_nonce {
        log::warn!("[TSS] Announce challenge_answer ({}) != sent nonce ({}); rejecting", challenge_answer, sent_nonce);
        return;
    }
    ...
}
```

---

### M-N1 — Long-term secrets (ECDSA private key JSON, FROST secret shares) are stored on disk in plaintext (MEDIUM)

**Files:**
- `client/tss/src/ecdsa/message_processor.rs:494–501` — stores the full ECDSA JSON (including `privkey.cl_sk`, `ec_sk`, `share_sk`) to `FileStorage` with `StorageType::EcdsaKeys`.
- `client/tss/src/dkg_session/session.rs:146–153` — stores FROST `KeyPackage` (includes the `signing_share`) to `FileStorage` with `StorageType::Key`.
- `client/tss/src/dkghelpers.rs:972–984` (`store_file`) — writes raw bytes via `File::create(path)?; file.write_all(bytes)?;` with no permission hardening, no encryption, no zeroization after use.

**Impact.** An attacker with read access to the node's data directory (`/var/lib/uomi/chains/uomi/tss/` or wherever the fallback base path points) recovers ECDSA signing-share material directly. In a production TSS deployment, this share + collusion with any other t-1 shares reconstructs the joint private key; or the sole share is sufficient to create invalid signatures / slash the holder if the attacker wants to frame them.

No use of the Substrate keystore for TSS shares; no `zeroize` crate anywhere (verified by grepping: no results).

**Fix recommendations.** In order of hardening effort:
1. `chmod 0600` the files on create (or use `OpenOptions::mode(0o600)`).
2. Wrap the data in an `AEAD` (ChaCha20-Poly1305) with a key derived from the operator-controlled keystore; or store the share directly inside Substrate's keystore under a TSS-specific `KeyTypeId`.
3. Add `zeroize::Zeroizing` on in-memory copies of serialized shares (secret packages, signing shares) so they don't linger in freed allocations.

---

### M-N2 — Global-buffer check prevents buffering for existing sessions when at capacity (MEDIUM, DoS amplification)

**File:** `client/tss/src/session/message_processor.rs:174, 207, 260`.

```rust
if buf.len() < MAX_BUFFERED_SESSIONS {
    let entry = buf.entry(*session_id).or_insert(Vec::new());
    if entry.len() < MAX_BUFFERED_PER_SESSION {
        entry.push(...);
    } else {
        log::warn!("...");
    }
} else {
    log::warn!("...");
}
```

When `buf.len() == MAX_BUFFERED_SESSIONS` (64), the outer check fails *even for a session that is already present in the buffer*. That means once 64 sessions occupy the buffer, **no further buffering happens at all**, not even for existing ones.

**Exploit.** An adversary sends 64 DKGRound1 messages for 64 fake session_ids they fabricated (each fake session_id is accepted for buffering because `!session_manager.session_exists(sid)` is true on line 170). Each new fake session_id adds a key to `buf`. Legitimate in-flight DKGs that need to buffer more than their current quota (e.g. out-of-order messages) are silently dropped.

**Fix.**
```rust
let entry = buf.entry(*session_id).or_insert_with(Vec::new);
let newly_created = entry.is_empty();
if !newly_created || buf.len() <= MAX_BUFFERED_SESSIONS {
    if entry.len() < MAX_BUFFERED_PER_SESSION {
        entry.push(...);
    }
}
```
or restructure so the "session count" check only applies when creating a new session key.

Additionally, consider tracking which `session_id`s are "real" (on-chain) vs. "speculative" (unseen in runtime events) and only allowing a small reservation for speculative buffering (e.g. 4–8 of the 64 slots).

---

### M-N3 — `Storage` trait helpers panic on I/O errors via `.map_err(..).unwrap()` (MEDIUM)

**File:** `client/tss/src/dkghelpers.rs:210–244`.

```rust
fn get_key_package(
    &self,
    session_id: SessionId,
    identifier: &Identifier
) -> Result<frost_ed25519::keys::KeyPackage, frost_ed25519::Error> {
    let data = self
        .read_data(session_id, StorageType::Key, Some(&identifier.serialize()[..]))
        .map_err(|err| {
            log::error!("Errrr {:?}", err);
            frost_ed25519::Error::DeserializationError
        })
        .unwrap();                  // <-- STILL UNWRAPS THE Result; map_err just transforms the Err
    frost_ed25519::keys::KeyPackage::deserialize(&data)
        .map_err(|_| frost_ed25519::Error::DeserializationError)
}
```

Same pattern in `get_signing_nonces` (line 232–233) and `get_pubkey` (line 241–242). The `map_err` rewrites the error type, but `unwrap()` still panics on any `Err`.

**Impact.** These helpers are called from `signing_message_processor.rs:76, 342, 524` and `dkg_message_processor.rs`. The key-package lookup occurs every time a signing commitment or signing package arrives. If storage I/O glitches (file deleted, permission change, corrupt file contents) or if an identifier lookup fails, the node panics instead of returning a `Result` that the caller can handle.

**Fix.** Replace `.unwrap()` with `?`:
```rust
let data = self.read_data(session_id, StorageType::Key, Some(&identifier.serialize()[..]))
    .map_err(|_| frost_ed25519::Error::DeserializationError)?;
```

---

### M-N4 — Sensitive / semi-sensitive data printed in debug/info logs (MEDIUM)

1. `client/tss/src/session/message_processor.rs:244–249`
   ```rust
   log::debug!(
       "[TSS] TssMessage::DKGRound2({:?}, {:?}, {:?})",
       session_id, bytes, recipient
   );
   ```
   `bytes` is the serialized FROST `round2::Package`. This package contains a `signing_share` that has been encrypted to the recipient — NOT cleartext — but revealing it in logs helps an attacker who later compromises the recipient reconstruct past rounds, and leaks per-session topology information.

2. `client/tss/src/session/signing_message_processor.rs:499`
   ```rust
   log::info!("signature_shares = {:?}", signature_shares);
   ```
   `SignatureShare` values are not themselves secrets (they are released to the combiner), but dumping all of them at `info` level (always-on in most deployments) is noisy and can expose timing/participation fingerprints. Use `debug!` at most, and redact.

3. `client/tss/src/session/dkg_message_processor.rs:106, 288` and `session/signing_message_processor.rs:279`
   ```rust
   log::debug!("[TSS] debug round1_packages = {:?}", round1_packages);
   log::error!("[TSS] Error {:?} Invalid data received as DKGRound2 = {:?}", e, bytes);
   log::debug!("[TSS] Debug SigningPackage = {:?}", signing_package);
   ```
   Round1 `Package` contains the participant's public commitment — public info — but at scale the log is noisy. The `DKGRound2` error log prints raw bytes (which might be malformed, yet still be a FROST ciphertext that an analyst could use). Recommend trimming to lengths / session IDs only.

**Fix.** Strip the payload from logs and leave only `session_id`, `recipient`, and `bytes.len()`.

---

### L-N1 — FROST identifier leaked in debug log (LOW)

**File:** `client/tss/src/ecdsa/message_processor.rs:668`.
```rust
log::debug!("[TSS] My Id is {:?}", _id);
```
`_id` is the local node's FROST `Identifier`. Combined with validator set metadata this uniquely identifies which node a log line came from. Not a secret, but useful for fingerprinting in log-pipeline breaches. Downgrade to `trace!` or remove.

### L-N2 — `println!` statements in production code (LOW)

- `client/tss/src/dkghelpers.rs:835`
  ```rust
  println!("Storing data for session {} type {:?}, identifier {:?}", session_id, storage_type, identifier);
  ```
- `client/tss/src/ecdsa/handler.rs:12`
  ```rust
  println!("TSS: handle_keygen_message from index {:?}", index.get_index());
  ```

These bypass `log::*` filtering — so even in `RUST_LOG=error` deployments they still spam stdout, and they reveal session indexing to any operator running `journalctl` or Docker log capture. Replace with `log::debug!` (or remove).

### L-N3 — `PeerMapper::add_peer` silently overwrites existing mappings (LOW, amplifies H-N2)

**File:** `client/tss/src/network/peer_mapper.rs:228–231`.
```rust
pub fn add_peer(&mut self, peer_id: PeerId, public_key_data: TSSPublic) {
    log::info!("Adding Peer {:?} with public key {:?}", peer_id, public_key_data);
    self.peers.insert(peer_id, public_key_data);
}
```

`HashMap::insert` returns the prior value, which is silently discarded. No log-warn if the same `peer_id` is re-bound to a different `public_key_data`. This is the mechanism that makes H-N2 stealthy.

**Fix.** Log a warning (or return an error) when overwriting:
```rust
if let Some(old_pk) = self.peers.get(&peer_id) {
    if old_pk != &public_key_data {
        log::warn!("[TSS][SEC] Attempt to rebind {} from pubkey {:?} to {:?}; rejecting",
            peer_id, old_pk, public_key_data);
        return;
    }
}
```

---

## 3. Audited & Clean Areas

### 3.1 FROST Ed25519 DKG (`dkground1.rs`, `dkground2.rs`, `dkg_session/`)

- `dkg_session/round1.rs::generate_round1_secret_package` correctly uses `rand::thread_rng()` (line 29) which wraps `OsRng`. Acceptable randomness for FROST `part1`.
- `dkg_session/round2.rs::round2_verify_round1_participants` delegates to `frost::keys::dkg::part2`, which per FROST Ed25519 2.1.0 internally verifies the proof-of-knowledge and commitment consistency of each `round1::Package`. If any is invalid, `part2` returns `Err(Error::*)`. The caller (`session/dkg_message_processor.rs:123`) correctly handles the error by setting `DKGSessionState::Failed` and reporting all round-1 participants to the on-chain offence module. This matches expected FROST behaviour.
- `dkg_session/session.rs::verify_and_complete` calls `dkg::part3` and on `Err` reports all round-2 participants (line 345–373) — again correct FROST handling. `dkg::part3` itself verifies the round2 encrypted shares and aborts on mismatch.
- The aggregate public key is stored locally but there is no explicit cross-participant consistency check; this is acceptable because FROST `part3`'s determinism guarantees all honest parties compute the same `PublicKeyPackage` for the same inputs (and divergent inputs would have caused `part3` to fail).

### 3.2 Multi-Party ECDSA (DMZ21 via `multi_party_ecdsa` 0.1.3 → `github.com/uomi-network/opentss`)

- `ecdsa/operations.rs::add_sign` calls `SignPhase::new(party_id, params, subset, keys)` once per session and stores the resulting phase inside an `Arc<Mutex<ECDSAManager>>` keyed by `SessionId`. Each signing session therefore has its own fresh `SignPhase` instance — **no nonce reuse** across parallel signings.
- Likewise `add_sign_online` is called once per signing session. The `SessionManager` guards re-initialization via `self.session_exists(&signing_id)` in `add_and_initialize_signing_session` (manager.rs:388–393).
- Recovery-ID path: `ecdsa/message_processor.rs::parse_signature_bytes` extracts `recid` from the JSON (line 754), defaults to 0 when absent, and the signature bytes are shipped to chain as `[r||s||recid]`. The `multi_party_ecdsa` crate's online sign phase produces the `recid` inside the final JSON (`recid` field). The on-chain C-4 fix handling `recid ∈ {0,1,2,3}` is exercised correctly.
- Reshare state transitions: each reshare session is keyed by a fresh `SessionId`; the old session's `EcdsaKeys` file is read but never mutated (session_creator.rs:216–222). Completion of reshare **does not** delete old keys automatically — this is acceptable as long as the pallet rotates the "active" key on chain; otherwise a compromised old share could still sign valid signatures against the old aggregate key. Out of scope for this re-audit, but worth a TODO to the team.
- Message validation: `session/message_processor.rs:571–685` processes ECDSA messages only after the outer `SignedTssMessage` signature was verified (line 47). The per-message `index` field is attacker-controlled, but all internal calls take that index as a `ECDSAIndexWrapper` and let `multi_party_ecdsa` verify protocol-level correctness. On error, `TssOffenceType::InvalidCryptographicData` is reported for the sender (ecdsa/message_processor.rs:25–42, 73–90). Acceptable.
- Paillier concerns do not apply — the DMZ21 variant used here relies on CL encryption (class groups), not Paillier. `SECURITY_BITS = 256` (`opentss/multi_party_ecdsa/src/utilities/mod.rs:18`).

### 3.3 Gossip replay-cache & announcement signing binding (gossip/router.rs)

The LRU cache is correctly implemented with a paired `VecDeque` + `HashSet` for O(1) duplicate detection and FIFO eviction. `MAX_CACHE = 512` is reasonable. Unit tests (`test_announce_replay_same_nonce_rejected`, `test_lru_eviction_allows_old_nonce_again`, `prop_unique_nonce_acceptance`) exercise the happy and unhappy paths. Verified. But note — this cache is inside `GossipHandler::announce_replay_cache` which, per H-N1, is **unused in production**.

### 3.4 Session cleanup (`session/cleanup.rs`)

Properly removes entries from all relevant shared maps under per-lock scopes (no lock poisoning risk), and reports DKG/Signing non-participation offences on timeout. Clean.

### 3.5 SigningService signing (`gossip/signing.rs`)

Payload is constructed deterministically as `message.encode() || validator_public_key || block_number.to_le_bytes()`. No length-confusion risks because the SCALE encoding is self-delimiting. Verified correct.

---

## 4. Open Questions (require upstream review)

1. **`multi_party_ecdsa` v0.1.3**: This is a fork (`github.com/uomi-network/opentss`). No public security advisories were reviewed in this audit for the upstream crate. Recommend a direct review of the Uomi fork's `dmz21/keygen.rs`, `dmz21/sign.rs`, `dmz21/reshare.rs`, especially around (a) whether `SignPhase::msg_handler` rate-limits malicious inputs per peer, and (b) whether CL encryption exchange messages are bound to the session id (a malicious party could otherwise cross-session-replay).
2. **FROST Ed25519 v2.1.0**: Crate is current as of 2025. No active RUSTSEC advisory. The `part2`/`part3` implementations are assumed correct; confirm by reading `frost_ed25519::keys::dkg::part3` to verify that a malicious participant cannot inject a round2 package that deserializes but decrypts to zero share.
3. **sc-network-gossip**: Uses Substrate workspace version. The node is tested against `frame-support`, `frame-system`, etc. from the workspace. The `NotificationService::in_peers = 5000, out_peers = 5000` (utils.rs:71–72) is very generous and potentially resource-heavy — confirm operational ulimit configuration is appropriate.
4. **Challenge generation entropy**: `rand::random()` is used to seed the `u32` challenge (session/message_processor.rs:79, 136). `rand::random::<u32>()` uses the default `thread_rng` (ChaCha20+OsRng reseed), so cryptographically adequate — but the challenge is only 32 bits wide, so an adversary with ~2^16 guesses can bruteforce a single challenge. Combined with the lack of comparison in H-N4, it makes no practical difference today, but for future hardening widen to `u64` or `u128`.

---

## 5. Suggested Priority of Remediation

1. **C-N1 (Announce-panic DoS)** — blocker; patch before next release.
2. **H-N1 + H-N4** — fix the production Announce verification and the challenge comparison simultaneously. The cleanest fix is to route production through `gossip/router.rs::process_announcement` rather than duplicating the logic in `session/message_processor.rs`.
3. **H-N2 + L-N3** — reject/log Announce bindings that don't match outer sender.
4. **H-N3** — re-enable the block-number check in `TssValidator::validate`.
5. **M-N1** — encrypt or keystore-protect long-term shares (can be phased; at minimum `0600` file perms immediately).
6. **M-N2, M-N3, M-N4** — low-risk cleanup, but `M-N3` panics are also DoS-adjacent and should be fixed with the rest.
7. **L-N1, L-N2** — hygiene.

---

*End of report.*
