# UOMI TSS — Security Audit Report

**Scope**: `pallets/tss` (~7.500 LOC on-chain) + `client/tss` (~10.000 LOC off-chain)
**Metodologia**: analisi line-by-line del codice sorgente; identificazione vulnerabilità concrete presenti nel codice (non teoriche).
**Convenzioni chiave osservate**: FROST Ed25519 per DKG (t-of-n), multi-party ECDSA secp256k1 (fork `uomi-network/opentss@0.1.3`) per signing, RLP EIP-155 / EIP-1559 preimage → offchain-worker submission.

> **Executive summary**: ho trovato **5 vulnerabilità CRITICAL** concrete sfruttabili, **5 HIGH**, **6 MEDIUM** e **4 LOW**. Il problema più grave è che l'intero schema di `validate_unsigned` + ogni extrinsic non firmato **non verifica la firma `_signature: T::Signature`**: qualsiasi utente con un client Substrate può impersonare qualsiasi validator e, fra le altre cose, **forgiare la chiave DKG aggregata** (reindirizzando fondi degli agent-wallet a un proprio indirizzo) e **far slashare validator onesti** senza costi. In questo stato il TSS **non è sicuro per la produzione**.

---

## CRITICAL

### C-1. Nessuna verifica della firma negli extrinsic unsigned → total authentication bypass
**File**: `pallets/tss/src/lib.rs:1397-1516` (`validate_unsigned`), più tutti i dispatch:
- `submit_dkg_result` (L796-883), `submit_signature_result` (L885-938),
- `report_participant` (L1055-1097), `report_tss_offence` (L1100-1126),
- `create_signing_session_unsigned` (L756-782), `update_validators` (L643-665),
- `update_last_opoc_request_id_unsigned` (L784-794),
- `create_reshare_dkg_session_unsigned` (L1028-1041),
- `submit_fsa_transaction_unsigned` (L1270-1286), `timeout_pending_transaction_unsigned` (L1288-1304),
- `fail_multi_chain_transaction_unsigned` (L1306-1324), `create_gap_filler_signing_session_unsigned` (L1328-1373),
- `complete_reshare_session_unsigned` (L1043-1053).

**Codice**:
```rust
// validate_unsigned — accetta TUTTO senza guardare il campo `signature`:
Call::submit_dkg_result { .. } => {
    return ValidTransaction::with_tag_prefix("TssPallet")
        .priority(TransactionPriority::MAX)
        .and_provides(call.encode())
        .longevity(64).propagate(true).build();
}

// dispatch — il parametro firma è letteralmente scartato (_signature):
pub fn submit_dkg_result(
    origin: OriginFor<T>,
    payload: SubmitDKGResultPayload<T>,
    _signature: T::Signature,      // mai letto
) -> DispatchResult {
    ensure_none(origin)?;
    let who = payload.public().into_account();   // trust sul campo `public` scelto dall'attaccante
    ...
    ensure!(session.participants.contains(&who), Error::<T>::UnauthorizedParticipation);
```

Lo stesso pattern `ensure_none(origin)?; let who = payload.public().into_account();` è replicato in tutti i dispatch non firmati: nessuna chiamata a `SignedPayload::<T>::verify(...)`, nessun controllo `AppCrypto`. `ensure_none` verifica solo che l'origine sia `RawOrigin::None`, non firma qualcosa.

**Perché è un problema**: senza verifica della firma, chiunque può costruire un `SubmitDKGResultPayload { session_id, public_key: ATTACKER_BYTES, public: <pubkey del validator onesto> }`, inviarla via RPC, e superare `session.participants.contains(&who)`.

**Attack proof (PoC di alto livello)**:
1. Osserva `DKGSessionCreated(sid)` on-chain; leggi `DkgSessions::<T>::get(sid).participants` → lista di AccountId dei validator.
2. Per ogni validator onesto `V`, costruisci un `Call::submit_dkg_result { payload: SubmitDKGResultPayload { session_id: sid, public_key: attacker_pub, public: V.public() }, _signature: [0u8; 64] }` e inviala come unsigned transaction.
3. Dopo ~`ceil(n * 67/100)` submit (es. 6/9), la soglia viene raggiunta, la sessione passa a `DKGComplete` (L852-881) e `AggregatedPublicKeys::<T>::insert(sid, attacker_pub)`.
4. `derive_from_address::<T>(nft_id)` (`fsa.rs:178-196`) calcola `keccak256(attacker_pub)[12..]` → indirizzo Ethereum dell'attaccante.
5. Qualunque trasferimento verso quell'agent wallet finisce sull'attaccante. Essendo lui a conoscere la private key, **prende i fondi**.

Una variante meno invasiva usa `Call::report_tss_offence { payload: ReportTssOffencePayload { offence_type: InvalidCryptographicData, session_id: sid, offenders: honest_validators, public: V.public() }, _signature: _ }`: lo slashing viene registrato in `PendingTssOffences` e consumato in `process_pending_tss_offences` (`lib.rs:2075-2128`) senza ulteriore verifica.

**Fix**:
```rust
fn validate_unsigned(_src: TransactionSource, call: &Self::Call) -> TransactionValidity {
    let verify = |payload: &impl SignedPayload<T>, signature: &T::Signature| -> bool {
        SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone())
    };
    match call {
        Call::submit_dkg_result { payload, signature } => {
            if !verify(payload, signature) { return InvalidTransaction::BadProof.into(); }
            // (verifica che payload.public corrisponda a un ActiveValidator)
            let who = payload.public().clone().into_account();
            if !ActiveValidators::<T>::get().contains(&who) { return InvalidTransaction::BadSigner.into(); }
            ValidTransaction::with_tag_prefix("TssPallet")
                .priority(TransactionPriority::MAX)
                .and_provides((call.encode(), who))
                .longevity(64).propagate(true).build()
        }
        // ...stesso trattamento per ogni altro unsigned...
    }
}
```
Aggiungi inoltre `and_provides((session_id, who))` per evitare doppio conteggio dello stesso voto tramite replay, e dentro i dispatch ri-verifica in modo difensivo: `ensure!(SignedPayload::verify::<T::AuthorityId>(&payload, signature), Error::<T>::InvalidSignature);`.

---

### C-2. Forgery della chiave DKG aggregata tramite voto impersonato
**File**: `pallets/tss/src/lib.rs:796-883` (`submit_dkg_result`)

```rust
ProposedPublicKeys::<T>::insert(nft_id.clone(), validator_id, aggregated_key.clone());
// ...
let threshold = T::MinimumValidatorThreshold::get();   // 67
let mut votes = 0;
for (_validator_id, key) in ProposedPublicKeys::<T>::iter_prefix(nft_id.clone()) {
    if key == aggregated_key { votes += 1; }
}
let total_validators = session.participants.len() as u32;
let required_votes = (total_validators * threshold) / 100;   // integer div → arrotondamento PER DIFETTO
if votes >= required_votes {
    session.state = SessionState::DKGComplete;
    AggregatedPublicKeys::<T>::insert(session_id, aggregated_key.clone());
    ...
}
```

**Perché è un problema**: combinato con **C-1**, l'attaccante controlla tutti i voti. Anche senza C-1, l'arrotondamento per difetto rende la soglia rilassata: 9 validator × 67 / 100 = `6` (cioè 66.7%, non 67%).
Inoltre il dispatch **non verifica** che `aggregated_key` derivi effettivamente da DKG — nessun challenge, nessuna proof-of-knowledge del discrete log, nessun commitment-verification on-chain.

**Attack proof**: vedi PoC di C-1. Impatto: ridirezionamento totale dei fondi agent-wallet.

**Fix**: oltre a C-1, usa `ceil` anziché `floor`: `required_votes = (total_validators * threshold + 99) / 100;`. Considerare di richiedere unanimità (`required_votes = participants`) per il finalize DKG dato che in un DKG corretto TUTTI i partecipanti sani ricavano la stessa chiave aggregata dai commitment. Accettare una minoranza ≥67 apre la porta a divergenza.

---

### C-3. OPOC processor si blocca su request_id mancante (stallo permanente)
**File**: `pallets/tss/src/fsa.rs:78-109`

```rust
let mut current = last_opoc_request_id.saturating_add(U256::one());
for _ in 0..10u8 {
    if !pallet_uomi_engine::Outputs::<T>::contains_key(&current) {
        continue;                     // ⬅ NON incrementa `current`
    }
    match Self::process_single_request(current) { ... }
    current = current.saturating_add(U256::one());
}
```

**Perché è un problema**: Il commento dice *"If we find a missing key we can safely skip it"* ma `continue` rientra nel loop **con lo stesso `current`**. Le 10 iterazioni si consumano tutte sullo stesso ID. Al blocco successivo idem. Risultato: una singola request_id saltata (es. `pallet_uomi_engine` non ha generato output per un request per qualsiasi motivo) **blocca indefinitamente** tutte le signing session successive.

**Attack proof**: se `uomi_engine::Outputs` non inserisce la chiave 5 (crash del runtime agent, output skippato per validazione fallita, ecc.), `LastOpocRequestId` resta fisso a 4 per sempre; nessuna transazione multi-chain viene firmata da quel momento in poi → **denial of service permanente del TSS multi-chain**. Un attaccante che controlla anche parzialmente la logica OPOC in `uomi_engine` può forzare questo stato.

**Fix**:
```rust
for _ in 0..10u8 {
    if !pallet_uomi_engine::Outputs::<T>::contains_key(&current) {
        // salta davvero: avanza
        current = current.saturating_add(U256::one());
        continue;
    }
    match Self::process_single_request(current) {
        Ok(Some((nft_id, data))) => { requests_to_sign.insert(current, (nft_id, data.0, data.1)); last_processed = current; }
        Ok(None) | Err(ProcessingError::NoOutputFound) => { last_processed = current; }
        Err(e) => { log::warn!("stop on hard error {:?}", e); break; }
    }
    current = current.saturating_add(U256::one());
}
```

---

### C-4. `panic!("invalid recid")` nel finalize delle transazioni firmate
**File**: `pallets/tss/src/multichain.rs:651` (legacy) e `:709` (EIP-1559)

```rust
let y_parity = match recid {
    27 | 28 => recid - 27,
    0 | 1 => recid,
    _ => panic!("invalid recid"),       // ← panic in hot path
} as u64;
```

**Perché è un problema**: `recid` è il 65° byte della firma aggregata (`submit_signed_transaction` → `sig_bytes[64]`, `lib.rs:2365`) prodotta dal gossip tra partecipanti ECDSA. secp256k1 ammette `recid ∈ {0,1,2,3}` (2/3 per r con X overflow, raro ma possibile). I partecipanti ECDSA possono **deliberatamente** produrre `recid = 2` o `3`, o semplicemente riportare un byte arbitrario tramite gossip malevolo: il panic viene scatenato in `process_completed_signatures` (`lib.rs:2138-2190`) che è chiamato anche in path on-chain tramite `Pallet::<T>::process_completed_signatures` (pubblico), e in offchain-worker in `lib.rs:1531-1569`. **Panic nell'offchain worker blocca ulteriori iterazioni FSA**; se mai raggiunto on-chain il blocco fallisce.

**Attack proof**: un validator malevolo firma con `recid = 2`, il blob finisce in `Signature` BoundedVec e al successivo `submit_signed_transaction`:
```
legacy_finalize_raw(... recid=2)
  └─ panic!("invalid recid")
```

**Fix**: gestire `recid ∈ {0,1,2,3}`:
```rust
let y_parity = match recid {
    0 | 1 | 2 | 3 => recid as u64 & 1,     // use low bit for parity
    27 | 28 => (recid - 27) as u64,
    _ => return Err(TxBuildError::InvalidRecid(recid)),
};
```
Oltre a ciò, spingere il check a monte (quando la firma viene ricevuta dal client TSS) e rifiutare `recid >= 4` in `submit_signed_transaction` restituendo `None` con log.

---

### C-5. Extrinsic senza controllo di autorizzazione
**File**: `pallets/tss/src/lib.rs`
- `create_dkg_session` (L577-641): `_origin: OriginFor<T>`, **zero** `ensure_*`.
- `create_signing_session` (L669-754): `_origin: OriginFor<T>`, **zero** `ensure_*`.

**Perché è un problema**: qualunque account firmato (paying fees) può creare DKG session arbitrarie per qualunque `nft_id`, oppure aprire signing session fittizie. Combinato con C-1, anche un account senza saldo può usarle tramite path unsigned (es. `create_signing_session_unsigned`).

**Impatto concreto**:
- DoS: flood di `create_dkg_session(nft_id_random, 80)` riempie `DkgSessions`, crea N × `internal_create_reshare_dkg_session` all'era successiva (`validators.rs:156-191`), crea N sessioni per NFT inesistenti.
- Degradazione reshare: `handle_era_transition` → `create_reshare_session_for_validator_change` itera su `DkgSessions::iter()` `==DKGComplete` e per ogni session crea **un nuovo reshare**; l'attaccante può gonfiare a ~∞.

**Fix**:
```rust
pub fn create_dkg_session(origin: OriginFor<T>, nft_id: NftId, threshold: u32) -> DispatchResult {
    // Solo callable da pallet_uomi_engine via TssInterface (origine None con guardia)
    ensure_root(origin).or_else(|_| { ensure_none(origin.clone()).map_err(|_| DispatchError::BadOrigin) })?;
    // ...
}
```
O meglio ancora: marcare `create_dkg_session` come `pub(crate)` e invocabile solo tramite `TssInterface::create_agent_wallet` (che è già usato da `pallet_uomi_engine`), togliendolo completamente da `#[pallet::call]`.

---

## HIGH

### H-1. Private keys loggate via `log::debug!` in successo keygen/reshare
**File**: `client/tss/src/ecdsa/message_processor.rs:492, 554`
```rust
log::debug!("[TSS] ECDSA Keygen successful, storing keys {:?}", msg);
log::debug!("[TSS] ECDSA Reshare successful, storing keys {:?}", msg);
```
Il JSON `msg` contiene `{"privkey":{"cl_sk":"...","ec_sk":"<32byte hex>","share_sk":"<32byte hex>"}, "pubkey":{...}}` — visibile nel test vector a L778: l'intera share secret dell'ECDSA multi-party è in chiaro.

**Perché è un problema**: con `RUST_LOG=debug` (abilitato frequentemente in staging/troubleshooting o se l'attaccante ottiene uno shell temporaneo in /var/log), la chiave share viene esfiltrata. Con `t+1` share un attaccante può firmare qualsiasi transazione a nome del wallet.

**Fix**: non stampare mai il blob. Usare un redacted log:
```rust
let bytes_len = msg.len();
log::debug!("[TSS] ECDSA Keygen successful (payload {} bytes, keys redacted)", bytes_len);
// se necessario per debug, loggare solo pubkey dopo extract_agg_key
if let Ok(agg) = extract_agg_key(&msg) {
    log::debug!("[TSS] Aggregated pubkey = {}", hex::encode(agg));
}
```
Ispezionare tutta la codebase per altri log con `msg`/`share` nei moduli `dkghelpers`, `dkground*`, `ecdsa/*`, `session/*`.

### H-2. `submit_aggregated_signature` verifica contro una chiave globale mai settata
**File**: `pallets/tss/src/lib.rs:976-1012`, L992
```rust
let public_key = TSSKey::<T>::get();   // StorageValue<_, PublicKey, ValueQuery>, mai scritto
ensure!(verify_signature::<T>(&public_key, &session.message, &signature), Error::<T>::InvalidSignature);
```
`TSSKey` è dichiarato in L339 e **non è mai scritto** in nessun punto del pallet (`grep "TSSKey::<T>::put\|TSSKey::<T>::mutate\|TSSKey::<T>::insert"` restituisce 0 match). Default = `PublicKey::default()` = vettore vuoto → `Verifier::verify` ritorna `false` sempre (`try_into()` fallisce a 33 byte).

**Perché è un problema**: (a) l'extrinsic è inutilizzabile (sempre `InvalidSignature`), il che suggerisce che il codice non è mai stato veramente esercitato; (b) se in futuro qualcuno scrive `TSSKey`, il verify userebbe UNA chiave globale mentre il sistema ne ha **una per NFT/session** → verification sbagliata. Il giusto riferimento è `AggregatedPublicKeys::<T>::get(session.dkg_session_id)`.

**Fix**:
```rust
let agg = AggregatedPublicKeys::<T>::get(session.dkg_session_id)
    .ok_or(Error::<T>::DkgSessionNotReady)?;
ensure!(verify_signature::<T>(&agg, &session.message, &signature), Error::<T>::InvalidSignature);
```
Rimuovere `TSSKey` dalla storage o documentarne lo scope.

### H-3. `get_agent_wallet_address` ritorna la chiave più LUNGA, non quella più VOTATA
**File**: `pallets/tss/src/lib.rs:2581-2608`
```rust
let mut proposed_keys = ProposedPublicKeys::<T>::iter_prefix(nft_id)
    .map(|(_validator_id, key)| key)
    .collect::<Vec<crate::types::PublicKey>>();
proposed_keys.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
if let Some(key) = proposed_keys.last() {       // ← prende la più lunga
    if let Ok(address) = sp_core::H160::decode(&mut &key[..]) { return Some(address); }
}
```
Il commento dichiara *"take the value that has most votes"* ma l'implementazione non fa counting: prende la più lunga (o lessicograficamente maggiore a parità di lunghezza).

**Perché è un problema**: un attaccante (via C-1) inietta una chiave di 65 byte (formato uncompressed con prefix 0x04) mentre i validator onesti votano 33 byte compressed → l'attaccante vince automaticamente. E in condizioni benigne, un validator onesto che vota in formato diverso può sovrascrivere la scelta.

**Fix**:
```rust
let mut counts: sp_std::collections::btree_map::BTreeMap<PublicKey, u32> = BTreeMap::new();
for (_vid, key) in ProposedPublicKeys::<T>::iter_prefix(nft_id) {
    *counts.entry(key).or_insert(0) += 1;
}
let winner = counts.into_iter().max_by_key(|(_, c)| *c).map(|(k, _)| k)?;
// oppure, preferibilmente, usare AggregatedPublicKeys::<T>::get(session_id_piu_recente) e smettere di basarsi su ProposedPublicKeys una volta finalizzato.
```

### H-4. Validator slashing via `report_tss_offence` impersonato
**File**: `pallets/tss/src/lib.rs:1100-1126` + `2075-2128` (process)
```rust
pub fn report_tss_offence(origin: OriginFor<T>, payload: ReportTssOffencePayload<T>, _signature: T::Signature) -> DispatchResult {
    ensure_none(origin)?;
    let who = payload.public().into_account();
    let session = DkgSessions::<T>::get(payload.session_id).ok_or(Error::<T>::DkgSessionNotFound)?;
    ensure!(session.participants.contains(&who), Error::<T>::UnauthorizedParticipation);
    PendingTssOffences::<T>::insert(payload.session_id, (payload.offence_type.clone(), who, payload.offenders.clone()));
```
Combinato con C-1 (no signature verify), l'attaccante imposta `payload.public = V_onesto` e `offenders = [altri_onesti]` → slashing al prossimo `on_initialize`.

**Perché è un problema**: l'integrità del validator set può essere compromessa senza costi dall'attaccante (no stake required). `Perbill::from_percent(2)` per `InvalidCryptographicData` → slash ripetibile in loop.

**Fix**: risolve automaticamente con C-1. Inoltre:
- Unire la verifica: un `offence_type` è valido solo se esiste evidenza (es. una firma non valida memorizzata in storage) → richiedere al reporter di fornire la `TssMessage` offending + firma originale del presunto offender, e verificarla on-chain;
- Limitare a un offence-type per (session, reporter): `ReportedOffenceByReporter<SessionId, Reporter, OffenceType>` come `Option<()>`.

### H-5. `update_last_opoc_request_id_unsigned` permette a chiunque di saltare request-id
**File**: `pallets/tss/src/lib.rs:784-794`
```rust
pub fn update_last_opoc_request_id_unsigned(origin: OriginFor<T>, payload: UpdateLastOpocRequestIdPayload<T>, _signature: T::Signature) -> DispatchResult {
    ensure_none(origin)?;
    LastOpocRequestId::<T>::put(payload.last_request_id);
    Ok(())
}
```
Nessuna verifica della firma, nessuna verifica che `payload.public` sia un validator, nessuna monotonicità.

**Perché è un problema**:
- Settando `last_request_id = U256::MAX` un attaccante **skippa tutte le request OPOC** future (l'OPOC loop parte da `last+1` che satura a MAX).
- Settando `last_request_id = 0` causa **rielaborazione infinita** delle request già processate → signing duplicati, possibili double-spend se i nonce collidono.

**Fix**:
```rust
ensure!(SignedPayload::<T>::verify::<T::AuthorityId>(&payload, signature.clone()), Error::<T>::InvalidSignature);
ensure!(ActiveValidators::<T>::get().contains(&payload.public().into_account()), Error::<T>::Unauthorized);
let current = LastOpocRequestId::<T>::get();
ensure!(payload.last_request_id > current, Error::<T>::StaleUpdate);
// Quorum: richiedere aggregazione di >67% dei validator prima di applicare.
```

---

## MEDIUM

### M-1. Buffer messaggi gossip cresce unbounded per session ignote
**File**: `client/tss/src/session/message_processor.rs:162-210, 240-256` e `manager.rs:56` (`HashMap<SessionId, Vec<(TSSPeerId, TssMessage)>>`)
```rust
session_manager.buffer.lock().unwrap()
    .entry(*session_id).or_insert(Vec::new())
    .push((sender_peer_id.to_bytes(), TssMessage::DKGRound1(*session_id, bytes.clone())));
```
Nessun cap per-session, nessun TTL, nessun LRU. Un attaccante spamma `DKGRound1(sid_random, 1MB_bytes)`: il nodo bufferizza all'infinito → OOM.

**Fix**: `const MAX_BUFFERED_PER_SESSION: usize = 128;` + cap globale sul numero di session bufferizzate + scadenza (evict session buffer dopo 5 minuti senza match).

### M-2. Finestra nonce (64) troppo piccola; `FailedTemp` stuck
**File**: `pallets/tss/src/types.rs:21` + `lib.rs:1819-1841` (`allocate_next_nonce_internal`)
- Con 12 blocchi di conferma tipici Ethereum a 3s Uomi-block → 36s, con un agent che firma 2 tx/s si superano 64 pending in 32s.
- `PendingStatus::FailedTemp(retry_count)` è definito ma **nessun codice** lo transisce mai a `Allocated` per retry (`grep FailedTemp` → solo la definizione). Una tx fallita temporaneamente resta per sempre in `pending`, consumando uno slot della finestra → DoS allocazione dopo 64 fallimenti.

**Fix**: (a) aumentare `MaxPendingNonces` a ≥256 e/o (b) implementare retry con decay in `on_initialize` (un count scende sotto threshold → `Allocated`) e (c) scadenza definitiva `FailedPermanent` dopo N retry con evento.

### M-3. `TssOffenceType::UnresponsiveBehavior` come fallback per valori ignoti
**File**: `pallets/tss/src/lib.rs:143-156`
```rust
impl From<u8> for TssOffenceType {
    fn from(value: u8) -> Self { match value {
        0 => DkgNonParticipation, 1 => SigningNonParticipation,
        2 => InvalidCryptographicData, 3 => UnresponsiveBehavior,
        _ => { log::warn!(...); TssOffenceType::UnresponsiveBehavior }
    }}
}
```
Combinato con C-1: attaccante manda offence_type=99 → mappato a `UnresponsiveBehavior` e slash 1%.

**Fix**: ritornare `Result<Self, DispatchError>` e reject in dispatch.

### M-4. `report_participants` `unwrap()` su decode
**File**: `pallets/tss/src/sessions.rs:112-116`
```rust
let reported_participants_bounded = BoundedVec::try_from(
    reported_participants.iter().map(|x| T::AccountId::decode(&mut &x[..]).unwrap()).collect::<Vec<T::AccountId>>(),
).unwrap();
```
Due `.unwrap()` in hot path offchain: `AccountId::decode` può fallire (input corrotto) → panic dell'offchain worker.

**Fix**: `.map_err(|_| ...)?` con log e skip del participant invalido.

### M-5. Non-determinism rischio latente: pattern `DkgSessions::<T>::iter()` con filter+max
**File**: `pallets/tss/src/lib.rs:704-709, 863-873, 1353-1356, 1783-1787, 1798-1805` e `validators.rs:166-184, 214-219`
Il codice è già stato patchato (commenti "IMPORTANT: Collect into BTreeMap for deterministic iteration order") indicando consapevolezza di un precedente fork. Tuttavia alcune iter() rimangono in hot path senza BTreeMap wrapping:
- `lib.rs:1534` `for (session_id, session) in SigningSessions::<T>::iter()` in offchain_worker (offchain, OK)
- `lib.rs:1620-1622` `for (_sid, existing) in SigningSessions::<T>::iter()` (offchain, OK)
- `lib.rs:1893` `for (_sid, sess) in SigningSessions::<T>::iter() { if sess.request_id == req_id { exists = true; break; } }` — offchain, solo early-exit, OK
- `lib.rs:841` `for (_validator_id, key) in ProposedPublicKeys::<T>::iter_prefix(nft_id.clone())` dentro `submit_dkg_result` ON-CHAIN → conta voti, l'ordine non influisce sul conteggio (solo `+= 1`), ma il count stesso dipende dall'ordinamento di iter SE ProposedPublicKeys è stato scritto in un ordine che diverge tra native/WASM. Qui il count è `if key == aggregated_key { votes += 1 }` indipendente dall'ordine → OK, ma pattern fragile.

**Fix**: raccogliere sempre in `BTreeMap` per gli iter on-chain, anche quando sembra benigno, come pattern difensivo. Aggiungere un lint/CI check: `grep "::iter()" pallets/tss/src/ | grep -v BTreeMap` dovrebbe essere vuoto nei dispatch.

### M-6. Announcement replay — challenge_answer=0 bypass
**File**: `client/tss/src/gossip/router.rs:148-182`, L153-154
```rust
payload.extend_from_slice(&nonce.to_le_bytes());
if challenge_answer != 0 { payload.extend_from_slice(&challenge_answer.to_le_bytes()); }
```
Il challenge è optional nel payload firmato. Un'Announce spontaneo (senza challenge) viene firmato senza bind → un attaccante intercetta il primo Announce di un peer onesto e può riutilizzarlo ad infinitum (fino ad eviction dalla LRU 512). La verifica `challenge_answer != 0` dovrebbe essere obbligatoria in risposta a `GetInfo`.

**Fix**: sempre `payload.extend_from_slice(&challenge_answer.to_le_bytes());` (anche se 0) e obbligare challenge non-zero nei contesti di risposta a GetInfo. Lato verifier: rifiutare Announce senza `challenge_answer` se era stato inviato un GetInfo.

---

## LOW

### L-1. `unsafe { core::str::from_utf8_unchecked(...) }` in `check_pending_transactions`
**File**: `pallets/tss/src/lib.rs:2303`
```rust
sp_std::borrow::Cow::Owned(unsafe { core::str::from_utf8_unchecked(&out) }.into())
```
I bytes sono generati internamente (solo hex a-f, 0-9) quindi è UTF-8 valido, ma un `unsafe` evitabile è code smell. Sostituire con `String::from_utf8(out).expect("ascii hex")` o pre-validazione.

### L-2. `panic!("bad hex")` in `derive_from_address_basic` test helper, ma accessibile fuori test
**File**: `pallets/tss/src/fsa.rs:214`
```rust
let h = |c: u8| -> u8 { match c { ... _ => panic!("bad hex") } };
```
Anche se `#[cfg(test)]`, la funzione `hex_to_bytes` è definita dentro `mod tests` e non leak. OK in ambito test, ma la logica duplicata con `decode_hex` (L294-311) fuori test è più robusta. Consolidare.

### L-3. RPC URLs pubblici hardcoded / `localhost:9944` per chain 4386 (Uomi)
**File**: `pallets/tss/src/multichain.rs:49-59`
- Ogni nodo userà `https://eth.llamarpc.com`, `https://polygon-rpc.com/`, ecc. → punti di fallimento/controllo esterno per un sistema di firma multi-party (RPC poisoning potrebbe far firmare tx relative a stato inconsistente).
- `Uomi => "http://localhost:9944"` assume che ogni validator esponga il proprio RPC localmente.

**Fix**: chain configs devono arrivare da on-chain storage (`ChainConfigs::<T>`) e non fallback a hardcoded. Inoltre implementare response cross-check (majority rule) tra più endpoint prima di usare gas_price/nonce dall'RPC.

### L-4. `miniserde::json::from_str` in parsing Action senza validazione stringhe esadecimali
**File**: `pallets/tss/src/fsa.rs:131`, `fsa.rs:293-312`
`decode_hex` tollera `len % 2 != 0` restituendo `Err(())` ma il chiamante poi usa `Vec::new()`:
```rust
let data_bytes = match decode_hex(&action.data) { Ok(v)=>v, Err(_)=>{log::warn!(...); Vec::new()} };
```
Una `action.data` corrotta porta a firmare una tx con data vuoto invece di rigettare l'azione → transazione funzionalmente diversa dall'intenzione del payload OPOC, ma comunque firmata dal TSS.

**Fix**: in caso di hex invalido restituire `Err` (e quindi `Err(ProcessingError::ParseError)` → il `break` nel loop non è desiderato nemmeno qui — restituire `Ok(None)` skippando l'azione specifica).

---

## Test coverage osservato

- `pallets/tss/src/tests.rs` (2886 righe) esercita principalmente path happy; non vedo test che chiami `validate_unsigned` con firme errate per verificare rifiuto. **Gap**: aggiungere test negativi per ogni call unsigned con firma invalida/public mismatch/dup.
- `client/tss/src/test_framework*.rs` usa dummy `[0u8; 64]` signature che in `security/verification.rs:14-18` viene auto-accettata. Il behaviour `#[cfg(test)]` è corretto ma mascherina eventuali bug nel path di firma.
- Non vedo round-trip test che confronti l'RLP legacy/EIP-1559 generato con output ethers.js/web3: i test verificano solo lunghezza/prefisso e non byte exact per vectors standard. **Gap**: aggiungere test vectors noti (es. EIP-155 example transactions).
- `prop_tests.rs` (232 righe) e router prop test su announce replay: buoni ma circoscritti. Manca property test Byzantine: "k-1 partecipanti malevoli non possono finalizzare una chiave arbitraria".

## Librerie / supply chain

- `frost-ed25519 = "2.1.0"` — Zcash Foundation, libreria ufficiale, review pubblica. Uso corretto di `part1/part2/part3`. Nessun red flag sull'uso.
- `multi-party-ecdsa = { git = "https://github.com/uomi-network/opentss", version = "0.1.3" }` — **fork non auditato** di OpenTSS. Non ho visibilità sulle modifiche rispetto all'upstream; la depend via git non pinna un commit hash (potrebbe muoversi). **Raccomandazione**: pinnare con `rev = "<full commit>"` e allegare delta-review del fork; confrontare con upstream per backport di fix su nonce biasing.
- `rlp = "0.6"` — `parity-common` crate, ok.
- `miniserde = "0.1.42"` — nessun handler per caratteri UTF non standard; va bene per JSON strettamente ASCII come Action, ma `log::debug!("...{:?}", msg)` stampa il debug repr che sì leakerebbe keys (vedi H-1).

---

## Ordine consigliato per il remediation

1. **C-1** (signature verify in `validate_unsigned` + dispatch) → senza questo nulla è difendibile.
2. **C-5** (restringere origine di `create_dkg_session` / `create_signing_session`) → insieme a (1) chiude la superficie controllo-chiamate.
3. **C-3** (OPOC advance on missing key) → una PR da 3 righe, fix immediato.
4. **C-4** (recid handling) → PR piccola, elimina panic.
5. **C-2** (soglia DKG + opzionale: unanimità) → medio impatto, ma serve definire policy.
6. **H-1** (redact log) → trivial, importante per op-sec.
7. **H-3** (wallet address = most voted o AggregatedPublicKeys diretto).
8. **H-5** (validate_unsigned + monotonicity last_opoc_request_id).
9. **H-2** (usare `AggregatedPublicKeys` in `submit_aggregated_signature`).
10. **H-4** (risolto da C-1, ma aggiungere evidenza obbligatoria per `report_tss_offence`).
11. Medium/Low in sprint successivo.

Appena applicato (1)+(2)+(3)+(4)+(5) raccomando un **re-audit mirato** sul solo path `#[pallet::call]` + `#[pallet::validate_unsigned]` perché sono la zona di rischio più alta; il resto (DKG FROST in `dkg_session/session.rs` e le chiamate a `frost::keys::dkg::part{1,2,3}`) l'ho trovato corretto dal punto di vista crittografico (uso conforme dell'API `frost_ed25519`, commitment verification effettuata dentro `part2`, key derivation deterministica in `part3`, zero share reconstruction in plaintext nel codice).
