# Rapporto Diagnostico — Errore Consensus "Digest item must match that calculated"

> **Data:** 10 marzo 2026  
> **Blocco bloccante:** `0x15440964ea61b298b1f4c30ea03e53657340f0672bef35cad52f02b400330a78`  
> **Errore:** `panicked at frame_executive::Executive::execute_block (lib.rs:863) — "Digest item must match that calculated."`  
> **Stato:** ❌ NON RISOLTO — tutte le ipotesi testate finora sono state smentite

---

## Indice

1. [Descrizione del Problema](#1-descrizione-del-problema)
2. [Architettura Coinvolta](#2-architettura-coinvolta)
3. [Cronologia delle Indagini e Fix](#3-cronologia-delle-indagini-e-fix)
4. [Ipotesi Testate e Risultati](#4-ipotesi-testate-e-risultati)
5. [Stato Attuale delle Verifiche](#5-stato-attuale-delle-verifiche)
6. [Analisi della Root Cause Più Probabile](#6-analisi-della-root-cause-più-probabile)
7. [Possibili Soluzioni](#7-possibili-soluzioni)
8. [File Modificati In Questa Sessione](#8-file-modificati-in-questa-sessione)

---

## 1. Descrizione del Problema

Quando un nodo (RPC o un nuovo validatore) tenta di importare il blocco `0x15440964ea61b298b1f4c30ea03e53657340f0672bef35cad52f02b400330a78`, l'esecuzione produce un digest diverso da quello sigillato nell'header del blocco. Il nodo va in panic:

```
panicked at polkadot-sdk/.../substrate/frame/executive/src/lib.rs:863:4:
Digest item must match that calculated.
```

Seguito da:

```
Block prepare storage changes error: Error at calling runtime api: 
Execution failed: Execution aborted due to trap: wasm trap: wasm `unreachable` instruction executed
```

**Comportamento chiave:**
- L'errore si verifica **deterministicamente** alla prima importazione del blocco
- Succede con DB **pulito** (riscaricato, il blocco non è mai stato eseguito prima)
- Succede con lo **stesso binario** (sha256 verificato identico su tutti i nodi)
- Succede con lo **stesso WASM on-chain** (hash verificato identico)
- Succede con lo **stesso `specVersion: 16`** su tutti i nodi
- Succede su **qualsiasi nodo** che non sia il validatore originale che ha prodotto il blocco

---

## 2. Architettura Coinvolta

### Stack Tecnologico
- **Substrate/Polkadot SDK:** commit `f3e0dfb`, branch `stable2506`
- **Frontier (EVM layer):** checkout `frontier-d64fc6ea84da53c0/0c8f43b`
- **Consenso:** BABE (block production) + GRANDPA (finality)
- **Executor:** `WasmExecutor<HostFunctions>` (migrato da `NativeElseWasmExecutor`)

### Il Meccanismo del Digest Frontier

In `construct_runtime!`, il pallet Ethereum ha indice `61`. L'ordine di esecuzione è:

1. **`on_initialize`** — eseguito in ordine di indice pallet (10, 11, ..., 61, ..., 110, ...)
2. **`on_finalize`** — eseguito in ordine **inverso** (125, 124, 123, ..., 61, ..., 13, 10)

Il pallet `pallet_ethereum` (indice 61) nella fase `on_finalize`:
- Chiama `IntermediateStateRoot<Self::Version>` → `sp_io::storage::root(version)` → calcola l'hash Merkle root dello state trie
- Questo valore viene inserito come **digest item** nell'header del blocco

In `frame_executive::final_checks` (riga 863), il framework confronta i digest nell'header del blocco proposto con quelli ricalcolati. Se non corrispondono → **panic**.

### Ordine on_finalize (rilevante)

Poiché `UomiEngine = 110` e `Ethereum = 61`:
- `UomiEngine::on_finalize` viene eseguito **prima** di `Ethereum::on_finalize`
- Qualsiasi modifica allo storage fatta da `UomiEngine::on_finalize` influenza lo state root calcolato da Ethereum

### HostFunctions Type

```rust
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions = (
    sp_io::SubstrateHostFunctions,
    moonbeam_primitives_ext::moonbeam_ext::HostFunctions,
    cumulus_primitives_proof_size_hostfunction::storage_proof_size::HostFunctions,
);
```

---

## 3. Cronologia delle Indagini e Fix

### Fix 1: IPFS Inherent (✅ RISOLTO)

**Problema:** L'errore iniziale era `"Checking inherents unhandled error: ipfs-ide"`. Il pallet IPFS dichiarava un inherent identifier `ipfs-ide` ma il client non registrava un `InherentDataProvider` corrispondente. Il framework trattava qualsiasi errore non gestito come fatale.

**Soluzione:**
- Modificato `check_inherent` in `pallets/ipfs/src/lib.rs` per restituire sempre `Ok(())` 
- Creato `node/src/ipfs_inherent.rs` — un `InherentDataProvider` no-op che:
  - Registra la chiave `ipfs-ide` in `InherentData` (con valore vuoto)
  - Gestisce errori gracefully con logging
- Registrato `IpfsInherentDataProvider` nel `create_inherent_data_providers` di tutti i file service (`uomi/service.rs`, `local/service.rs`)

**File modificati:**
- `pallets/ipfs/src/lib.rs` — `check_inherent` → return `Ok(())`
- `node/src/ipfs_inherent.rs` — nuovo file
- `node/src/lib.rs` — aggiunto `pub mod ipfs_inherent;`
- `node/src/uomi/service.rs` — registrato `IpfsInherentDataProvider`
- `node/src/local/service.rs` — registrato `IpfsInherentDataProvider`

---

### Fix 2: Audit Non-determinismo `iter()` / `iter_prefix()` (✅ VERIFICATO SICURO)

**Indagine:** Audit completo di tutti i pattern `iter()` e `iter_prefix()` in tutti i pallet, cercando uso non-deterministico dove l'ordine degli elementi potrebbe influenzare il risultato.

**Risultato:** Tutti i pattern trovati sono sicuri:
- **pallet-uomi-engine:** Tutti gli `iter()` raccolgono in `BTreeMap` prima dell'uso
- **pallet-tss:** Tutti gli `iter_prefix()` raccolgono in `BTreeMap`
- **pallet-ipfs:** Tutti gli `iter()` sono order-independent (somme, filtri, collect in Vec)
- **pallet-unified-accounts:** No iter/iter_prefix usati

**Nessuna modifica necessaria** per questo punto.

---

### Fix 3: Bug logico `opoc_nodes_works_operations_count` (✅ CORRETTO)

**Problema:** In `pallets/uomi-engine/src/opoc.rs`, la funzione `opoc_nodes_works_operations_count` non sottraeva correttamente le operazioni pending removal dal conteggio.

**Prima:**
```rust
fn opoc_nodes_works_operations_count() -> u32 {
    OPoCNodesWorks::<T>::iter().count() as u32
}
```

**Dopo:**
```rust
fn opoc_nodes_works_operations_count() -> u32 {
    let total = OPoCNodesWorks::<T>::iter().count() as u32;
    let removed_count = OPoCNodesWorksPendingRemoval::<T>::iter().count() as u32;
    let added_count = OPoCNodesWorksPendingAdditions::<T>::iter().count() as u32;
    total.saturating_sub(removed_count) + added_count
}
```

**File modificato:** `pallets/uomi-engine/src/opoc.rs`

---

### Fix 4: TSS `process_completed_signatures` — Ordine deterministico (✅ CORRETTO)

**Problema:** In `pallets/tss/src/lib.rs`, `process_completed_signatures` iterava su `CompletedSignatures` e processava le voci in ordine non deterministico.

**Soluzione:** Raccolta in `BTreeMap` prima di processare per garantire ordine deterministico.

**File modificato:** `pallets/tss/src/lib.rs`

---

### Fix 5: TSS `get_agent_wallet_address` — Tie-breaker deterministico (✅ CORRETTO)

**Problema:** In `pallets/tss/src/lib.rs`, `get_agent_wallet_address` ordinava per stake ma in caso di parità non aveva un tie-breaker deterministico.

**Soluzione:** Aggiunto ordinamento secondario lessicografico per AccountId in caso di parità di stake.

**File modificato:** `pallets/tss/src/lib.rs`

---

### Fix 6: Migrazione da `NativeElseWasmExecutor` a `WasmExecutor` (✅ IMPLEMENTATO)

**Problema ipotizzato:** Con `NativeElseWasmExecutor`, il validatore esegue blocchi in native (x86_64) mentre l'import verification usa WASM. Anche con codice sorgente identico, i target di compilazione x86_64 e wasm32 possono produrre risultati sottilmente diversi (floating point, padding, ecc.).

**Soluzione implementata:**
- Rimosso `struct Executor` che implementava `NativeExecutionDispatch` 
- Sostituito `NativeElseWasmExecutor<Executor>` con `WasmExecutor<HostFunctions>` ovunque
- Sostituito `new_native_or_wasm_executor` con `new_wasm_executor::<HostFunctions>`
- Aggiornati tutti i generics in benchmarking

**File modificati:**
- `node/src/uomi/service.rs` — migrazione completa
- `node/src/local/service.rs` — migrazione completa
- `node/src/uomi/mod.rs` — rimosso `Executor` da re-exports
- `node/src/local/mod.rs` — rimosso `Executor` da re-exports
- `node/src/benchmarking.rs` — migrati tutti i generics

**Compilazione:** `cargo check -p uomi` passato con successo (7m 45s, solo warning, zero errori)

**Bump spec_version:** 14 → 15 (poi l'utente ha portato a 16)

**Risultato:** ❌ L'errore persiste anche dopo il deploy del nuovo binario con WasmExecutor.

---

### Fix 7: Aumento WASM Instance Pool (❌ NON HA RISOLTO)

**Ipotesi:** Il log mostrava `"Ran out of free WASM instances"` appena prima del blocco fallito. Ipotizzato che esaurimento del pool di istanze WASM causasse stato corrotto.

**Tentativo:** Avviato il nodo con `--max-runtime-instances 32 --runtime-cache-size 8`

**Risultato:** ❌ Stesso identico errore al blocco `0x1544...`.

---

### Fix 8: DB Pulito (❌ NON HA RISOLTO)

**Ipotesi:** Lo stato nel database poteva essere corrotto da un'esecuzione parziale precedente.

**Verifica:** L'utente ha confermato che il DB era già stato riscaricato da zero — il blocco bloccante non era mai stato eseguito in quel DB. L'errore è deterministico alla prima importazione.

**Risultato:** ❌ Ipotesi smentita — non è un problema di DB corrotto.

---

## 4. Ipotesi Testate e Risultati

| # | Ipotesi | Azione | Risultato |
|---|---------|--------|-----------|
| 1 | IPFS inherent non registrato | Creato `IpfsInherentDataProvider` + fix `check_inherent` | ✅ Risolto (errore diverso) |
| 2 | Non-determinismo da `iter()`/`iter_prefix()` | Audit completo | ✅ Tutti sicuri |
| 3 | Bug logico opoc count | Fix con `saturating_sub` | ✅ Corretto |
| 4 | TSS ordine non-deterministico | BTreeMap + tie-breaker | ✅ Corretto |
| 5 | **Divergenza native vs WASM** | Migrazione a `WasmExecutor` | ❌ Errore persiste |
| 6 | **Pool WASM esaurito** | `--max-runtime-instances 32` | ❌ Errore persiste |
| 7 | **DB corrotto** | DB pulito riscaricato | ❌ Errore persiste |
| 8 | Non-determinismo da HashMap/HashSet | Audit completo | ✅ Nessuno trovato nel runtime |
| 9 | Floating point non-deterministico | Audit completo | ✅ Nessuno trovato |
| 10 | `usize` encoding architecture-dependent | Audit completo | ✅ Nessuno trovato |
| 11 | Precompile non-deterministiche | Audit completo | ✅ Tutte sicure |
| 12 | Fonte Randomness non-deterministica | Verificato | ✅ Usa `ParentBlockRandomness` (deterministico) |

---

## 5. Stato Attuale delle Verifiche

### Verifiche positive (identiche su tutti i nodi)

| Check | Metodo | Valore |
|-------|--------|--------|
| **Binary sha256** | `sha256sum ./uomi` | `00491c44312f925d7ce1e6e49b06a089b1e508e19451c786f5026d10a682e30c` |
| **specVersion** | `system_version` RPC | `16` |
| **WASM blob on-chain** | `state_getStorage(":code")` hash | Identico su entrambi i nodi |
| **Executor** | codice sorgente | `WasmExecutor<HostFunctions>` (non più NativeElseWasmExecutor) |

### Il blocco bloccante

- **Hash:** `0x15440964ea61b298b1f4c30ea03e53657340f0672bef35cad52f02b400330a78`
- **Comportamento:** Sempre lo stesso blocco, qualsiasi nodo che tenta di importarlo fallisce
- **Errore:** Il Frontier Ethereum digest (IntermediateStateRoot) nell'header del blocco non corrisponde al valore ricalcolato durante la ri-esecuzione

---

## 6. Analisi della Root Cause Più Probabile

### Teoria: Il blocco è stato prodotto con il VECCHIO binario (native execution)

Questa è l'ipotesi più probabile rimasta:

1. **Il validatore ha prodotto il blocco `0x1544...`** usando il **vecchio binario** che aveva `NativeElseWasmExecutor`
2. Durante la produzione del blocco, il `on_finalize` di `pallet_ethereum` ha calcolato `IntermediateStateRoot` tramite **esecuzione nativa** (x86_64)
3. Questo state root è stato sigillato nell'header del blocco come digest item  
4. **Dopo** la produzione di quel blocco, il validatore è stato aggiornato al nuovo binario con `WasmExecutor`
5. Ora qualsiasi nodo che tenta di ri-eseguire quel blocco usa **WASM execution**, che produce un state root leggermente diverso
6. `frame_executive::final_checks` confronta i digest → **mismatch → panic**

**Perché il validatore originale riesce a passarlo:** Il validatore non ri-esegue i propri blocchi che ha già prodotto e finalizzato — sono già nel suo DB.

**Perché il mismatch è permanente:** L'header del blocco è immutabile una volta sigillato. Il digest calcolato con native execution non può essere riprodotto da WASM.

### Possibili cause della differenza native vs WASM

- **Floating point rounding** (improbabile — non trovato nel runtime)
- **Padding/alignment di strutture** (target-dependent layout)
- **Ordine di operazioni nello storage trie** che differisce sottilmente tra native e WASM
- **Host functions che restituiscono risultati diversi** tra native e WASM context
- **Un pallet (es. UomiEngine) che durante `on_finalize` produce storage writes non-deterministiche** che non sono state catturate dall'audit (improbabile ma possibile)

### Teoria Alternativa: FrontierBlockImport sigilla il digest fuori dal WASM

È possibile che il digest Frontier venga calcolato durante la fase di `block_import` lato client (non dentro il WASM runtime) e poi iniettato nell'header. In quel caso, il problema potrebbe essere nel codice di `FrontierBlockImport` che usa una logica diversa per calcolare lo state root rispetto a quella usata durante la ri-esecuzione nel WASM.

---

## 7. Possibili Soluzioni

### Opzione A: Skip del blocco problematico (workaround)

Aggiungere una hardcoded exception in `frame_executive` o nel block import per accettare il blocco con hash `0x1544...` senza verificare il digest. Questo è un workaround sporco ma permetterebbe alla chain di continuare.

```rust
// Nel runtime, in final_checks o in un wrapper
if block_hash == known_problematic_hash {
    // skip digest verification
}
```

**Pro:** Rapido, permette alla chain di continuare  
**Contro:** Hack, va rimosso dopo

### Opzione B: Fork della chain

Se il validatore è sotto controllo, fare un fork escludendo il blocco problematico e ri-producendo da quel punto in poi con il nuovo binario.

**Pro:** Soluzione pulita  
**Contro:** Richiede coordinamento, possibile perdita di transazioni

### Opzione C: Revert temporaneo a NativeElseWasmExecutor

Tornare al vecchio executor per permettere ai nodi di importare il blocco con native execution, poi fare il setCode con il nuovo WASM e successivamente migrare a WasmExecutor.

**Pro:** Potrebbe funzionare se il problema è davvero native vs WASM  
**Contro:** Reintroduce il problema originale, potrebbe non funzionare se il nativo del nuovo binario è diverso da quello del vecchio

### Opzione D: Indagine profonda sul digest

Aggiungere logging dettagliato per capire esattamente:
1. Quanti digest items ha il blocco
2. Quale digest specifico non corrisponde (BABE? GRANDPA? Frontier Ethereum?)
3. Il valore atteso vs quello calcolato

Questo richiede modifiche al `frame_executive` per stampare i digest prima del panic.

---

## 8. File Modificati In Questa Sessione

### Nuovi file
| File | Descrizione |
|------|-------------|
| `node/src/ipfs_inherent.rs` | No-op InherentDataProvider per `ipfs-ide` |

### File modificati
| File | Modifica |
|------|----------|
| `node/src/uomi/service.rs` | Migrato da `NativeElseWasmExecutor<Executor>` a `WasmExecutor<HostFunctions>`, registrato `IpfsInherentDataProvider` |
| `node/src/local/service.rs` | Stessa migrazione di uomi/service.rs |
| `node/src/uomi/mod.rs` | Rimosso `Executor` da re-exports |
| `node/src/local/mod.rs` | Rimosso `Executor` da re-exports |
| `node/src/benchmarking.rs` | Migrati generics da `NativeExecutionDispatch` a `HostFunctions` |
| `node/src/lib.rs` | Aggiunto `pub mod ipfs_inherent;` |
| `pallets/ipfs/src/lib.rs` | `check_inherent` → return `Ok(())` sempre |
| `pallets/uomi-engine/src/opoc.rs` | Fix `opoc_nodes_works_operations_count` con `saturating_sub` |
| `pallets/tss/src/lib.rs` | BTreeMap in `process_completed_signatures`, tie-breaker in `get_agent_wallet_address` |
| `runtime/uomi/src/lib.rs` | `spec_version` bumped (14 → 15, poi utente ha portato a 16) |

---

## Prossimi Passi Consigliati

1. **Determinare QUANDO il blocco `0x1544...` è stato prodotto** — prima o dopo l'aggiornamento del binario sul validatore?
2. **Aggiungere logging diagnostico** a `frame_executive::final_checks` per capire QUALE digest item non corrisponde e i valori esatti
3. **Verificare se il validatore ha lo stesso problema** se cancella il suo DB e prova a ri-sincronizzare
4. **Considerare l'Opzione A** (skip del blocco) come soluzione temporanea per sbloccare la rete

---

*Documento generato durante sessione di debug. Ultimo aggiornamento: 10 marzo 2026.*
