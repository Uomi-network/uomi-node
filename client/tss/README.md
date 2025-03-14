# UOMI Threshold Signature Scheme (TSS) Implementation

This document provides a comprehensive overview of the UOMI blockchain's Threshold Signature Scheme (TSS) implementation. It supports both FROST (Flexible Round-Optimized Schnorr Threshold signatures) for Ed25519 and ECDSA (using GG20/DMZ21-like protocols).

## Table of Contents

1.  [Introduction](#introduction)
2.  [Design Goals and Challenges](#design-goals-and-challenges)
3.  [Architecture Overview](#architecture-overview)
4.  [Key Components](#key-components)
    *   [4.1 Gossip Network Integration](#41-gossip-network-integration)
    *   [4.2 TSS Message Handling](#42-tss-message-handling)
    *   [4.3 Session Management](#43-session-management)
    *   [4.4 Runtime Event Handling](#44-runtime-event-handling)
    *   [4.5 Peer Mapping](#45-peer-mapping)
    *   [4.6 Data Storage](#46-data-storage)
    *   [4.7 FROST DKG Round 1](#47-frost-dkg-round-1)
    *   [4.8 FROST DKG Round 2](#48-frost-dkg-round-2)
    *   [4.9 FROST DKG Finalization (Round 3)](#49-frost-dkg-finalization-round-3)
    *   [4.10 FROST Signing Commitment Generation](#410-frost-signing-commitment-generation)
    *   [4.11 FROST Signing Package Creation](#411-frost-signing-package-creation)
    *   [4.12 FROST Signature Share Generation](#412-frost-signature-share-generation)
    *   [4.13 FROST Signature Aggregation](#413-frost-signature-aggregation)
    *   [4.14 ECDSA Key Generation and Signing](#414-ecdsa-key-generation-and-signing)
    *   [4.15 Message Buffering](#415-message-buffering)
5.  [Concurrency Model](#concurrency-model)
6.  [Error Handling](#error-handling)
7.  [Future Improvements](#future-improvements)

## 1. Introduction <a name="introduction"></a>

This library provides the off-chain components necessary for performing threshold cryptography on the UOMI blockchain.  It enables a group of validators to collaboratively generate keys and sign messages without any single validator having complete control over the private key. This enhances security and resilience. The library is designed to be integrated with a Substrate-based blockchain, interacting with an on-chain TSS pallet.

## 2. Design Goals and Challenges <a name="design-goals-and-challenges"></a>

**Design Goals:**

*   **Security:**  The primary goal is to provide secure key generation and signing, preventing any single point of failure or compromise.
*   **Reliability:**  The system must be robust against network partitions, node failures, and message delays.
*   **Efficiency:**  Minimize communication overhead and computational cost.
*   **Modularity:**  The code is structured into well-defined modules with clear interfaces, making it easier to maintain and extend.
*   **Integration:**  Seamless integration with the Substrate framework and the on-chain TSS pallet.

**Challenges and Solutions:**

| Challenge                                     | Solution                                                                                                                                                                                                                                                                                          |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Message Ordering & Race Conditions**        | Robust buffering system in `SessionManager` to temporarily store early messages until the appropriate session state is reached.  This prevents messages from being dropped or processed out of order.                                                                                             |
| **Network Reliability**                       | Session timeouts with the `session_timestamps` map and `cleanup_expired_sessions()` mechanism. Failed sessions are automatically cleaned up to prevent resource leaks and ensure the system can recover from network issues.                                                                  |
| **Thread Safety & Concurrency**               | Careful use of `Arc<Mutex<>>` for shared state and fine-grained locking to minimize contention.  This allows multiple TSS sessions to run concurrently without data races or deadlocks.                                                                                                        |
| **Protocol State Machine Complexity**         | Clear state machine approach in `SessionManager`, using the `DKGSessionState` and `SigningSessionState` enums for precise state tracking.  This simplifies the logic for handling messages and events at different stages of the protocols.                                                     |
| **Integration with Substrate Runtime Events** | `RuntimeEventHandler` listens for on-chain events (using `BlockchainEvents`) and translates them into internal messages for the `SessionManager`. This ensures the off-chain worker stays synchronized with the on-chain state.                                                                 |
| **Serialization and Deserialization**          |  Uses `parity-scale-codec` for consistent and efficient serialization/deserialization of messages and data structures. This is crucial for network communication and data storage.                                                                                                                 |

## 3. Architecture Overview <a name="architecture-overview"></a>

The architecture consists of several key components that interact to provide the TSS functionality:

```
+-------------------------------------------------------------------------------------------+
|                                   UOMI TSS System                                         |
+-------------------------------------------------------------------------------------------+
|  +---------------------+      +---------------------------+   +---------------------+     |
|  |   GossipHandler     |      |    SessionManager         |   | RuntimeEventHandler |     |
|  +---------------------+      +---------------------------+   +---------------------+     |
|  | - GossipEngine      |      | - DKGSessionState         |   | - BlockchainEvents  |     |
|  | - TssValidator      |      | - SigningSessionState     |   | - TssApi            |     |
|  | - PeerMapper        |      | - PeerMapper              |   +---------------------+     |
|  +---------------------+      | - Storage                 |           ^                   |
|          ^                    | - ECDSAManager            |           |                   |
|          |                    | - Message Buffer          |           | (Runtime Events)  |
|  (Network Messages)           +---------------------------+           |                   |
|          |                    |          ^                |           |                   |
|          |                    |          |                |           v                   |
|          v                    |          | (TSS Messages) |     +---------------------+   |
|  +---------------------+      |          |                |     |   Substrate Node    |   |
|  |   Substrate Node    |      |          v                |     +---------------------+   |
|  | (Network Service)   |      |  +---------------------+  |     | - pallet_tss        |   |
|  +---------------------+      |  |     Storage         |  |     +---------------------+   |
|                               |  +---------------------+  |                               |
|                               |  | - MemoryStorage     |  |                               |
|                               |  | - FileStorage       |  |                               |
|                               |  +---------------------+  |                               |
+-------------------------------------------------------------------------------------------+

```

*   **GossipHandler:** Manages peer-to-peer communication using the `sc-network-gossip` crate.  It handles message validation, broadcasting, and direct sending.
*   **SessionManager:** The central coordinator for TSS operations.  It tracks session states, manages participants, handles timeouts, and processes messages and events.
*   **RuntimeEventHandler:** Listens for events from the Substrate runtime (specifically, the `pallet-tss`) and notifies the `SessionManager`.
*   **Storage:** An abstraction for data persistence (in-memory or file system).
*   **PeerMapper:**  Maintains mappings between network peer IDs, validator public keys, and session-specific identifiers.
*   **ECDSAManager:** Handles the multi-party ECDSA key generation and signing processes.
*   **Substrate Node:** The blockchain node, including the `pallet_tss`, which manages TSS sessions on-chain.

## 4. Key Components <a name="key-components"></a>

### 4.1 Gossip Network Integration <a name="41-gossip-network-integration"></a>

*   **Purpose:** Provides the underlying peer-to-peer communication layer.
*   **Key Crates:** `sc-network`, `sc-network-gossip`.
*   **Key Structs:**
    *   `GossipEngine`:  The core gossip engine.
    *   `GossipHandler`:  Manages sending and receiving messages, interacting with the `GossipEngine`.
    *   `TssValidator`:  A custom validator that checks the validity of incoming TSS messages.
*   **Key Functions:**
    *   `setup_gossip()`:  Initializes the gossip network components.
    *   `GossipHandler::broadcast_message()`:  Broadcasts a message to all peers.
    *   `GossipHandler::send_message()`:  Sends a message directly to a specific peer.
    *   `GossipEngine::new()`: Creates a new `GossipEngine` instance.
    *   `GossipEngine::gossip_message()`:  Broadcasts a message using the gossip protocol.
    *   `GossipEngine::send_message()`: Sends a direct message.
    *   `TssValidator::new_peer()`: Handles new peer connections (sends an announcement).
    *   `TssValidator::validate()`:  Validates incoming messages.
* **Workflow:**
    1.  `setup_gossip()` is called during node startup to create the `GossipEngine` and `GossipHandler`.
    2.  The `GossipHandler` listens for incoming messages using a `Receiver<TopicNotification>`.
    3.  When a message arrives, the `TssValidator` checks its validity.
    4.  Valid messages are passed to the `SessionManager` for processing.
    5.  The `GossipHandler` also handles sending messages (broadcast and direct) initiated by the `SessionManager`.

### 4.2 TSS Message Handling <a name="42-tss-message-handling"></a>

*   **Purpose:** Defines the structure and types of messages exchanged between TSS nodes.
*   **Key Enums:**
    *   `TssMessage`:  An enum that encapsulates all possible message types (FROST, ECDSA, utility).
    *   `ECDSAPhase`:  An enum to distinguish between different phases of the ECDSA protocol (Key generation, Offline Signing, Online Signing).
*   **Key Functions:**
    *   `GossipHandler::poll()`:  Handles incoming gossip messages and forwards them to the `SessionManager`.
    *   `SessionManager::handle_gossip_message()`:  Processes incoming messages based on their type.
*   **Workflow:**
    1.  Messages are serialized using `parity-scale-codec`'s `Encode` trait.
    2.  Messages are sent over the network using the `GossipEngine`.
    3.  The `GossipHandler` receives messages and deserializes them using `Decode`.
    4.  The `SessionManager::handle_gossip_message()` function uses pattern matching (`match`) to handle different `TssMessage` variants.

### 4.3 Session Management <a name="43-session-management"></a>

*   **Purpose:** Coordinates TSS operations, tracks session states, manages participants, and handles timeouts.
*   **Key Structs:**
    *   `SessionManager`: The central coordinator.
    *   `DKGSessionState`:  An enum representing the state of a DKG session.
    *   `SigningSessionState`: An enum representing the state of a signing session.
*   **Key Functions:**
    *   `SessionManager::new()`:  Creates a new `SessionManager` instance.
    *   `SessionManager::run()`:  The main loop that processes incoming messages and events.
    *   `SessionManager::handle_gossip_message()`:  Handles messages received from the gossip network.
    *   `SessionManager::add_session_data()`:  Adds a new session to the manager.
    *   `SessionManager::get_session_data()`:  Retrieves session data.
    *   `SessionManager::cleanup_expired_sessions()`:  Removes timed-out sessions.
    *   `SessionManager::dkg_handle_session_created()`:  Handles the creation of a new DKG session.
    *   `SessionManager::dkg_handle_round1_message()`, `SessionManager::dkg_handle_round2_message()`: Handle messages for specific DKG rounds.
    *   `SessionManager::signing_handle_session_created()`, etc.:  Handle signing-related operations.
*   **Workflow:**
    1.  The `SessionManager` receives messages from the `GossipHandler` and events from the `RuntimeEventHandler`.
    2.  It uses the `dkg_session_states` and `signing_session_states` maps to track the current state of each session.
    3.  It uses the `sessions_participants` map to manage the participants in each session.
    4.  It uses the `session_timestamps` map and `session_timeout` value to enforce timeouts.
    5.  It interacts with the `Storage` trait to persist session data.
    6.  It uses the `PeerMapper` to resolve peer IDs and account IDs.
    7.  It interacts with the `ECDSAManager` to handle ECDSA operations.

### 4.4 Runtime Event Handling <a name="44-runtime-event-handling"></a>

*   **Purpose:** Listens for events from the Substrate runtime and notifies the `SessionManager`.
*   **Key Struct:** `RuntimeEventHandler`.
*   **Key Enum:** `TSSRuntimeEvent`: Represents the different types of runtime events.
*   **Key Functions:**
    *   `RuntimeEventHandler::new()`:  Creates a new `RuntimeEventHandler` instance.
    *   `RuntimeEventHandler::run()`:  The main loop that listens for runtime events.
*   **Workflow:**
    1.  The `RuntimeEventHandler` uses `BlockchainEvents` to subscribe to storage change notifications from the runtime.
    2.  It filters these notifications to identify `TssEvent`s from the `pallet_tss`.
    3.  When a relevant event (e.g., `DKGSessionCreated`, `SigningSessionCreated`) is detected, it constructs a `TSSRuntimeEvent` and sends it to the `SessionManager`.

### 4.5 Peer Mapping <a name="45-peer-mapping"></a>

*   **Purpose:** Maintains mappings between `PeerId`, `TSSPublic`, and `Identifier`.
*   **Key Struct:** `PeerMapper`.
*   **Key Functions:**
    *   `PeerMapper::new()`: Creates a new `PeerMapper` instance.
    *   `PeerMapper::add_peer()`: Adds a new peer mapping (PeerId to TSSPublic).
    *   `PeerMapper::get_account_id_from_peer_id()`: Retrieves the TSSPublic associated with a PeerId.
    *   `PeerMapper::get_peer_id_from_account_id()`: Retrieves the PeerId associated with a TSSPublic.
    *   `PeerMapper::get_identifier_from_peer_id()`: Retrieves the Identifier associated with a PeerId within a specific session.
    *   `PeerMapper::get_identifier_from_account_id()`: Retrieves the Identifier associated with a TSSPublic within a specific session.
    *   `PeerMapper::create_session()`: Initializes the mapping for a new session (associating Identifiers with TSSPublics).
*   **Workflow:**
    1.  The `PeerMapper` is initialized when the node starts up.
    2.  When a node receives an `Announce` message, it calls `PeerMapper::add_peer()` to store the mapping between the sender's `PeerId` and their `TSSPublic` key.
    3.  When a new session is created, `PeerMapper::create_session()` is called to store the mappings between participant identifiers and their public keys.
    4.  The `SessionManager` uses the `PeerMapper`'s lookup functions to route messages to the correct participants.

### 4.6 Data Storage <a name="46-data-storage"></a>

*   **Purpose:** Provides an abstraction for storing and retrieving data related to TSS operations.
*   **Key Trait:** `Storage`.
*   **Key Structs:**
    *   `MemoryStorage`: An in-memory implementation using `BTreeMap`.
    *   `FileStorage`: A file system-based implementation.
    *   `StorageType`: An enum that specifies the type of data being stored.
*   **Key Functions:**
    *   `Storage::store_data()`: Stores data.
    *   `Storage::read_data()`: Retrieves data.
    *   Other methods (e.g., `read_secret_package_round1()`) provide specialized access for specific data types.
*   **Workflow:**
    1.  The `SessionManager` uses the `Storage` trait to interact with the chosen storage implementation (either `MemoryStorage` or `FileStorage`).
    2.  Data is stored and retrieved using the `store_data()` and `read_data()` methods, along with the `StorageType` enum to specify the data type.

### 4.7 FROST DKG Round 1 <a name="47-frost-dkg-round-1"></a>

*   **Purpose:** Implements the first round of the FROST DKG protocol.
*   **Key File:** `dkground1.rs`.
*   **Key Function:** `generate_round1_secret_package()`.
*   **Workflow:**
    1.  The `SessionManager::dkg_handle_session_created()` function calls `generate_round1_secret_package()` to initiate round 1.
    2.  `generate_round1_secret_package()` uses the `frost-ed25519` crate to generate a secret share and a corresponding public commitment.
    3.  The public commitment is broadcast to all other participants.
    4.  The `SessionManager::dkg_handle_round1_message()` function handles incoming round 1 packages from other participants.

### 4.8 FROST DKG Round 2 <a name="48-frost-dkg-round-2"></a>

*   **Purpose:** Implements the second round of the FROST DKG protocol.
*   **Key File:** `dkground2.rs`.
*   **Key Function:** `round2_verify_round1_participants()`.
*   **Workflow:**
    1.  `SessionManager::dkg_verify_and_start_round2()` calls `round2_verify_round1_participants()`.
    2.  `round2_verify_round1_participants()` receives the public commitments from all other participants, verifies them, and generates a round 2 package to send to each participant.
    3.  `SessionManager::dkg_handle_round2_message()` handles incoming round 2 packages.

### 4.9 FROST DKG Finalization (Round 3) <a name="49-frost-dkg-finalization-round-3"></a>

*   **Purpose:** Completes the DKG process.
*   **Key Function:** `dkg::part3` (from `frost-ed25519`).
*   **Workflow:**
    1.  `SessionManager::dkg_verify_and_complete()` calls `dkg::part3` to finalize the DKG.
    2.  `dkg::part3` combines the round 2 packages to compute the shared secret key and the public key package.

### 4.10 FROST Signing Commitment Generation <a name="410-frost-signing-commitment-generation"></a>

*   **Purpose:** Generates signing nonces and commitments.
*   **Key File:** `signlib.rs`.
*   **Key Function:** `generate_signing_commitments_and_nonces()`.
*   **Workflow:**
    1.  `SessionManager::signing_handle_session_created()` calls `generate_signing_commitments_and_nonces()`.
    2.  `generate_signing_commitments_and_nonces()` uses the `frost-ed25519` crate to generate a signing nonce and a corresponding commitment.
    3.  The commitments are shared with the coordinator (or all participants).

### 4.11 FROST Signing Package Creation <a name="411-frost-signing-package-creation"></a>

*   **Purpose:** Creates the signing package.
*   **Key File:** `signlib.rs`.
*   **Key Function:** `get_signing_package()`.
*   **Workflow:**
    1.  `SessionManager::signing_handle_verification_to_complete_round1()` calls `get_signing_package()`.
    2.  `get_signing_package()` creates a `SigningPackage` containing the message to be signed and the collected commitments.

### 4.12 FROST Signature Share Generation <a name="412-frost-signature-share-generation"></a>

*   **Purpose:** Generates individual signature shares.
*   **Key Function:** `frost_round2_sign` (from `frost-ed25519`).
*   **Workflow:**
    1.  `SessionManager::signing_handle_signing_package()` calls `frost_round2_sign`.
    2.  `frost_round2_sign` computes a signature share using the signing package, the participant's secret nonce, and their secret key share.

### 4.13 FROST Signature Aggregation <a name="413-frost-signature-aggregation"></a>

*   **Purpose:** Aggregates signature shares to produce the final signature.
*   **Key Function:** `aggregate` (from `frost-ed25519`).
*   **Workflow:**
    1.  `SessionManager::signing_handle_signature_share()` calls `aggregate`.
    2.  `aggregate` combines the signature shares to produce the final, valid FROST signature.

### 4.14 ECDSA Key Generation and Signing <a name="414-ecdsa-key-generation-and-signing"></a>

*   **Purpose:** Implements ECDSA key generation and signing using the `multi-party-ecdsa` crate.
*   **Key Struct:** `ECDSAManager`.
*   **Key Functions:**
    *   `ECDSAManager::new()`: Creates a new `ECDSAManager` instance.
    *   `ECDSAManager::add_keygen()`, `ECDSAManager::add_sign()`, `ECDSAManager::add_sign_online()`: Initialize new ECDSA operations.
    *   `ECDSAManager::handle_keygen_message()`, `ECDSAManager::handle_sign_message()`, `ECDSAManager::handle_sign_online_message()`: Handle incoming messages for each phase.
    *   Buffer handling functions (`handle_keygen_buffer`, etc.): Process buffered messages.
    *   `SessionManager::handle_gossip_message()`: Routes ECDSA messages to the `ECDSAManager`.
    *   `SessionManager::ecdsa_create_keygen_phase()`, `SessionManager::ecdsa_create_sign_phase()`, `SessionManager::handle_ecdsa_sending_messages()`: Helper functions to initiate and manage ECDSA operations.
*   **Workflow:**
    1.  The `SessionManager` receives ECDSA-related `TssMessage`s.
    2.  It calls the appropriate handler functions on the `ECDSAManager` instance.
    3.  The `ECDSAManager` uses the `multi-party-ecdsa` crate to perform the cryptographic operations.
    4.  The `ECDSAManager` also handles buffering messages if they arrive out of order.

### 4.15 Message Buffering <a name="415-message-buffering"></a>

*   **Purpose:** Handles messages that arrive out of order.
*   **Key Data Structure:** `buffer` (within `SessionManager`): A `HashMap` that stores buffered messages.
*   **Key Functions:**
    *   `SessionManager::handle_gossip_message()`: Adds messages to the buffer if the corresponding session is not yet ready.
    *   `SessionManager::dkg_process_buffer_for_round2()` (and similar functions): Processes buffered messages when the session is ready.
*   **Workflow:**
    1.  If a message arrives for a session that doesn't exist or is not in the correct state, it's added to the `buffer`.
    2.  When the session is created or reaches the appropriate state, the buffered messages are processed.

## 5. Concurrency Model <a name="concurrency-model"></a>

The library uses a combination of asynchronous programming (with `async`/`await` and `futures`) and multi-threading to handle concurrent operations.

*   **`async`/`await`:** Used for non-blocking I/O operations (network communication, file system access).
*   **`futures`:**  Used to represent asynchronous computations.
*   **`Arc<Mutex<>>`:** Used to share mutable state between threads safely.  `Arc` provides shared ownership, and `Mutex` provides exclusive access to the data.
*   **`RwLock`:** Used within the `ECDSAManager` to allow for concurrent read access to the ECDSA operation state, while still providing exclusive write access when needed.
*   **`TracingUnboundedSender` and `TracingUnboundedReceiver`:**  Used for asynchronous message passing between different components (e.g., `GossipHandler`, `SessionManager`, `RuntimeEventHandler`).

## 6. Error Handling <a name="error-handling"></a>

*   **`Result` type:**  Most functions return a `Result` to indicate success or failure.  This allows for proper error handling and propagation.
*   **Custom Error Types:**  The code defines custom error types (e.g., `SessionManagerError`, `ECDSAError`) to provide more specific error information.
*   **Logging:**  The `log` crate is used extensively to provide detailed logging of events, warnings, and errors. This is crucial for debugging and monitoring.
* **Session Timeouts**: The `SessionManager` implements timeouts to handle cases where participants become unresponsive.

## 7. Future Improvements <a name="future-improvements"></a>

*   **Database Integration:**  Replace `FileStorage` with a database-backed storage implementation for improved scalability and reliability.
*   **More Sophisticated Buffering:** Implement a more sophisticated buffering mechanism that can handle different message types and priorities.
*   **Formal Verification:** Explore using formal methods to verify the correctness of the cryptographic protocols and the implementation.
*   **Performance Optimization:**  Profile the code to identify performance bottlenecks and optimize critical sections.
*   **Dynamic Threshold and Participants:**  Allow for dynamic changes to the threshold (`t`) and the set of participants.
*   **Integration with other cryptographic schemes:** Add support for other threshold signature schemes, such as BLS.
* **Improved error messages**: Improve the error messages to be more descriptive.

