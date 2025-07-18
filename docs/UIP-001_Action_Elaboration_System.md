# **UOMI Improvement Proposal: On-Chain Action Elaboration System**

**UIP Number:** UIP-001  
**Title:** On-Chain Action Elaboration System  
**Status:** Draft  
**Type:** Core  
**Category:** Engine Enhancement  
**Created:** June 24, 2025  
**Author:** Development Team  

---

## **Executive Summary**

This proposal introduces an **On-Chain Action Elaboration System** for the UOMI Engine that transforms AI agent outputs from passive data into executable on-chain actions. The system interprets structured agent responses as actionable instructions, manages their execution through a Finite State Automata framework, and integrates with the existing TSS (Threshold Signature Scheme) pallet for secure transaction signing.

**Key Benefits:**
- Enables AI agents to autonomously execute blockchain transactions
- Creates feedback loops where transaction results can trigger new agent invocations
- Maintains security through existing validator consensus and TSS infrastructure
- Provides extensible framework for future action types beyond transactions

---

## **1. Problem Statement**

### **Current Limitations**
The existing UOMI Engine processes AI agent requests and stores outputs as static data. While this enables computation verification through OPoC (Optimistic Proof of Computation), it lacks the capability for agents to:

1. **Execute Actions:** Agents cannot trigger blockchain transactions, contract calls, or external integrations
2. **Create Feedback Loops:** No mechanism for transaction results to inform subsequent agent executions
3. **Autonomous Operation:** Agents cannot operate independently beyond single request-response cycles
4. **Complex Workflows:** No support for multi-step, conditional, or dependent action sequences

### **Market Opportunity**
The growing demand for autonomous AI agents in DeFi, governance, and cross-chain operations requires systems that can:
- Execute trades and portfolio management autonomously
- Participate in governance decisions based on analysis
- Coordinate cross-chain operations and arbitrage
- Manage treasury and resource allocation dynamically

---

## **2. Proposed Solution**

### **2.1 System Architecture**

The Action Elaboration System introduces four core components:

#### **Action Parser Framework**
- **Purpose:** Extract structured action sets from agent outputs
- **Capability:** Support multiple output formats (JSON, custom protocols)
- **Validation:** Security checks, resource limits, and authorization verification
- **Extensibility:** Pluggable parsers for different agent types and output formats

#### **Finite State Automata Engine**
- **Purpose:** Manage action execution lifecycles through deterministic state transitions
- **States:** `Pending` → `Triggered` → `Executing` → `Completed` (with failure branches)
- **Features:** Timeout handling, dependency management, rollback mechanisms
- **Monitoring:** Complete audit trail of state transitions

#### **Transaction Request Handler**
- **Purpose:** Specialized handling for blockchain transaction actions
- **Features:** Multi-chain support, gas management, retry logic
- **Integration:** Seamless connection with existing TSS infrastructure
- **Callbacks:** Parse transaction results for follow-up actions

#### **TSS Integration Layer**
- **Purpose:** Leverage existing TSS pallet for secure transaction signing
- **Security Model:** Distributed signature generation with threshold requirements
- **Authority:** Actions executed under agent-specific identities with proper authorization
- **Multi-Chain:** Support for various target blockchains through unified signing interface

### **2.2 Critical Design Decision: Signature Timing**

#### **Post-Consensus Signature Generation**
The system implements a **post-consensus signing** approach where:

1. **Consensus First:** Agent outputs and action parsing reach consensus across all validators
2. **Deterministic Processing:** All validators process identical action sets in identical order
3. **Coordinated Signing:** TSS signature generation occurs after consensus is achieved
4. **Synchronized Execution:** Transaction submission happens uniformly across the network

#### **Benefits of Post-Consensus Signing**
- **Deterministic Behavior:** All validators execute identical actions in identical order
- **Consensus Safety:** No validator disagreement about which actions to execute
- **Audit Consistency:** Identical execution logs across all network participants
- **Security Preservation:** Maintains existing consensus security guarantees

#### **Implementation Requirements**
- **Consensus Integration:** Action parsing and validation must be consensus-critical operations
- **TSS Coordination:** Signature generation coordinated across validator set
- **Block Scheduling:** Actions scheduled for execution in specific future blocks
- **State Synchronization:** All validators maintain synchronized action execution state

### **2.3 Data Flow Design**

```
Agent Output → Action Parser → FSA Engine → Transaction Handler → Blockchain
     ↑              ↓            ↓              ↓                ↓
     └──── Feedback Loop ←── Result Monitor ←──┴────────────────┘
```

**Detailed Flow:**
1. **Agent Execution:** Agent completes processing and generates structured output
2. **Consensus Processing:** Validators reach consensus on agent output and action extraction
3. **Action Parsing:** Extract executable actions from consensus-approved agent output  
4. **Action Validation:** Verify action parameters, permissions, and dependencies
5. **FSA State Management:** Track action progress through deterministic state machine
6. **TSS Coordination:** Generate required signatures through existing TSS infrastructure
7. **Transaction Submission:** Submit signed transactions to target blockchains
8. **Result Monitoring:** Monitor transaction outcomes and update action states
9. **Feedback Integration:** Transaction results can trigger new agent execution cycles

---

## **3. Technical Specifications**

### **3.1 Integration Points**

#### **UOMI Engine Integration**
The Action Elaboration System integrates with existing UOMI Engine components:

- **Agent Output Storage:** Read agent results from existing storage mechanisms
- **Consensus Integration:** Action parsing operations included in consensus process
- **Event System:** Leverage existing event emission for action state changes
- **Access Control:** Utilize existing permission systems for action authorization

#### **TSS Pallet Integration**
Direct integration with the existing TSS pallet for secure transaction signing:

- **Signature Requests:** Submit transaction data for distributed signature generation
- **Key Management:** Leverage existing key rotation and threshold management
- **Authority Verification:** Ensure actions are authorized under appropriate agent identities
- **Multi-Chain Support:** Support signature generation for various target blockchains

### **3.2 Data Structures**

#### **Action Definition**
```rust
pub struct Action {
    pub id: ActionId,
    pub agent_id: AgentId,
    pub action_type: ActionType,
    pub parameters: ActionParameters,
    pub dependencies: Vec<ActionId>,
    pub trigger_policy: TriggerPolicy,
    pub state: ActionState,
    pub metadata: ActionMetadata,
}

pub enum ActionType {
    TokenTransfer(TransferParams),
    ContractCall(CallParams),
    AgentInvocation(InvocationParams),
    DataStorage(StorageParams),
    Custom(Vec<u8>),
}
```

#### **State Management**
```rust
pub enum ActionState {
    Parsed,                  // Action extracted from agent output
    Validated,               // Parameters and permissions verified
    Scheduled,               // Waiting for trigger condition
    Triggered,               // Trigger condition met, ready for execution
    RequestingSignature,     // TSS signature request initiated
    AwaitingSignature,       // Waiting for TSS signature generation
    SignatureReady,          // TSS signature completed and retrieved
    SubmittingTransaction,   // Atomic transaction submission in progress
    TransactionSubmitted,    // Transaction successfully submitted to blockchain
    Executing,               // Transaction being processed by target blockchain
    Completed,               // Successful execution confirmed
    Failed(FailureReason),   // Execution failed with specific reason
    Expired,                 // Timeout reached without successful execution
}
```

### **3.3 Security Framework**

#### **Authorization Model**
- **Agent Identity:** Each action tied to specific agent identity
- **Permission Verification:** Actions validated against agent capabilities
- **Resource Limits:** Bounded execution to prevent resource exhaustion
- **Audit Trails:** Complete logging of all action attempts and results

#### **Attack Vector Mitigation**
- **Input Validation:** Strict parsing and validation of agent outputs
- **State Consistency:** FSA prevents invalid state transitions
- **Transaction Security:** TSS integration ensures signature security
- **Rate Limiting:** Prevent excessive action generation from single agents

### **3.4 Action Trigger Timing Policies**

#### **Trigger Policy Types**

##### **Immediate Execution**
```rust
TriggerPolicy::Immediate
```
- **Execution:** Action executes as soon as all dependencies are satisfied
- **Use Case:** Time-sensitive operations like arbitrage or emergency responses
- **Latency:** Minimal delay between action readiness and execution
- **Resource Impact:** Immediate TSS signature generation required

##### **Block-Scheduled Execution**
```rust
TriggerPolicy::AtBlock(block_number)
```
- **Execution:** Action executes at a specific future block number
- **Use Case:** Coordinated actions, scheduled operations, planned transactions
- **Scheduling:** Deterministic execution timing across all validators
- **Advantages:** Predictable execution time, allows for coordination

##### **Delay-Based Execution**
```rust
TriggerPolicy::DelayFromRequest { blocks: u64 }
TriggerPolicy::DelayFromOutput { blocks: u64 }
```
- **DelayFromRequest:** Execute N blocks after original agent request submission
- **DelayFromOutput:** Execute N blocks after agent output consensus
- **Use Case:** Cooling-off periods, delayed settlements, staged deployments
- **Benefits:** Provides time for review, reduces frontrunning risks

##### **Condition-Based Execution**
```rust
TriggerPolicy::OnCondition {
    condition: ExecutionCondition,
    timeout_blocks: Option<u64>,
}
```
- **Execution:** Action executes when specified on-chain condition becomes true
- **Conditions:** Block number, price thresholds, contract state changes
- **Timeout:** Optional fallback execution after maximum wait period
- **Monitoring:** Continuous evaluation of trigger conditions

### **3.5 TSS-Based Transaction Signing Specification**

#### **Overview**
All blockchain-directed transactions within the Action Elaboration System must be cryptographically signed using the existing TSS (Threshold Signature Scheme) pallet. This ensures secure, distributed signature generation while preventing double execution and maintaining transaction atomicity.

#### **TSS Integration Requirements**

##### **Mandatory Signature Generation**
- **Universal Coverage:** Every blockchain transaction action must generate a TSS signature
- **No Exceptions:** Direct transaction submission without TSS signing is prohibited
- **Multi-Chain Support:** TSS signatures required for all target blockchains (Ethereum, Substrate-based, etc.)
- **Action Types:** Applies to all transaction-type actions regardless of complexity or value

##### **TSS Pallet API Utilization**
The system leverages the existing TSS pallet through the following workflow:

```rust
// Core TSS Integration Points
pub trait TSSTransactionSigner<T: Config> {
    // Request signature generation from TSS pallet
    fn request_signature(
        action_id: ActionId,
        transaction_data: Vec<u8>,
        target_chain: ChainId,
    ) -> Result<SignatureRequestId, TSSError>;
    
    // Check signature readiness status
    fn check_signature_status(
        request_id: SignatureRequestId,
    ) -> SignatureStatus;
    
    // Retrieve completed signature
    fn get_signature(
        request_id: SignatureRequestId,
    ) -> Result<TSSSignature, TSSError>;
    
    // Submit signed transaction with atomicity guarantees
    fn submit_signed_transaction(
        action_id: ActionId,
        signed_transaction: SignedTransaction,
    ) -> DispatchResult;
}
```

##### **Signature Generation Workflow**

**Step 1: Pre-Signature Preparation**
```
Action Triggered → Transaction Data Serialization → TSS Signature Request
```
- Transaction data formatted according to target chain specifications
- Unique action_id included to prevent signature reuse
- TSS pallet API called with `request_signature()`

**Step 2: Signature Generation Phase**
```
TSS Request → Distributed Key Generation → Threshold Signature → Signature Ready
```
- TSS pallet coordinates signature generation across validator nodes
- Threshold requirements met according to existing TSS configuration
- Signature cryptographically bound to specific transaction data

**Step 3: Atomic Transaction Submission**
```
Signature Ready → Transaction Assembly → Blockchain Submission → Execution Confirmation
```
- Signed transaction assembled with TSS-generated signature
- Single atomic submission to prevent double execution
- Transaction result monitored for success/failure

#### **Double Execution Prevention**

##### **Action-Level Protection**
- **Unique Action IDs:** Each action receives cryptographically unique identifier
- **State Tracking:** FSA engine tracks signature request and submission states
- **Idempotency Guarantees:** Multiple signature requests for same action return identical results

##### **Database-Level Protection**
```rust
// Storage schema for signature tracking
#[pallet::storage]
pub type SignatureRequests<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    ActionId,
    SignatureRequestState,
    OptionQuery
>;

#[pallet::storage]
pub type SubmittedTransactions<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    ActionId,
    TransactionSubmissionRecord,
    OptionQuery
>;
```

##### **Blockchain-Level Protection**
- **Nonce Management:** Proper transaction nonce handling per target chain
- **Transaction Hash Tracking:** Monitor for duplicate transaction submissions
- **Reorg Handling:** Account for blockchain reorganizations and transaction status changes

#### **Error Handling and Recovery**

##### **Signature Generation Failures**
- **TSS Unavailability:** Retry mechanism with exponential backoff
- **Threshold Not Met:** Graceful failure with clear error reporting
- **Timeout Handling:** Configurable timeouts for signature generation
- **Validator Coordination Issues:** Fallback mechanisms and manual intervention options

##### **Transaction Submission Failures**
- **Network Congestion:** Retry with adjusted gas fees
- **Invalid Transactions:** Proper error propagation and action failure handling
- **Chain-Specific Errors:** Target chain error interpretation and handling
- **Partial Failures:** Rollback mechanisms for multi-action transactions

#### **Security Considerations**

##### **Signature Security**
- **Key Isolation:** TSS private key shares never exposed to action system
- **Signature Binding:** Each signature cryptographically bound to specific action and transaction
- **Replay Protection:** Signatures cannot be reused across different actions or transactions
- **Audit Trail:** Complete logging of all signature requests and generations

##### **Transaction Security**
- **Authorization Checks:** Verify action authority before signature request
- **Resource Limits:** Bounded signature requests per time period
- **Validation:** Pre-signature validation of transaction data and parameters
- **Monitoring:** Real-time detection of unusual signature patterns

#### **Performance Optimization**

##### **Signature Request Batching**
- **Batch Processing:** Group multiple signature requests when possible
- **Priority Queuing:** High-priority actions processed first
- **Resource Allocation:** Balanced TSS resource utilization
- **Throughput Management:** Prevent TSS system overload

##### **Caching Strategies**
- **Signature Caching:** Cache signatures for identical transaction patterns
- **Validation Caching:** Cache transaction validation results
- **Chain State Caching:** Cache target chain state for faster processing
- **Metadata Caching:** Cache chain-specific formatting requirements

#### **Integration with Action States**

The TSS signing process introduces additional FSA states:

```rust
pub enum ActionState {
    // ...existing states...
    RequestingSignature,     // TSS signature request initiated
    AwaitingSignature,       // Waiting for TSS signature generation
    SignatureReady,          // TSS signature completed and retrieved
    SubmittingTransaction,   // Atomic transaction submission in progress
    TransactionSubmitted,    // Transaction successfully submitted to blockchain
    // ...existing states...
}
```

##### **State Transition Rules**
- `Triggered` → `RequestingSignature`: Action begins TSS integration
- `RequestingSignature` → `AwaitingSignature`: TSS request successfully submitted
- `AwaitingSignature` → `SignatureReady`: TSS signature generation completed
- `SignatureReady` → `SubmittingTransaction`: Begin atomic transaction submission
- `SubmittingTransaction` → `TransactionSubmitted`: Transaction successfully submitted
- Any TSS state → `Failed`: Error handling with appropriate failure reasons

#### **Monitoring and Observability**

##### **TSS-Specific Metrics**
- **Signature Request Rate:** Track TSS system load
- **Signature Generation Latency:** Monitor TSS performance
- **Signature Success Rate:** Track TSS reliability
- **Transaction Submission Success Rate:** Monitor blockchain integration health

##### **Alert Conditions**
- **TSS System Unavailability:** Critical alert for signature system failures
- **High Signature Latency:** Performance degradation warnings
- **Signature Failures:** Security-relevant failure notifications
- **Double Execution Detection:** Critical security alert

#### **Chain-Specific Implementation Notes**

##### **Ethereum Integration**
- **Transaction Format:** EIP-155 compliant transaction serialization
- **Gas Management:** Dynamic gas price estimation and adjustment
- **Nonce Management:** Proper account nonce tracking and synchronization
- **MEV Protection:** Consider MEV-resistant submission strategies

##### **Substrate Integration**
- **Extrinsic Format:** Substrate-specific extrinsic construction
- **Runtime Versioning:** Handle runtime upgrades and version compatibility
- **Tip Management:** Appropriate tip calculation for priority
- **Multi-Signature Support:** Integration with Substrate's multi-sig capabilities

#### **Storage Schema**

```rust
// Action management storage
#[pallet::storage]
pub type Actions<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    ActionId,
    Action<T>,
    OptionQuery
>;

#[pallet::storage]
pub type ActionSets<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    ActionSetId,
    ActionSet<T>,
    OptionQuery
>;

// TSS signature tracking
#[pallet::storage]
pub type SignatureRequests<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    ActionId,
    SignatureRequestState,
    OptionQuery
>;

#[pallet::storage]
pub type SubmittedTransactions<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    ActionId,
    TransactionSubmissionRecord,
    OptionQuery
>;

// Trigger scheduling
#[pallet::storage]
pub type ScheduledActions<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    BlockNumber,
    Vec<ActionId>,
    ValueQuery
>;
```

#### **Event Definitions**

```rust
#[pallet::event]
#[pallet::generate_deposit(pub(super) fn deposit_event)]
pub enum Event<T: Config> {
    /// Action set parsed from agent output
    ActionSetParsed {
        agent_id: AgentId,
        action_set_id: ActionSetId,
        action_count: u32,
    },
    
    /// Action state transition
    ActionStateChanged {
        action_id: ActionId,
        old_state: ActionState,
        new_state: ActionState,
    },
    
    /// TSS signature requested
    SignatureRequested {
        action_id: ActionId,
        signature_request_id: SignatureRequestId,
    },
    
    /// TSS signature completed
    SignatureCompleted {
        action_id: ActionId,
        signature_request_id: SignatureRequestId,
    },
    
    /// Transaction submitted to blockchain
    TransactionSubmitted {
        action_id: ActionId,
        transaction_hash: H256,
        target_chain: ChainId,
    },
    
    /// Action execution completed
    ActionCompleted {
        action_id: ActionId,
        result: ActionResult,
    },
    
    /// Action execution failed
    ActionFailed {
        action_id: ActionId,
        failure_reason: FailureReason,
    },
}
```

### **3.6 Post-Consensus Signing Implications**

#### **Consensus Integration Requirements**

##### **Action Processing as Consensus Operation**
- **Deterministic Parsing:** Action extraction must produce identical results across validators
- **Consensus Critical States:** Action state transitions included in consensus process
- **Validator Agreement:** All validators must agree on action execution schedules
- **Block Integration:** Action trigger evaluation integrated into block production

##### **State Management Complexity**
- **Multi-Phase Execution:** Actions progress through consensus and signing phases
- **Cross-Block Dependencies:** Action state may span multiple blocks
- **Rollback Scenarios:** Handle consensus failures during action processing
- **Recovery Mechanisms:** Restart action processing after network interruptions

#### **TSS Coordination Requirements**

##### **Synchronized Signature Generation**
- **Coordinator Selection:** Determine which validator initiates TSS signature requests
- **Timing Coordination:** Ensure signature generation happens at correct block
- **Signature Distribution:** Propagate completed signatures across validator network
- **Fallback Mechanisms:** Handle TSS failures and retry logic

##### **Transaction Submission Coordination**
- **Single Submission:** Prevent multiple validators from submitting same transaction
- **Submission Responsibility:** Designate specific validator for transaction submission
- **Monitoring Coordination:** Coordinate transaction status monitoring across validators
- **Result Propagation:** Ensure transaction results reach all validators consistently

#### **Performance Implications**

##### **Execution Latency**
- **Additional Consensus Rounds:** Action processing adds consensus overhead
- **Signature Generation Delay:** TSS signature generation adds execution latency
- **Multi-Block Execution:** Actions may span multiple blocks for completion
- **Network Synchronization:** Coordination overhead for distributed execution

##### **Resource Overhead**
- **Consensus Load:** Additional consensus processing for action management
- **Storage Requirements:** Persistent action state storage across validators
- **Network Bandwidth:** TSS coordination and result distribution overhead
- **Computational Cost:** Action parsing and state management processing

#### **Implementation Complexity**
- **State Management:** More complex FSA with scheduled waiting states
- **Synchronization:** Coordination between consensus and signing systems
- **Trigger Scheduling:** Block-based scheduling system for delayed actions
- **Monitoring:** Enhanced observability for multi-phase execution
- **Testing:** Extended test scenarios for consensus/signing interactions
- **Time Management:** Accurate block-based timing calculations across different trigger policies

---

## **4. Risk Assessment**

### **Technical Risks**

#### **High Priority**
- **TSS System Dependency:** Critical dependency on TSS pallet availability and performance
- **Consensus Integration Complexity:** Risk of consensus failures during action processing
- **Multi-Chain Coordination:** Complexity of managing actions across different blockchain networks
- **State Synchronization:** Risk of validator state divergence during action execution

#### **Medium Priority**
- **Performance Impact:** Potential latency increases due to post-consensus signing
- **Resource Consumption:** Additional storage and computation requirements
- **Error Recovery:** Complexity of handling partial failures and rollbacks
- **Upgrade Compatibility:** Risk of breaking changes during system upgrades

#### **Low Priority**
- **Parser Extensibility:** Risk of parser framework limitations
- **Monitoring Overhead:** Performance impact of comprehensive logging and metrics
- **Documentation Maintenance:** Risk of documentation becoming outdated

### **Security Risks**

#### **High Priority**
- **Action Authorization:** Risk of unauthorized actions if permission checks fail
- **Signature Security:** Risk of signature compromise or misuse
- **Double Execution:** Risk of duplicate transaction submissions
- **Input Validation:** Risk of malicious or malformed agent outputs

#### **Medium Priority**
- **Resource Exhaustion:** Risk of DoS through excessive action generation
- **Private Key Exposure:** Risk of TSS key compromise
- **Network Attacks:** Risk of coordinated attacks on TSS infrastructure
- **Audit Trail Integrity:** Risk of log tampering or incomplete records

### **Operational Risks**

#### **High Priority**
- **System Availability:** Risk of action execution system downtime
- **TSS Coordination Failures:** Risk of threshold signature failures
- **Cross-Chain Failures:** Risk of target blockchain unavailability
- **Validator Coordination:** Risk of validator disagreement on action execution

#### **Medium Priority**
- **Monitoring Gaps:** Risk of undetected system failures
- **Recovery Procedures:** Risk of inadequate incident response
- **Performance Degradation:** Risk of gradual system slowdown
- **Configuration Errors:** Risk of incorrect system configuration

### **Mitigation Strategies**

#### **Technical Mitigations**
- **Redundancy:** Multiple fallback mechanisms for critical components
- **Testing:** Comprehensive test suites for all failure scenarios
- **Monitoring:** Real-time alerting for system health and performance
- **Documentation:** Detailed operational procedures and troubleshooting guides

#### **Security Mitigations**
- **Multi-Layer Validation:** Multiple validation stages for action authorization
- **Rate Limiting:** Bounded action generation and execution rates
- **Audit Logging:** Comprehensive logging of all system activities
- **Regular Security Reviews:** Periodic security assessments and penetration testing

#### **Operational Mitigations**
- **Staged Deployment:** Gradual rollout with careful monitoring
- **Rollback Procedures:** Quick rollback capabilities for critical issues
- **Staff Training:** Comprehensive training for operations staff
- **Incident Response:** Well-defined incident response procedures

---

## **5. Appendices**

### **Appendix A: Action Set JSON Schema**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "title": "UOMI Action Set Schema",
  "properties": {
    "action_set_id": {
      "type": "string",
      "description": "Unique identifier for the action set"
    },
    "agent_id": {
      "type": "string", 
      "description": "Identifier of the agent that generated this action set"
    },
    "actions": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": {
            "type": "string",
            "description": "Unique action identifier within the set"
          },
          "type": {
            "type": "string",
            "enum": ["transaction", "contract_call", "agent_invocation", "data_storage"],
            "description": "Type of action to execute"
          },
          "trigger_policy": {
            "oneOf": [
              {"type": "string", "enum": ["immediate"]},
              {"type": "object", "properties": {"at_block": {"type": "integer"}}},
              {"type": "object", "properties": {"delay_from_request": {"type": "integer"}}},
              {"type": "object", "properties": {"delay_from_output": {"type": "integer"}}}
            ],
            "description": "When this action should be triggered"
          },
          "dependencies": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Action IDs that must complete before this action"
          },
          "parameters": {
            "type": "object",
            "description": "Action-specific parameters"
          }
        },
        "required": ["id", "type", "trigger_policy", "parameters"]
      }
    }
  },
  "required": ["action_set_id", "agent_id", "actions"]
}
```

### **Appendix B: TSS Pallet Interface Reference**

```rust
// Trait definition for TSS pallet integration
pub trait TSSPalletInterface<T: Config> {
    // Core signature request functionality
    fn request_signature(
        origin: OriginFor<T>,
        transaction_data: Vec<u8>,
        target_chain: ChainId,
        metadata: SignatureMetadata,
    ) -> DispatchResult;
    
    // Signature status and retrieval
    fn get_signature_status(
        request_id: SignatureRequestId,
    ) -> Result<SignatureStatus, TSSError>;
    
    fn retrieve_signature(
        request_id: SignatureRequestId,
    ) -> Result<TSSSignature, TSSError>;
    
    // Key management
    fn get_public_key(chain_id: ChainId) -> Result<PublicKey, TSSError>;
    fn rotate_keys() -> DispatchResult;
    
    // Threshold management
    fn update_threshold(new_threshold: u32) -> DispatchResult;
    fn get_current_threshold() -> u32;
}
```

### **Appendix C: Error Codes and Handling**

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum ActionError {
    // Parser errors
    InvalidFormat,
    MalformedJSON,
    UnsupportedActionType,
    MissingRequiredField,
    
    // Validation errors
    UnauthorizedAgent,
    InsufficientPermissions,
    InvalidParameters,
    ResourceLimitExceeded,
    
    // State transition errors
    InvalidStateTransition,
    DependencyNotSatisfied,
    TriggerConditionNotMet,
    TimeoutExpired,
    
    // TSS errors
    TSSUnavailable,
    SignatureRequestFailed,
    SignatureGenerationFailed,
    ThresholdNotMet,
    
    // Transaction errors
    TransactionSubmissionFailed,
    TransactionReverted,
    InsufficientGas,
    NetworkError,
    
    // System errors
    StorageError,
    ConsensusError,
    NetworkPartition,
    InternalError,
}
```

---

This TSS integration specification ensures that all blockchain transactions generated by the Action Elaboration System maintain the highest security standards while preventing double execution and ensuring atomic transaction processing.
