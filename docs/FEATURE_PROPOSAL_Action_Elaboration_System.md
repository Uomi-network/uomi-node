# **UOMI Engine Feature Proposal: On-Chain Action Elaboration System**

**Document Version:** 1.0  
**Date:** June 23, 2025  
**Author:** Development Team  
**Status:** Draft  

---

## **Executive Summary**

This proposal introduces an **On-Chain Action Elaboration System** for the UOMI Engine that transforms AI agent outputs from passive data into executable on-chain actions. The system interprets structured agent responses as actionable instructions, manages their execution through a Finite State Automata framework, and integrates with the existing agent wallet system for secure transaction signing.

**Key Benefits:**
- Enables AI agents to autonomously execute blockchain transactions
- Creates feedback loops where transaction results can trigger new agent invocations
- Maintains security through existing validator consensus and agent wallet infrastructure
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

#### **Agent Wallet Integration Layer**
- **Purpose:** Leverage existing agent wallet/signature system for transaction execution
- **Current State:** Each agent has dedicated address/wallet/public key with signing capabilities
- **Integration:** Direct utilization of existing blockchain signature request system
- **Critical Decision:** Signature timing - before consensus (immediate) vs after consensus (delayed)

### **2.2 Critical Design Decision: Signature Timing**

Since each agent already has its own wallet and signing capabilities, we must decide when signatures are generated:

#### **Option A: Pre-Consensus Signing**
- **Process:** Agent generates signature immediately upon action creation
- **Advantages:**
  - Faster execution once consensus is reached
  - No delay between consensus and transaction execution
  - Simpler state management (signature ready when needed)
- **Disadvantages:**
  - Potential for signed transactions that never execute (if consensus fails)
  - Security risk: signatures exist for actions that may be rejected
  - Resource waste: signing operations for potentially invalid actions

#### **Option B: Post-Consensus Signing**
- **Process:** Agent generates signature only after validator consensus confirms action validity
- **Advantages:**
  - Higher security: only validated actions get signed
  - No wasted signing operations on rejected actions
  - Cleaner separation between validation and execution
- **Disadvantages:**
  - Added latency: signature generation delays execution
  - More complex state management (validation → signing → execution)
  - Potential signing failures after consensus (though rare)

#### **Recommended Approach: Post-Consensus Signing**
Given the security-critical nature of transaction signing, we recommend **Option B** with the following optimizations:
- Fast consensus mechanisms to minimize delay
- Signature caching for repeated similar transactions
- Parallel signature generation where possible
- Graceful handling of post-consensus signature failures

### **2.3 Data Flow Design**

```
Agent Output → Action Parser → FSA Engine → Consensus → Agent Signing → Execution → Callback Processing
     ↑                                                                                    ↓
     └── New Agent Invocation ← Callback Data Processing ← Transaction Results ←
```

**Key Flow Steps:**
1. Agent generates output with embedded action set definitions
2. Parser extracts and validates action instructions from the action set
3. FSA engine manages execution state and dependencies for each action
4. **Validator consensus validates action set (OPoC)**
5. **Agent wallet signs approved transactions**
6. External transactions executed on target chains
7. Results processed and fed back to trigger new agent invocations

---

## **3. Technical Specifications**

### **3.1 Integration Points**

#### **Existing UOMI Engine Integration**
- **Minimal Disruption:** Current `run_request` → `offchain_worker` flow unchanged
- **Output Enhancement:** Additional processing layer for action-enabled agent outputs
- **Storage Extension:** New storage items for action set state management
- **Event System:** New events for action lifecycle tracking

#### **Agent Wallet Integration**
- **Existing Infrastructure:** Each agent has dedicated wallet address and signing capabilities
- **Direct Integration:** Utilize existing blockchain signature request system
- **Post-Consensus Signing:** Signatures generated only after validator consensus
- **Multi-Chain Support:** Leverage existing agent wallet capabilities across chains

#### **External Chain Integration**
- **Bridge Architecture:** Pluggable interfaces for different blockchain targets
- **Transaction Formatting:** Chain-specific transaction construction
- **Status Monitoring:** Cross-chain transaction status tracking
- **Result Processing:** Parse chain-specific transaction results and logs

### **3.2 Data Structures**

#### **Action Set Definition Schema**
```
ActionSet: Collection of related actions from a single agent output
ActionType: TransactionRequest | DataStorage | ExternalAPI | AgentInvocation
TriggerPolicy: Immediate | AtBlock(block_number) | DelayFromRequest(blocks) | DelayFromOutput(blocks)
TriggerConditions: Additional validation rules and prerequisites
ExecutionParameters: Action-specific configuration and data
ConsequenceHandlers: Post-execution processing instructions
Priority: Execution ordering within action sets
ConsensusRequired: Whether action requires validator agreement
Dependencies: Inter-action dependencies within the set
```

#### **State Management**
```
ActionState: Pending | ScheduledWaiting | Triggered | AwaitingConsensus | ConsensusReached | WaitingForSignature | Signed | Executing | Completed | Failed | Cancelled
ActionSetState: Processing | PartiallyExecuted | Completed | Failed
ExecutionContext: Runtime data and intermediate results
DependencyGraph: Relationships between actions in the set
TimeoutConfiguration: Block-based execution deadlines
ConsensusResult: Validator agreement outcome and details
TriggerSchedule: When the action should be triggered based on policy
```

### **3.3 Security Framework**

#### **Authorization Model**
- **Request-Based Permissions:** Actions inherit permissions from originating request
- **NFT-Based Access Control:** Transaction actions limited to associated NFT wallets
- **Validator Consensus:** Action execution requires validator agreement via OPoC
- **Resource Limits:** Bounded action counts, data sizes, and execution times

#### **Validation Layers**
- **Parse-Time Validation:** Malformed action definitions rejected immediately
- **Pre-Execution Validation:** Runtime checks before each state transition
- **Consensus Validation:** Validator agreement on action set validity
- **Post-Execution Validation:** Verification of action results and side effects

### **3.4 Action Trigger Timing Policies**

To provide agents with maximum flexibility in action execution timing, the system supports multiple trigger policies:

#### **Policy 1: Immediate Execution**
- **Trigger:** `"trigger_policy": "immediate"`
- **Behavior:** Action triggers as soon as all dependencies are satisfied
- **Use Cases:** Time-sensitive transactions, immediate responses to events
- **Implementation:** Direct transition from `Pending` to `Triggered` state

#### **Policy 2: Specific Block Execution**
- **Trigger:** `"trigger_policy": {"at_block": 12345678}`
- **Behavior:** Action waits until the specified block number is reached
- **Use Cases:** Scheduled governance votes, time-locked transactions, coordinated multi-agent actions
- **Implementation:** Action remains in `ScheduledWaiting` until target block

#### **Policy 3: Delay from Request Start**
- **Trigger:** `"trigger_policy": {"delay_from_request": 100}` (blocks)
- **Behavior:** Action triggers after specified blocks since the original request
- **Use Cases:** Cool-down periods, staged execution workflows, risk management delays
- **Implementation:** Calculate trigger block as `request_block + delay_blocks`

#### **Policy 4: Delay from Output**
- **Trigger:** `"trigger_policy": {"delay_from_output": 50}` (blocks)
- **Behavior:** Action triggers after specified blocks since model output completion
- **Use Cases:** Confirmation periods, market impact delays, validation windows
- **Implementation:** Calculate trigger block as `output_completion_block + delay_blocks`

#### **Future Policy Extensions**
The framework is designed to support additional trigger policies:
- **Conditional Triggers:** Based on external events or chain state
- **Recurring Triggers:** Periodic execution patterns
- **Market-Based Triggers:** Price thresholds, volume conditions
- **Cross-Chain Triggers:** Events from other blockchain networks

#### **Trigger Policy JSON Examples**
```json
{
  "actions": [
    {
      "id": "action_1",
      "type": "transaction",
      "trigger_policy": "immediate",
      "target_address": "0x...",
      "value": "1000000000000000000"
    },
    {
      "id": "action_2", 
      "type": "transaction",
      "trigger_policy": {"at_block": 12345678},
      "target_address": "0x...",
      "value": "2000000000000000000"
    },
    {
      "id": "action_3",
      "type": "transaction", 
      "trigger_policy": {"delay_from_request": 100},
      "target_address": "0x...",
      "value": "500000000000000000"
    },
    {
      "id": "action_4",
      "type": "transaction",
      "trigger_policy": {"delay_from_output": 50},
      "target_address": "0x...", 
      "value": "750000000000000000"
    }
  ]
}
```

### **3.5 Post-Consensus Signing Implications**

#### **Security Benefits**
- **Validation First:** Only consensus-approved actions receive signatures
- **No Orphaned Signatures:** Eliminates signed transactions for rejected actions
- **Audit Trail:** Clear separation between validation and execution phases
- **Attack Prevention:** Malicious actions stopped before signature generation

#### **Performance Considerations**
- **Latency Impact:** Additional ~1-3 seconds for consensus before signing
- **Optimization Strategies:**
  - Fast consensus mechanisms for time-critical actions
  - Predictive signature preparation for likely-approved actions
  - Parallel processing where dependencies allow
  - Signature caching for repeated transaction patterns

#### **Error Handling**
- **Consensus Failure:** Actions rejected before signature attempt
- **Signature Failure:** Post-consensus signature errors require retry mechanism
- **Timeout Management:** Separate timeouts for consensus and signing phases
- **Recovery Options:** Automatic retry, manual intervention, or graceful failure

#### **Implementation Complexity**
- **State Management:** More complex FSA with scheduled waiting states
- **Synchronization:** Coordination between consensus and signing systems
- **Trigger Scheduling:** Block-based scheduling system for delayed actions
- **Monitoring:** Enhanced observability for multi-phase execution
- **Testing:** Extended test scenarios for consensus/signing interactions
- **Time Management:** Accurate block-based timing calculations across different trigger policies

---

## **4. Benefits and Impact**

### **4.1 Technical Benefits**
- **Autonomous Agents:** Enable self-executing AI agents with real blockchain capabilities
- **Feedback Loops:** Create dynamic systems where actions inform future decisions
- **Action Sets:** Support complex multi-action workflows from single agent outputs
- **Extensibility:** Framework supports future action types beyond transactions
- **Security:** Leverages existing battle-tested agent wallet and consensus mechanisms

### **4.2 Business Benefits**
- **Market Expansion:** Opens new use cases in DeFi, governance, and cross-chain operations
- **Competitive Advantage:** First-mover advantage in autonomous AI agent infrastructure
- **Developer Adoption:** Simplified development of complex agent behaviors
- **Revenue Opportunities:** New transaction fees and service offerings

### **4.3 Ecosystem Benefits**
- **Innovation Catalyst:** Enables new classes of decentralized applications
- **Interoperability:** Cross-chain capabilities expand UOMI's reach
- **Community Growth:** Attracts developers building autonomous systems
- **Network Effects:** More sophisticated agents increase platform value

---

## **5. Risk Assessment**

### **5.1 Technical Risks**
| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| TSS Integration Complexity | High | Medium | Incremental integration, extensive testing |
| State Machine Bugs | High | Low | Formal verification, comprehensive test coverage |
| External Chain Dependencies | Medium | Medium | Multi-chain support, fallback mechanisms |
| Performance Bottlenecks | Medium | Low | Profiling, optimization, scalable architecture |

### **5.2 Security Risks**
| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Malicious Action Injection | High | Low | Multi-layer validation, consensus requirements |
| Signature Key Compromise | High | Very Low | Existing TSS security model |
| Infinite Callback Loops | Medium | Medium | Cycle detection, resource limits |
| Transaction Front-Running | Low | Medium | MEV protection, timing randomization |

### **5.3 Operational Risks**
| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Development Timeline Delays | Medium | Medium | Phased approach, clear milestones |
| Integration Breaking Changes | Medium | Low | Backward compatibility, migration tools |
| Validator Adoption Resistance | Low | Low | Community engagement, clear benefits |

---

## **6. Security Considerations**

### **6.1 Attack Vectors and Mitigations**

#### **Action Injection Attacks**
- **Threat:** Malicious actors inject harmful actions into agent outputs
- **Mitigation:** Multi-layer validation, signature verification, consensus requirements
- **Detection:** Pattern analysis, anomaly detection, validator voting

#### **State Machine Manipulation**
- **Threat:** Attempts to force invalid state transitions
- **Mitigation:** Formal verification of state machine, immutable transition rules
- **Detection:** State consistency checks, audit logging

#### **TSS Key Compromise**
- **Threat:** Compromise of threshold signature keys
- **Mitigation:** Existing TSS security model, key rotation, multi-layer authorization
- **Detection:** Signature pattern analysis, validator consensus monitoring

### **6.2 Security Architecture**

#### **Defense in Depth**
1. **Input Validation:** Strict parsing and format validation
2. **Authorization Checks:** NFT ownership and permission verification
3. **Consensus Requirements:** Validator agreement on action validity
4. **Execution Sandboxing:** Isolated action execution environments
5. **Result Verification:** Post-execution validation and audit

#### **Monitoring and Alerting**
- **Real-time Monitoring:** Continuous surveillance of action execution
- **Anomaly Detection:** Machine learning-based pattern recognition
- **Incident Response:** Automated containment and manual escalation
- **Forensic Analysis:** Complete audit trail for security investigations

---

## **7. Performance and Scalability**

### **7.1 Performance Requirements**
- **Latency:** <5 seconds for action parsing and validation
- **Throughput:** 1000+ actions per minute system-wide
- **Concurrency:** 100+ parallel action executions
- **Availability:** 99.9% uptime with graceful degradation

### **7.2 Scalability Strategy**
- **Horizontal Scaling:** Multiple action processor instances
- **Load Balancing:** Intelligent request distribution
- **Caching:** Frequently accessed data caching
- **Resource Pooling:** Shared resources across action executions

### **7.3 Optimization Techniques**
- **Batch Processing:** Group related actions for efficiency
- **Lazy Evaluation:** Process actions only when triggered
- **Parallel Execution:** Independent actions run concurrently
- **Resource Reuse:** Minimize allocation and deallocation overhead

---

## **8. Testing Strategy**

### **8.1 Testing Phases**

#### **Unit Testing**
- **Component Testing:** Individual module functionality
- **State Machine Testing:** All state transitions and edge cases
- **Parser Testing:** Various input formats and malformed data
- **Integration Testing:** Interface compatibility verification

#### **Integration Testing**
- **End-to-End Flows:** Complete action lifecycle testing
- **TSS Integration:** Signature request and callback verification
- **Chain Integration:** Multi-chain transaction testing
- **Performance Testing:** Load and stress testing

#### **Security Testing**
- **Penetration Testing:** Simulated attack scenarios
- **Fuzzing:** Random input generation for robustness
- **Audit:** External security review and verification
- **Formal Verification:** Mathematical proof of critical properties

### **8.2 Test Environments**
- **Unit Test Environment:** Local development testing
- **Integration Test Environment:** Multi-node testnet
- **Staging Environment:** Production-like testing
- **Security Test Environment:** Isolated security testing

---

## **9. Documentation and Training**

### **9.1 Technical Documentation**
- **Architecture Guide:** System design and component interaction
- **API Reference:** Detailed interface documentation
- **Integration Guide:** Step-by-step integration instructions
- **Security Guide:** Best practices and security considerations

### **9.2 Developer Resources**
- **Quick Start Guide:** Getting started with action-enabled agents
- **Example Applications:** Reference implementations and use cases
- **Troubleshooting Guide:** Common issues and solutions
- **Community Forum:** Developer support and discussion

### **9.3 Training Materials**
- **Video Tutorials:** Visual learning for key concepts
- **Interactive Examples:** Hands-on learning experiences
- **Workshops:** Live training sessions and Q&A
- **Certification Program:** Structured learning path with validation

---

## **10. Conclusion**

The On-Chain Action Elaboration System represents a fundamental evolution of the UOMI Engine from a passive computation platform to an active autonomous agent infrastructure. By enabling AI agents to execute real blockchain transactions through coordinated action sets and create feedback loops, this feature positions UOMI at the forefront of the autonomous AI agent revolution.

The proposed system leverages existing UOMI infrastructure while adding powerful new capabilities, ensuring both compatibility and innovation. Each agent output can contain multiple coordinated actions, enabling sophisticated multi-step workflows. The phased implementation approach minimizes risk while delivering incremental value, and the extensible architecture provides a foundation for future enhancements.

**Recommendation:** Proceed with implementation to validate the core concept and demonstrate the system's potential, with full commitment to the complete feature roadmap.

---

## **11. Appendices**

### **Appendix A: Code Architecture Examples**

#### **Action Definition Interface**
```rust
pub trait ActionDefinition {
    fn action_type(&self) -> ActionType;
    fn validate(&self) -> Result<(), ValidationError>;
    fn execute(&self, context: &ExecutionContext) -> Result<ActionResult, ExecutionError>;
    fn rollback(&self, context: &ExecutionContext) -> Result<(), RollbackError>;
}
```

#### **FSA Engine Interface**
```rust
pub trait FiniteStateAutomata<T: Config> {
    fn transition_state(
        action_id: &ActionId,
        from_state: ActionState,
        to_state: ActionState,
        context: &[u8],
    ) -> DispatchResult;
    
    fn can_transition(
        action_id: &ActionId,
        from_state: &ActionState,
        to_state: &ActionState,
    ) -> bool;
    
    fn execute_action_step(
        action_id: &ActionId,
        step: u32,
    ) -> DispatchResult;
}
```

### **Appendix B: Storage Schema**

#### **Action-Related Storage Items**
```rust
// Action sets parsed from agent outputs
#[pallet::storage]
pub type ActionSets<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    RequestId,
    ParsedActionSet,
    OptionQuery
>;

// Individual action execution state within sets
#[pallet::storage]
pub type ActionExecutions<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    RequestId,
    Blake2_128Concat,
    ActionId,
    ActionExecution,
    OptionQuery
>;

// Transaction-specific action data
#[pallet::storage]
pub type TransactionRequests<T: Config> = StorageMap<
    _,
    Blake2_128Concat,
    ActionId,
    TransactionRequest,
    OptionQuery
>;

// Scheduled actions waiting for trigger block
#[pallet::storage]
pub type ScheduledActions<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    BlockNumber, // trigger_block
    Blake2_128Concat,
    ActionId,
    TriggerPolicy,
    OptionQuery
>;
```

### **Appendix C: Event Definitions**

#### **Action Lifecycle Events**
```rust
#[pallet::event]
pub enum Event<T: Config> {
    // Action set created from model output
    ActionSetCreated {
        request_id: RequestId,
        action_count: u32,
    },
    
    // Action scheduled for future execution
    ActionScheduled {
        action_id: ActionId,
        trigger_block: BlockNumber,
        trigger_policy: TriggerPolicy,
    },
    
    // Scheduled action triggered
    ActionTriggered {
        action_id: ActionId,
        trigger_block: BlockNumber,
    },
    
    // Action state transition
    ActionStateChanged {
        action_id: ActionId,
        from_state: ActionState,
        to_state: ActionState,
    },
    
    // Transaction action initiated
    TransactionActionInitiated {
        action_id: ActionId,
        target_address: H160,
        value: U256,
    },
    
    // Transaction completed with callback
    TransactionCompleted {
        action_id: ActionId,
        transaction_hash: H256,
        success: bool,
    },
    
    // Callback triggered new agent invocation
    CallbackAgentInvoked {
        original_request_id: RequestId,
        new_request_id: RequestId,
    },
}
```

---

**Document Control:**
- **Review Required:** Technical Lead, Security Team, Product Manager
- **Approval Required:** CTO, Head of Product
- **Next Review Date:** July 15, 2025
- **Distribution:** Engineering Team, Product Team, Executive Team
- **Document Location:** `/docs/FEATURE_PROPOSAL_Action_Elaboration_System.md`
- **Version History:**
  - v1.0 (June 23, 2025): Initial draft
