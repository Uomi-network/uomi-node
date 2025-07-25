use codec::{Decode, Encode};
use uomi_runtime::{pallet_tss::types::SessionId, RuntimeEvent};

use crate::types::{TssMessage, TSSPeerId};

/// Type alias for TSS Participant 
pub type TSSParticipant = [u8; 32];

/// Session data structure: (t, n, coordinator, message)
pub type SessionData = (u16, u16, Vec<u8>, Vec<u8>);

/// Enum representing the state of a DKG session
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum DKGSessionState {
    Idle,            // Session created, but not started locally
    Round1Initiated, // Round 1 secret package generated and potentially broadcasted
    Round1Completed, // Received enough Round 1 packages to proceed to Round 2
    Round2Initiated, // Round 2 verification and package generation initiated
    Round2Completed, // Received enough Round 2 packages to proceed to Round 3 (or finalize DKG)
    Round3Initiated, // Round 3 initiated (if needed in Frost - check if round 3 is necessary for keygen)
    Round3Completed, // Round 3 completed
    KeyGenerated,    // Final TSS key generated
    Failed,          // Session failed for some reason
}

/// Enum representing the state of a signing session
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum SigningSessionState {
    Idle,               // Session created, but not started locally
    Round1Initiated,    // Round 1 secret package generated and potentially broadcasted
    Round1Completed,    // Received enough Round 1 packages to proceed to Round 2
    Round2Initiated,    // Round 2 verification and package generation initiated
    Round2Completed,    // Received enough Round 2 packages to proceed to Round 3 (or finalize DKG)
    Round3Initiated,    // Round 3 initiated (if needed in Frost - check if round 3 is necessary for keygen)
    Round3Completed,    // Round 3 completed
    SignatureGenerated, // Final Signature key generated
    Failed,             // Session failed for some reason
}

/// Messages sent to the SessionManager
#[derive(Encode, Decode, Debug)]
pub enum SessionManagerMessage {
    NewDKGMessage(SessionId, TssMessage, TSSPeerId), // Message received from gossip before session info
    SessionInfoReady(SessionId),                     // Session info from runtime is now available
    RuntimeEvent(RuntimeEvent),                      // Events from the runtime
}

/// Runtime events related to TSS operations
#[derive(Encode, Decode, Debug)]
pub enum TSSRuntimeEvent {
    DKGSessionInfoReady(SessionId, u16, u16, Vec<TSSParticipant>), // Session info from runtime is now available
    DKGReshareSessionInfoReady(SessionId, u16, u16, Vec<TSSParticipant>, Vec<TSSParticipant>), // Session info from runtime is now available
    SigningSessionInfoReady(
        SessionId,
        u16,
        u16,
        Vec<TSSParticipant>,
        TSSParticipant,
        Vec<u8>,
    ), // Session info from runtime is now available
    ValidatorIdAssigned(TSSParticipant, u32)
}