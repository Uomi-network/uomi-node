use crate::types::SessionId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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

/// Manages the state of DKG sessions.
pub struct DKGStateManager {
    pub dkg_session_states: Arc<Mutex<HashMap<SessionId, DKGSessionState>>>,
}

impl DKGStateManager {
    /// Creates a new DKGStateManager.
    pub fn new(dkg_session_states: Arc<Mutex<HashMap<SessionId, DKGSessionState>>>) -> Self {
        Self { dkg_session_states }
    }

    /// Gets the state of a DKG session.
    pub fn get_state(&self, session_id: &SessionId) -> DKGSessionState {
        let lock = self.dkg_session_states.lock().unwrap();
        lock.get(session_id)
            .copied()
            .unwrap_or(DKGSessionState::Idle)
    }

    /// Sets the state of a DKG session.
    pub fn set_state(&self, session_id: SessionId, state: DKGSessionState) {
        let mut lock = self.dkg_session_states.lock().unwrap();
        lock.insert(session_id, state);
    }
}
