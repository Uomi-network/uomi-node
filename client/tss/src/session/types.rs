use codec::{Decode, Encode};
use uomi_runtime::{pallet_tss::types::SessionId, RuntimeEvent};

use crate::types::{TssMessage, TSSPeerId};

/// Type alias for TSS Participant 
pub type TSSParticipant = [u8; 32];

/// Session data structure: (t, n, coordinator, message)
pub type SessionData = (u16, u16, Vec<u8>, Vec<u8>);


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
        SessionId,
        u16,
        u16,
        Vec<TSSParticipant>,
        TSSParticipant,
        Vec<u8>,
    ), // Session info from runtime is now available
    ValidatorIdAssigned(TSSParticipant, u32)
}