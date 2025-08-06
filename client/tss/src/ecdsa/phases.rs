use codec::{Decode, Encode};

/// Enum representing different phases of the ECDSA protocol
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ECDSAPhase {
    Key,
    Reshare,
    Sign,
    SignOnline,
}
