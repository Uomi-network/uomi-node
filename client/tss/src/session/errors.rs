use codec::{Decode, Encode};

/// Error type for session operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Session with this ID already exists
    SessionAlreadyExists,
    /// Session with this ID doesn't exist
    SessionDoesNotExist,
    /// Session is in an invalid state for the requested operation
    InvalidSessionState,
    /// Participant is not allowed in this session
    NotAuthorized,
    /// Message couldn't be deserialized
    DeserializationError,
    /// Session timed out
    SessionTimeout,
    /// Generic error
    GenericError(String),
}

/// Errors that can occur in the SessionManager
#[derive(Encode, Decode, Debug)]
pub enum SessionManagerError {
    IdentifierNotFound,
    SessionNotYetInitiated,
    Round2SecretPackageNotYetAvailable,
    DeserializationError,
    SignatureAggregationError,
    SignatureNotReadyYet,
    // DKG-specific errors
    Round1SecretPackageNotFound,
    Round2VerificationFailed(String),
    DkgPart3Failed(String),
    StorageError(String),
}