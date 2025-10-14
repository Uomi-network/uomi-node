#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;
// Alias sp_std as std for macro code paths that unconditionally reference `std`.
#[cfg(not(feature = "std"))]
extern crate sp_std as std;
use sp_runtime::KeyTypeId;
use alloc::string::String; // for no_std String

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod prop_tests;

mod fsa;
mod multichain;
mod payloads;
pub mod crypto;
mod errors;
mod utils;
mod sessions;
mod validators;

use core::fmt::Debug;
use frame_support::pallet_prelude::*;
use sp_std::prelude::*;
// Bring in common std replacements for runtime API macro (avoids implicit std:: paths)
use sp_std::{vec::Vec as SpVec, result::Result as SpResult};
pub mod types;
use frame_support::BoundedVec;

use frame_system::offchain::SendUnsignedTransaction;
use frame_system::offchain::{SignedPayload, Signer};
use frame_system::pallet_prelude::{BlockNumberFor, OriginFor};
use frame_system::{ensure_none, ensure_signed};
use scale_info::TypeInfo;
use sp_staking::{
    offence::{Offence, ReportOffence},
    SessionIndex,
};
use sp_runtime::Perbill;
use sp_runtime::transaction_validity::{
    TransactionValidity, ValidTransaction, InvalidTransaction, TransactionSource,
    TransactionPriority,
};
use sp_runtime::traits::{Saturating, SaturatedConversion, Convert};
use frame_system::offchain::SigningTypes;

pub use pallet::*;
use sp_std::vec;
use sp_std::vec::Vec;
use types::{SessionId, NftId};
use ethereum_types::U256;
pub use payloads::*;
pub use errors::*;
pub use utils::*;

// Storage version for pallet_tss. Start at 0; first real migration will bump to 1.
// Do NOT change this constant directly when writing a migration; instead add a new migration
// module (e.g. migrations::v1) and bump the constant there as part of that migration.
pub const STORAGE_VERSION: frame_support::traits::StorageVersion = frame_support::traits::StorageVersion::new(0);

// Migrations module following Polkadot SDK best practices (VersionedMigration + UncheckedOnRuntimeUpgrade).
// Each version hop lives in its own submodule (v1, v2, ...). Add them under migrations/ if they grow large.
// For now we include a skeleton v1 migration illustrating re-keying logic from the previous design
// (legacy storage not present anymore in code, so this runs only on chains that still have old data on upgrade).
// (Removed duplicate alloc::vec::Vec import; sp_std::vec::Vec already in scope)

pub mod migrations; // external module with versioned migrations
pub use migrations::*;

// TssWeightInfo trait for benchmarked weights; fallback implementation provided for tests.
pub trait TssWeightInfo {
    fn create_dkg_session() -> frame_support::weights::Weight;
    fn update_validators() -> frame_support::weights::Weight;
    fn create_signing_session_unsigned() -> frame_support::weights::Weight;
    fn update_last_opoc_request_id_unsigned() -> frame_support::weights::Weight;
    fn submit_dkg_result() -> frame_support::weights::Weight;
    fn submit_signature_result() -> frame_support::weights::Weight;
    fn submit_aggregated_signature() -> frame_support::weights::Weight;
    fn create_reshare_dkg_session() -> frame_support::weights::Weight;
    fn report_participant() -> frame_support::weights::Weight;
    fn report_tss_offence() -> frame_support::weights::Weight;
    fn submit_multi_chain_transaction() -> frame_support::weights::Weight;
    fn update_chain_config() -> frame_support::weights::Weight;
    fn get_transaction_status() -> frame_support::weights::Weight;
    fn timeout_pending_transaction_unsigned() -> frame_support::weights::Weight;
    fn fail_multi_chain_transaction_unsigned() -> frame_support::weights::Weight;
}

impl TssWeightInfo for () { // temporary placeholder until benchmarks are added
    fn create_dkg_session() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn update_validators() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn create_signing_session_unsigned() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn update_last_opoc_request_id_unsigned() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn submit_dkg_result() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn submit_signature_result() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn submit_aggregated_signature() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn create_reshare_dkg_session() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn report_participant() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn report_tss_offence() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn submit_multi_chain_transaction() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn update_chain_config() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn get_transaction_status() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn timeout_pending_transaction_unsigned() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
    fn fail_multi_chain_transaction_unsigned() -> frame_support::weights::Weight { frame_support::weights::Weight::from_parts(10_000,0) }
}


/// A struct for the payload of the ReportTssOffence call
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo, DecodeWithMemTracking)]
pub struct ReportTssOffencePayload<T: Config> {
    pub offence_type: TssOffenceType,
    pub session_id: SessionId,
    pub validator_set_count: u32,
    pub offenders: BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>,
    pub public: T::Public,
}

impl<T: SigningTypes + Config> SignedPayload<T> for ReportTssOffencePayload<T> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

pub const CRYPTO_KEY_TYPE: KeyTypeId = KeyTypeId(*b"tss-");

/// TSS offence types
#[derive(RuntimeDebug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen, DecodeWithMemTracking)]
pub enum TssOffenceType {
    /// Validator failed to participate in DKG session
    DkgNonParticipation,
    /// Validator failed to participate in signing session
    SigningNonParticipation,
    /// Validator sent invalid cryptographic data
    InvalidCryptographicData,
    /// Validator was consistently unresponsive
    UnresponsiveBehavior,
}

// Helper to decode u8 into TssOffenceType
impl From<u8> for TssOffenceType {
    fn from(value: u8) -> Self {
    match value {
        0 => TssOffenceType::DkgNonParticipation,
        1 => TssOffenceType::SigningNonParticipation,
        2 => TssOffenceType::InvalidCryptographicData,
        3 => TssOffenceType::UnresponsiveBehavior,
        _ => panic!("Invalid TSS offence type"),
    }
    }
}
// Helper to encode TssOffenceType into u8
impl TssOffenceType {
    pub fn encode(&self) -> u8 {
    match self {
        TssOffenceType::DkgNonParticipation => 0,
        TssOffenceType::SigningNonParticipation => 1,
        TssOffenceType::InvalidCryptographicData => 2,
        TssOffenceType::UnresponsiveBehavior => 3,
    }
    }
}






#[frame_support::pallet]
pub mod pallet {

    use frame_system::offchain::{AppCrypto, CreateSignedTransaction, CreateInherent};
    use sp_runtime::traits::IdentifyAccount;

    use crate::types::{MaxMessageSize, NftId, PublicKey, Signature};

    use super::*;
    
    // Re-export Verifier to make it accessible from pallet module
    pub use crate::utils::Verifier;

    // Attach a storage version so future migrations can bump from 0 -> 1 etc.
    // Initial version is 0 (implicit); we will migrate to 1 when re-keying legacy storage if needed.
    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    /// Offence structure reported to the staking offences system.
    /// Holds multiple offenders for a single (session, offence_type) combination.
    #[derive(RuntimeDebug, Clone)]
    pub struct TssReportedOffence<T: Config> {
        pub offence_type: TssOffenceType,
        pub session_index: SessionIndex,
        pub validator_set_count: u32,
        pub offenders: Vec<pallet_session::historical::IdentificationTuple<T>>, // full identification tuples
    }

    impl<T: Config> Offence<pallet_session::historical::IdentificationTuple<T>> for TssReportedOffence<T>
    where
        T: pallet_session::historical::Config,
        T: pallet_session::Config<ValidatorId = <T as frame_system::Config>::AccountId>,
    {
        const ID: [u8; 16] = *b"tss:offence_____"; // keep stable; change only with migration
        type TimeSlot = SessionIndex;

        fn offenders(&self) -> Vec<pallet_session::historical::IdentificationTuple<T>> {
            self.offenders.clone()
        }
        fn session_index(&self) -> SessionIndex { self.session_index }
        fn validator_set_count(&self) -> u32 { self.validator_set_count }
        fn time_slot(&self) -> Self::TimeSlot { self.session_index }
        fn slash_fraction(&self, _offenders_count: u32) -> Perbill {
            match self.offence_type {
                TssOffenceType::DkgNonParticipation => Perbill::from_percent(1),
                TssOffenceType::SigningNonParticipation => Perbill::from_percent(1),
                TssOffenceType::InvalidCryptographicData => Perbill::from_percent(2),
                TssOffenceType::UnresponsiveBehavior => Perbill::from_percent(1),
            }
        }
    }


    #[pallet::config]
    pub trait Config:
    frame_system::Config
    + TypeInfo
    + frame_system::offchain::SigningTypes
    + Debug
    + pallet_uomi_engine::pallet::Config
    + pallet_session::Config<ValidatorId = <Self as frame_system::Config>::AccountId>
    + pallet_session::historical::Config
    + CreateSignedTransaction<Call<Self>> 
    + CreateInherent<Call<Self>>
    + pallet_offences::Config

    {
    // Events emitted by the pallet.
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    #[pallet::constant]
    type MaxNumberOfShares: Get<u32>;
    type SignatureVerifier: SignatureVerification<PublicKey>;

    type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

    #[pallet::constant]
    type MinimumValidatorThreshold: Get<u32>;

    /// A trait for reporting offences.
    type OffenceReporter: ReportOffence<
        <Self as frame_system::Config>::AccountId, // reporter AccountId
        pallet_session::historical::IdentificationTuple<Self>, // offender identification tuple
        TssReportedOffence<Self>
    >;
    // Weight info specific to this pallet
    type TssWeightInfo: TssWeightInfo;
    }


    #[derive(Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq, Clone, Copy, PartialOrd, DecodeWithMemTracking)]
    #[repr(u8)]
    pub enum SessionState {
        // NOTE: Explicit discriminants are assigned to preserve backwards compatibility with any
        // previously stored enum values that used the implicit ordering. DO NOT reorder existing
        // variants or change their numeric values without a storage migration.
        // --- DKG lifecycle (original variants 0..=3) ---
        DKGCreated        = 0, // Session object created (participants + metadata recorded)
        DKGInProgress     = 1, // Shares / proposals are being collected
        DKGComplete       = 2, // Aggregated public key finalized
        DKGFailed         = 3, // Genuine protocol failure (legacy values that previously also meant superseded/expired stay here)
        // --- Signing lifecycle (original variants 4..=5) ---
        SigningInProgress = 4, // Collecting partial signatures
        SigningComplete   = 5, // Final aggregated signature produced
        // --- Newly added variants (appended; safe for old data) ---
        DKGSuperseded     = 6, // An older successful DKG rendered inactive by a newer DKG for same nft_id
        DKGExpired        = 7, // DKG session hit its deadline and was expired/cleaned
        SigningExpired    = 8, // Signing session TTL elapsed without completion
    }

    #[derive(Encode, Decode, MaxEncodedLen, Debug, PartialEq, Eq, Clone, TypeInfo, DecodeWithMemTracking)] // IMPORTANT: Keep these derives
    pub struct DKGSession<T>
    where
    T: Config,
    {
    pub participants: BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>,
    pub nft_id: NftId,
    pub threshold: u32,
    pub state: SessionState,
    pub old_participants: Option<BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>>,
    pub deadline: BlockNumberFor<T>,
    }

    #[derive(Encode, Decode, MaxEncodedLen, Debug, PartialEq, Eq, Clone, TypeInfo, DecodeWithMemTracking)]
    pub struct SigningSession {
    pub dkg_session_id: SessionId,
        pub request_id: U256, // Link to OPOC Outputs request id
    pub nft_id: NftId,
    pub message: BoundedVec<u8, MaxMessageSize>, // Store message to sign
    pub state: SessionState,
    pub aggregated_sig: Option<Signature>, // Store final aggregated signature
    }

    #[pallet::storage]
    pub type AggregatedPublicKeys<T: Config> =
    StorageMap<_, Blake2_128Concat, SessionId, PublicKey, OptionQuery>;

    #[pallet::storage]
    pub type PendingDKGUpdates<T: Config> =
    StorageValue<_, BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>>;

    // Add a new storage item for signing sessions
    #[pallet::storage]
    #[pallet::getter(fn get_signing_session)]
    pub type SigningSessions<T: Config> =
    StorageMap<_, Blake2_128Concat, SessionId, SigningSession, OptionQuery>;

    /// Expiration block for a signing session (soft TTL). We avoid altering `SigningSession` itself
    /// to keep storage layout unchanged; an entry here means the session expires at or after the
    /// stored block if still `SigningInProgress` with no aggregated signature.
    #[pallet::storage]
    #[pallet::getter(fn signing_session_expiry)]
    pub type SigningSessionExpiry<T: Config> =
    StorageMap<_, Blake2_128Concat, SessionId, BlockNumberFor<T>, OptionQuery>;

    /// Tracks how many signing attempts have been created for a given request_id.
    /// Keyed by the original external request identifier; increments only when a new
    /// signing session is created (not when one is retried internally). Used to cap retries.
    #[pallet::storage]
    #[pallet::getter(fn request_retry_count)]
    pub type RequestRetryCount<T: Config> =
    StorageMap<_, Blake2_128Concat, U256, u8, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn get_tss_key)]
    pub type TSSKey<T: Config> = StorageValue<_, PublicKey, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn active_validators)]
    pub type ActiveValidators<T: Config> =
    StorageValue<_, BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn get_dkg_session)]
    pub type DkgSessions<T: Config> =
    StorageMap<_, Blake2_128Concat, SessionId, DKGSession<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn next_session_id)]
    pub type NextSessionId<T: Config> = StorageValue<_, SessionId, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn validator_ids)]
    pub type ValidatorIds<T: Config> =
    StorageMap<_, Blake2_128Concat, T::AccountId, u32, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn id_to_validator)]
    pub type IdToValidator<T: Config> =
    StorageMap<_, Blake2_128Concat, u32, T::AccountId, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn next_validator_id)]
    pub type NextValidatorId<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn previous_era)]
    pub type PreviousEra<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn last_opoc_request_id)]
    pub type LastOpocRequestId<T: Config> = StorageValue<_, U256, ValueQuery>;

    // Add storage for tracking previous validator set to detect changes
    #[pallet::storage]
    #[pallet::getter(fn previous_era_validators)]
    pub type PreviousEraValidators<T: Config> =
    StorageValue<_, BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>, ValueQuery>;

    // A storage to store the reported participants for a given session_id. Used to skip them during next retry
    // each participant may report multiple participants, we need to know who reported who so that we can check against
    // that and maybe exclude someone definitively
    #[pallet::storage]
    #[pallet::getter(fn reported_participants)]
    pub type ReportedParticipants<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    SessionId,
    Blake2_128Concat,
    T::AccountId,
    BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>,
    OptionQuery,
    >;

    // A storage that counts for how many sessions a given participant has been reported, so that we can slash them
    #[pallet::storage]
    #[pallet::getter(fn participant_report_count)]
    pub type ParticipantReportCount<T: Config> =
    StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

    // Storage to track pending TSS offences to be processed during on_initialize
    #[pallet::storage]
    #[pallet::getter(fn pending_tss_offences)]
    pub type PendingTssOffences<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        SessionId,
        (TssOffenceType, T::AccountId, BoundedVec<T::AccountId, T::MaxNumberOfShares>), // (type, reporter, offenders)
        OptionQuery,
    >;

    /// Prevent repeated slashing for the same (session, offence_type, offender).
    #[pallet::storage]
    pub type ProcessedOffenderFlags<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, SessionId,
        Blake2_128Concat, (T::AccountId, u8), // (offender, offence_type encoded)
        (),
        OptionQuery
    >;

    // A storage to store temporarily proposed public keys generated from the DKG process associated with the session ID and validator ID
    #[pallet::storage]
    #[pallet::getter(fn proposed_public_keys)]
    pub type ProposedPublicKeys<T: Config> =
    StorageDoubleMap<_, Blake2_128Concat, NftId, Blake2_128Concat, u32, PublicKey, OptionQuery>;

    // A storage to temporarily store proposed aggregated signatures for a signing session
    #[pallet::storage]
    #[pallet::getter(fn proposed_signatures)]
    pub type ProposedSignatures<T: Config> =
    StorageDoubleMap<_, Blake2_128Concat, SessionId, Blake2_128Concat, u32, Signature, OptionQuery>;

    /// Storage for tracking multi-chain transaction status
    /// Maps (chain_id, tx_hash) -> transaction_status
    #[pallet::storage]
    #[pallet::getter(fn multi_chain_transactions)]
    pub type MultiChainTransactions<T: Config> =
    StorageDoubleMap<_, Blake2_128Concat, u32, Blake2_128Concat, BoundedVec<u8, crate::types::MaxTxHashSize>, crate::types::TransactionStatus, OptionQuery>;

    /// Storage for supported chain configurations
    /// Maps chain_id -> (name, rpc_url, is_testnet)
    #[pallet::storage]
    #[pallet::getter(fn chain_configs)]
    pub type ChainConfigs<T: Config> =
    StorageMap<_, Blake2_128Concat, u32, (BoundedVec<u8, crate::types::MaxChainNameSize>, BoundedVec<u8, crate::types::MaxRpcUrlSize>, bool), OptionQuery>;


    /// Storage for tracking submitted transactions pending confirmation
    /// Maps (chain_id, tx_hash) -> (submission_block, max_wait_blocks)
    #[pallet::storage]
    #[pallet::getter(fn pending_transactions)]
    pub type PendingTransactions<T: Config> =
    StorageDoubleMap<_, Blake2_128Concat, u32, Blake2_128Concat, BoundedVec<u8, crate::types::MaxTxHashSize>, (BlockNumberFor<T>, u32), OptionQuery>;

    /// Storage for mapping request IDs (from OPOC Outputs) to pending FSA transaction data
    /// Maps request_id -> (nft_id, chain_id, transaction_data)
    #[pallet::storage]
    #[pallet::getter(fn fsa_transaction_requests)]
    pub type FsaTransactionRequests<T: Config> =
    StorageMap<_, Blake2_128Concat, U256, (NftId, u32, BoundedVec<u8, crate::types::MaxMessageSize>), OptionQuery>;


    /// Counter for generating unique request IDs
    #[pallet::storage]
    #[pallet::getter(fn next_request_id)]
    pub type NextRequestId<T: Config> = StorageValue<_, u32, ValueQuery>;

    // Legacy AgentNonces storage removed; NonceStates now handles allocation + acceptance window.

    /// Advanced nonce tracking state per (agent, chain)
    #[pallet::storage]
    #[pallet::getter(fn nonce_states)]
    pub type NonceStates<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, NftId,
        Blake2_128Concat, u32,
        crate::types::NonceState,
        ValueQuery
    >;

    /// Map signing session -> (chain_id, allocated_nonce)
    #[pallet::storage]
    #[pallet::getter(fn signing_session_nonce)]
    pub type SigningSessionNonces<T: Config> = StorageMap<
        _,
        Blake2_128Concat, SessionId,
        (u32, u64),
        OptionQuery
    >;

    

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
    /// A new TSS key has been set.
    DKGSessionCreated(SessionId),
    DKGReshareSessionCreated(SessionId, SessionId), // (new_session_id, old_session_id)
    SigningSessionCreated(SessionId, SessionId), // Signing session ID, DKG session ID
    DKGCompleted(SessionId, PublicKey),          // Aggregated public key
    SigningCompleted(SessionId, Signature),      // Final aggregated signature
    SignatureResultSubmitted(SessionId, Signature), // Emitted when threshold reached for signature voting
    SignatureSubmitted(SessionId),               // When signature is stored
    ValidatorIdAssigned(T::AccountId, u32),      // Validator account, ID
    DKGFailed(SessionId),                        // DKG session failed (protocol failure)
    DKGSuperseded(SessionId),                    // Older DKG made inactive by a newer one
    DKGExpired(SessionId),                       // DKG session deadline reached and removed
    SigningExpired(SessionId),                   // Signing session TTL reached and expired
    SigningRetry(U256, u8, SessionId),           // (request_id, attempt_number, new_session_id)
    SigningRetriesExhausted(U256, u8),           // (request_id, attempts)
    /// Validator has been slashed for TSS offence
    ValidatorSlashed(T::AccountId, TssOffenceType, SessionId),
    /// Offence has been reported to the staking system
    OffenceReported(TssOffenceType, SessionId, u32), // offence type, session id, validator count
    
    /// Multi-chain transaction events
    MultiChainTransactionSubmitted(u32, Vec<u8>), // Chain ID, Transaction hash
    MultiChainTransactionConfirmed(u32, Vec<u8>), // Chain ID, Transaction hash
    MultiChainTransactionFailed(u32, Vec<u8>),    // Chain ID, Transaction hash
    ChainConfigurationUpdated(u32),               // Chain ID updated
    /// Transaction request submitted to FSA
    TransactionRequestSubmitted(NftId, u32),      // NFT ID, Chain ID
    // Nonce tracking events
    NonceAllocated(NftId, u32, u64),              // (agent, chain, nonce)
    NonceAccepted(NftId, u32, u64, Vec<u8>),      // (agent, chain, nonce, tx_hash)
    NonceWindowPruned(NftId, u32, u64),           // pruned up to (last_accepted)
    /// Detected mismatch between internal allocated nonce and chain's reported account nonce (chain reports lower)
    NonceGapDetected(NftId, u32, u64, u64),       // (agent, chain, internal_last_allocated, chain_next_nonce)
    /// Queued a gap filler (empty) transaction for the earliest missing nonce
    NonceGapFillerQueued(NftId, u32, u64),        // (agent, chain, nonce)
    }

    #[pallet::error]
    pub enum Error<T> {
    KeyUpdateFailed,
    DuplicateParticipant,
    InvalidParticipantsCount,
    TooFewActiveValidators,
    InvalidThreshold,
    DkgSessionNotFound,
    DkgSessionNotReady,
    InvalidSignature,
    UnauthorizedParticipation,
    AggregatedKeyAlreadySubmitted,
    StaleDkgSession,
    InvalidSessionState,
    SigningSessionNotFound,
    DecodingError,
    /// Failed to retrieve validator's full identification
    FullIdentificationNotFound,
    /// Failed to report offence to staking system
    OffenceReportingFailed,
    /// Invalid offence type
    InvalidOffenceType,
    
    /// Multi-chain related errors
    UnsupportedChain,
    TransactionSubmissionFailed,
    InvalidChainConfig,
    ChainConnectionFailed,
    InvalidTransactionData,
    InsufficientGasLimit,
    InvalidNonce,
    NonceWindowExceeded,
    NonceNotAllocated,
    PendingStorageFull,
    /// Called a deprecated / removed extrinsic retained only for decoding legacy transactions
    DeprecatedExtrinsic,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::create_dkg_session())]
    #[pallet::call_index(0)]
    pub fn create_dkg_session(
        _origin: OriginFor<T>,
        nft_id: NftId,
        threshold: u32,
    ) -> DispatchResult {
        ensure!(threshold > 0, Error::<T>::InvalidThreshold);

        // threshold needs to be an integer value between 50 and 100%
        ensure!(threshold <= 100, Error::<T>::InvalidThreshold);
        ensure!(threshold >= 50, Error::<T>::InvalidThreshold);

        let slashed_validators = Self::get_slashed_validators();
    // Deadline is current block + 100 (kept small for tests)
    let deadline = frame_system::Pallet::<T>::block_number() + 100u32.into();

        let active_validators = ActiveValidators::<T>::get();

        // we need to be sure that the slashed validators is not more than 1/3 of the active validators, otherwise stop here
        let total_validators = active_validators.len() as u32;
        let slashed_validators_count = slashed_validators.len() as u32; 

    // Use global minimum validator threshold only for availability check (rename to avoid shadowing user threshold)
    let min_pct = T::MinimumValidatorThreshold::get(); // percentage of validators needed to sign
    let required_validators = (total_validators * min_pct) / 100;

        // Check if the number of slashed validators exceeds the threshold
        ensure!(
            slashed_validators_count <= (total_validators - required_validators),
            Error::<T>::TooFewActiveValidators,
        );
        
        let participants = active_validators
            .iter()
            .filter(|validator| !slashed_validators.contains(validator))
            .cloned()
            .collect::<Vec<T::AccountId>>();

        ensure!(
            participants.len() > 0,
            Error::<T>::TooFewActiveValidators,
        );

        // Create new DKG session
        let session = DKGSession {
            nft_id,
            participants: BoundedVec::try_from(participants).map_err(|_| Error::<T>::InvalidParticipantsCount)?,
            // Store the user-requested session threshold (after validation) rather than global min
            threshold,
            state: SessionState::DKGCreated,
            old_participants: None,
            deadline
        };


        // Generate random session ID
        let session_id = Self::get_next_session_id();

        // Store the session
        DkgSessions::<T>::insert(session_id, session);

        Self::deposit_event(Event::DKGSessionCreated(session_id));
        Ok(())
    }

    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::update_validators())]
    #[pallet::call_index(1)]
    pub fn update_validators(
        origin: OriginFor<T>,
        payload: UpdateValidatorsPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;

        let new_validators = payload.validators;

        // Assign IDs to any new validators
        for validator in new_validators.clone() {
            Self::assign_validator_id(validator)?;
        }

        ActiveValidators::<T>::put(BoundedVec::try_from(new_validators.clone()).unwrap());

        Ok(())
    }

    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::create_signing_session_unsigned())]
    #[pallet::call_index(2)]
    pub fn create_signing_session(
        _origin: OriginFor<T>,
        request_id: U256,
        nft_id: NftId,
        message: BoundedVec<u8, MaxMessageSize>,
    ) -> DispatchResult {
        // Retry policy constants (could be configurable via Config later)
        const MAX_SIGNING_RETRIES: u8 = 3; // total attempts allowed (including first)

        // Check existing sessions for this request
        let mut has_in_progress = false;
        for (_sid, existing) in SigningSessions::<T>::iter() {
            if existing.request_id == request_id {
                match existing.state {
                    SessionState::SigningInProgress => {
                        has_in_progress = true;
                        break;
                    }
                    _ => { /* terminal */ }
                }
            }
        }
        if has_in_progress {
            log::debug!("[TSS] Skipping duplicate signing session (in progress) for request_id {:?}", request_id);
            return Ok(());
        }

        // Determine attempt number
        let mut attempt = RequestRetryCount::<T>::get(request_id);
        if attempt >= MAX_SIGNING_RETRIES {
            // Exceeded retry budget
            Self::deposit_event(Event::SigningRetriesExhausted(request_id, attempt));
            return Ok(()); // silently ignore further attempts
        }
    attempt += 1; // current attempt number (1-based)
    RequestRetryCount::<T>::insert(request_id, attempt);
        // Select the MOST RECENT completed DKG session for this NFT (highest session_id).
        // This avoids relying on the first iterator hit (which is not ordered) and implicitly
        // gives precedence to newer reshare keys without adding new storage fields.
        let dkg_session_id = DkgSessions::<T>::iter()
            .filter(|(_, s)| s.nft_id == nft_id && s.state == SessionState::DKGComplete)
            .max_by_key(|(id, _)| *id)
            .map(|(id, _)| id)
            .ok_or(Error::<T>::DkgSessionNotFound)?;

        // Ensure the DKG session is in the correct state
        let dkg_session =
            Self::get_dkg_session(dkg_session_id).ok_or(Error::<T>::DkgSessionNotFound)?;
        ensure!(
            dkg_session.state == SessionState::DKGComplete,
            Error::<T>::DkgSessionNotReady
        );

        // Determine chain for this request (if transaction data already registered)
        let maybe_chain_id = FsaTransactionRequests::<T>::get(&request_id).map(|(_, cid, _)| cid);

        // Create new Signing session
        let session = SigningSession {
            dkg_session_id,
            request_id,
            nft_id: nft_id.clone(),
            message,
            aggregated_sig: None,
            state: SessionState::SigningInProgress,
        };

        // Generate session ID
        let session_id = Self::get_next_session_id();

        // Store the session
        SigningSessions::<T>::insert(session_id, session.clone());
    // Record expiry (TTL) using a fixed heuristic; avoid new Config item to keep runtime stable.
    let ttl_blocks: BlockNumberFor<T> = 300u32.into(); // TODO: consider making configurable in future upgrade
    let expiry = frame_system::Pallet::<T>::block_number() + ttl_blocks;
    SigningSessionExpiry::<T>::insert(session_id, expiry);

    // Emit events
    // Allocate nonce early if we know chain
    if let Some(chain_id) = maybe_chain_id {
        if let Ok(nonce) = Self::allocate_next_nonce_internal(&session.nft_id, chain_id) {
            SigningSessionNonces::<T>::insert(session_id, (chain_id, nonce));
        }
    }
    Self::deposit_event(Event::SigningSessionCreated(session_id, dkg_session_id));
    // Emit SigningRetry only for retry attempts (attempt > 1)
    if attempt > 1 { Self::deposit_event(Event::SigningRetry(request_id, attempt, session_id)); }

        Ok(())
    }

    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::create_signing_session_unsigned())]
    #[pallet::call_index(7)]
    pub fn create_signing_session_unsigned(
        origin: OriginFor<T>,
        payload: CreateSigningSessionPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;

        // Convert U256 to NftId (BoundedVec<u8, MaxCidSize>)
        let nft_id_bytes: Vec<u8> = payload.nft_id.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
        let nft_id = BoundedVec::try_from(nft_id_bytes)
            .map_err(|_| Error::<T>::DecodingError)?;

        // Store FSA transaction request (nft_id + chain_id + message bytes) if not already stored
        if !FsaTransactionRequests::<T>::contains_key(&payload.request_id) {
            FsaTransactionRequests::<T>::insert(&payload.request_id, (nft_id.clone(), payload.chain_id, payload.message.clone()));
            log::info!("[TSS] Stored FSA transaction request for request_id {:?} on chain {}", payload.request_id, payload.chain_id);
        }

        Self::create_signing_session(
            frame_system::RawOrigin::None.into(),
            payload.request_id,
            nft_id,
            payload.message,
        )
    }

    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::update_last_opoc_request_id_unsigned())]
    #[pallet::call_index(16)]
    pub fn update_last_opoc_request_id_unsigned(
        origin: OriginFor<T>,
        payload: UpdateLastOpocRequestIdPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;
        LastOpocRequestId::<T>::put(payload.last_request_id);
        Ok(())
    }

    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::submit_dkg_result())]
    #[pallet::call_index(3)]
    pub fn submit_dkg_result(
        origin: OriginFor<T>,
        payload: SubmitDKGResultPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;

        log::info!("[TSS] Call::submit_dkg_result");

        let who = payload.public().into_account();
        let session_id = payload.session_id;
        let aggregated_key = payload.public_key;


        let mut session =
            DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

        log::info!("[TSS] Current session state: {:?}", session.state);
    // Only allow result submission while session is in creation or in-progress
    ensure!(matches!(session.state, SessionState::DKGCreated | SessionState::DKGInProgress), Error::<T>::InvalidSessionState);

        // Get the NFT ID from the session
        let nft_id = session.nft_id.clone();

        // Check if the validator was involved in the DKG session
        let validator_id = ValidatorIds::<T>::get(who.clone()).ok_or(Error::<T>::UnauthorizedParticipation)?;
        log::info!("[TSS] Validator ID: {:?}", validator_id);
        log::info!("[TSS] Is participant: {:?}", session.participants.contains(&who));
        ensure!(
            session.participants.contains(&who),
            Error::<T>::UnauthorizedParticipation
        );

        // Add the vote to the proposed public keys
        ProposedPublicKeys::<T>::insert(nft_id.clone(), validator_id, aggregated_key.clone());

        log::info!("[TSS] Proposed public key inserted");

        let threshold = T::MinimumValidatorThreshold::get(); // percentage of validators needed to sign

        // Check if the number of votes meets the threshold
        let mut votes = 0;
        
    for (_validator_id, key) in ProposedPublicKeys::<T>::iter_prefix(nft_id.clone()) {
            if key == aggregated_key {
                votes += 1;
            }
        }

        let total_validators = session.participants.len() as u32;
        let required_votes = (total_validators * threshold) / 100;

        log::info!("[TSS] Votes: {}, Required: {}", votes, required_votes);

        if votes >= required_votes {
            // If the threshold is met, finalize the DKG session
            session.state = SessionState::DKGComplete;
            DkgSessions::<T>::insert(session_id, session);

            // Store the aggregated public key
            AggregatedPublicKeys::<T>::insert(session_id, aggregated_key.clone());

            // Mark all older completed DKG sessions for the same NFT as failed (superseded).
            // We reuse the existing DKGFailed state to avoid introducing a new enum variant / storage field.
            // This overloading should be documented: DKGFailed now also means "Inactive (superseded)".
            if let Some(current_session) = DkgSessions::<T>::get(session_id) {
                for (other_id, mut other_session) in DkgSessions::<T>::iter() {
                    if other_id != session_id
                        && other_session.nft_id == current_session.nft_id
                        && other_session.state == SessionState::DKGComplete
                    {
                        other_session.state = SessionState::DKGSuperseded; // mark as inactive
                        DkgSessions::<T>::insert(other_id, other_session);
                        Self::deposit_event(Event::DKGSuperseded(other_id));
                    }
                }
            }

            // Emit event
            Self::deposit_event(Event::DKGCompleted(session_id, aggregated_key));

            // GC: remove all ProposedPublicKeys votes for this nft_id (final key chosen)
            let _ = ProposedPublicKeys::<T>::clear_prefix(nft_id.clone(), u32::MAX, None);
        }
        Ok(())
    }

    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::submit_signature_result())]
    #[pallet::call_index(15)]
    pub fn submit_signature_result(
        origin: OriginFor<T>,
        payload: crate::payloads::SubmitSignatureResultPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;

        let who = payload.public().into_account();
        let session_id = payload.session_id;
        let signature = payload.signature.clone();

        // Fetch signing session
        let mut session = SigningSessions::<T>::get(session_id).ok_or(Error::<T>::SigningSessionNotFound)?;

        // Only allow while signing is in progress
        ensure!(matches!(session.state, SessionState::SigningInProgress), Error::<T>::InvalidSessionState);

        // Retrieve corresponding DKG session for participants and nft id
        let dkg_session = DkgSessions::<T>::get(session.dkg_session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

        // Ensure signer participated
        ensure!(dkg_session.participants.contains(&who), Error::<T>::UnauthorizedParticipation);
        let validator_id = ValidatorIds::<T>::get(who).ok_or(Error::<T>::UnauthorizedParticipation)?;

        // Insert vote
        ProposedSignatures::<T>::insert(session_id, validator_id, signature.clone());

        // Count votes for this signature
        let threshold_pct = T::MinimumValidatorThreshold::get();
        let mut votes = 0u32;
        for (_validator_id, sig) in ProposedSignatures::<T>::iter_prefix(session_id) {
            if sig == signature { votes += 1; }
        }
        let total = dkg_session.participants.len() as u32;
        let required = (total * threshold_pct) / 100;

        if votes >= required {
            // Finalize
            session.aggregated_sig = Some(signature.clone());
            session.state = SessionState::SigningComplete;
            let req_id_for_cleanup = session.request_id;
            // Store updated session state (clone to retain local copy if further logic added later)
            SigningSessions::<T>::insert(session_id, session.clone());
            // Success: clear retry counter so future identical request IDs could start fresh if reused.
            RequestRetryCount::<T>::remove(req_id_for_cleanup);
            Self::deposit_event(Event::SignatureResultSubmitted(session_id, signature));

            // GC: clear votes for this signing session now finalized
            let _ = ProposedSignatures::<T>::clear_prefix(session_id, u32::MAX, None);
        }
        Ok(())
    }

    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::submit_dkg_result())]
    #[pallet::call_index(14)]
    pub fn finalize_dkg_session(
        origin: OriginFor<T>,
        session_id: SessionId,
        aggregated_key: Vec<u8>,
    ) -> DispatchResult {
        let _who = ensure_signed(origin)?;
        let mut session = DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;
        ensure!(session.state == SessionState::DKGInProgress, Error::<T>::InvalidSessionState);
        session.state = SessionState::DKGComplete;
        DkgSessions::<T>::insert(session_id, session);
        let bounded: PublicKey = BoundedVec::try_from(aggregated_key.clone()).map_err(|_| Error::<T>::InvalidParticipantsCount)?;
        AggregatedPublicKeys::<T>::insert(session_id, bounded.clone());

        // Mark older completed sessions for same NFT as failed (superseded) without extra storage.
        if let Some(current_session) = DkgSessions::<T>::get(session_id) {
            for (other_id, mut other_session) in DkgSessions::<T>::iter() {
                if other_id != session_id
                    && other_session.nft_id == current_session.nft_id
                    && other_session.state == SessionState::DKGComplete
                {
                    other_session.state = SessionState::DKGSuperseded;
                    DkgSessions::<T>::insert(other_id, other_session);
                    Self::deposit_event(Event::DKGSuperseded(other_id));
                }
            }
            // GC: clear any lingering proposed public keys for this NFT
            let _ = ProposedPublicKeys::<T>::clear_prefix(current_session.nft_id, u32::MAX, None);
        }
        Self::deposit_event(Event::DKGCompleted(session_id, bounded));
        Ok(())
    }

    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::submit_aggregated_signature())]
    #[pallet::call_index(4)]
    pub fn submit_aggregated_signature(
        origin: OriginFor<T>,
        session_id: SessionId,
        signature: Signature,
    ) -> DispatchResult {
        let _who = ensure_signed(origin)?; // Could add participant check

        let mut session =
            SigningSessions::<T>::get(session_id).ok_or(Error::<T>::SigningSessionNotFound)?;

        ensure!(
            session.state == SessionState::SigningInProgress,
            Error::<T>::InvalidSessionState
        );

        // Verify signature against stored message and TSS key
        let public_key = TSSKey::<T>::get();
        ensure!(
            verify_signature::<T>(&public_key, &session.message, &signature),
            Error::<T>::InvalidSignature
        );

        session.aggregated_sig = Some(signature.clone());
        session.state = SessionState::SigningComplete;
    let req_id_for_cleanup = session.request_id;
    SigningSessions::<T>::insert(session_id, session.clone());
    RequestRetryCount::<T>::remove(req_id_for_cleanup);

        // Signature is already stored in session.aggregated_sig for FSA processing
        log::info!("Completed signature for session {} ready for transaction submission", session_id);

    // GC: clear votes for this signing session
    let _ = ProposedSignatures::<T>::clear_prefix(session_id, u32::MAX, None);

        Self::deposit_event(Event::SigningCompleted(session_id, signature));
        Ok(())
    }

    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::create_reshare_dkg_session())]
    #[pallet::call_index(5)]
    pub fn create_reshare_dkg_session(
        origin: OriginFor<T>,
        nft_id: NftId,
        threshold: u32,
        old_participants: BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>,
    ) -> DispatchResult {
        let _who = ensure_signed(origin)?;
    // Reuse internal helper
    Self::internal_create_reshare_dkg_session(nft_id, threshold, old_participants)
    }

    // New unsigned variant with signed payload for offchain usage
    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::create_reshare_dkg_session())]
    #[pallet::call_index(21)]
    pub fn create_reshare_dkg_session_unsigned(
        origin: OriginFor<T>,
        payload: crate::CreateReshareDkgSessionPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;
        Self::internal_create_reshare_dkg_session(
            payload.nft_id.clone(),
            payload.threshold,
            payload.old_participants.clone(),
        )
    }
    
    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::create_reshare_dkg_session())]
    #[pallet::call_index(22)]
    pub fn complete_reshare_session_unsigned(
        origin: OriginFor<T>,
        payload: crate::payloads::CompleteResharePayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;
        // Only call internal helper with provided session id
        Self::complete_reshare_session(payload.session_id)
    }

    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::report_participant())]
    #[pallet::call_index(6)]
    pub fn report_participant(
        origin: OriginFor<T>,
        payload: ReportParticipantsPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        let _ = ensure_none(origin)?;

        let who = payload.public().into_account();

        // Check if the session exists
        let _session =
            DkgSessions::<T>::get(payload.session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

        // Check if the participant has already reported for this session
        if let Some(mut reported_list) =
            ReportedParticipants::<T>::get(payload.session_id, who.clone())
        {
            // Check if any of the reported participants are already in the list
            for reported_participant in payload.reported_participants.iter() {
                if reported_list.contains(reported_participant) {
                    // Participant has already been reported by this reporter
                    // You might want to handle this differently, e.g., ignore the duplicate report
                    continue;
                }
                // Add the new reported participant to the list
                reported_list
                    .try_push(reported_participant.clone())
                    .map_err(|_| Error::<T>::InvalidParticipantsCount)?;
            }
            // Update the storage with the new list
            ReportedParticipants::<T>::insert(payload.session_id, who.clone(), reported_list);
        } else {
            // No previous reports from this participant, add the new list
            ReportedParticipants::<T>::insert(
                payload.session_id,
                who.clone(),
                payload.reported_participants.clone(),
            );
        }
        Ok(())
    }

    /// Report TSS offence and slash validator
    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::report_tss_offence())]
    #[pallet::call_index(8)]
    pub fn report_tss_offence(
        origin: OriginFor<T>,
        payload: ReportTssOffencePayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;

        let who = payload.public().into_account();
        
        // Verify the session exists
        let session = DkgSessions::<T>::get(payload.session_id).ok_or(Error::<T>::DkgSessionNotFound)?;
        
        // Ensure the reporter is a participant in the session
        ensure!(
            session.participants.contains(&who),
            Error::<T>::UnauthorizedParticipation
        );
        // Store the offence with reporter
        PendingTssOffences::<T>::insert(
            payload.session_id,
            (payload.offence_type.clone(), who.clone(), payload.offenders.clone())
        );
        Self::deposit_event(Event::OffenceReported(payload.offence_type, payload.session_id, payload.offenders.len() as u32));
        Ok(())
    }

    /// Submit a signed transaction to a specific blockchain network
    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::submit_multi_chain_transaction())]
    #[pallet::call_index(9)]
    pub fn submit_multi_chain_transaction(
        origin: OriginFor<T>,
        chain_id: u32,
        signed_transaction: Vec<u8>,
    ) -> DispatchResult {
        let _who = ensure_signed(origin)?;

        // Validate chain is supported
        ensure!(
            Self::is_chain_supported(chain_id),
            Error::<T>::UnsupportedChain
        );

        // Submit transaction
        match Self::submit_multi_chain_transaction_to_chain(chain_id, &signed_transaction) {
            Ok(response) => {
                // Store transaction status
                if let Some(ref tx_hash) = response.tx_hash {
                    let tx_hash_bytes = tx_hash.as_bytes().to_vec();
                    let bounded_tx_hash: BoundedVec<u8, crate::types::MaxTxHashSize> = 
                        tx_hash_bytes.clone().try_into()
                            .map_err(|_| Error::<T>::InvalidTransactionData)?;
                    
                    MultiChainTransactions::<T>::insert(
                        chain_id,
                        bounded_tx_hash.clone(),
                        response.status.clone(),
                    );

                    // Add to pending transactions for status tracking
                    let current_block = frame_system::Pallet::<T>::block_number();
                    let max_wait_blocks = 100u32; // Wait up to 100 blocks for confirmation
                    
                    PendingTransactions::<T>::insert(
                        chain_id, 
                        bounded_tx_hash.clone(), 
                        (current_block, max_wait_blocks)
                    );

                    // Emit event
                    Self::deposit_event(Event::MultiChainTransactionSubmitted(
                        chain_id,
                        tx_hash_bytes,
                    ));
                }
                Ok(())
            }
            Err(_) => Err(Error::<T>::TransactionSubmissionFailed.into()),
        }
    }

    /// Update the configuration for a supported blockchain network
    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::update_chain_config())]
    #[pallet::call_index(10)]
    pub fn update_chain_config(
        origin: OriginFor<T>,
        chain_id: u32,
        name: Vec<u8>,
        rpc_url: Vec<u8>,
        is_testnet: bool,
    ) -> DispatchResult {
        let _who = ensure_signed(origin)?;

        // Basic validation
        ensure!(!name.is_empty(), Error::<T>::InvalidChainConfig);
        ensure!(!rpc_url.is_empty(), Error::<T>::InvalidChainConfig);

        // Convert to BoundedVec
        let bounded_name: BoundedVec<u8, crate::types::MaxChainNameSize> = 
            name.try_into().map_err(|_| Error::<T>::InvalidChainConfig)?;
        let bounded_rpc_url: BoundedVec<u8, crate::types::MaxRpcUrlSize> = 
            rpc_url.try_into().map_err(|_| Error::<T>::InvalidChainConfig)?;

        // Store chain configuration
        ChainConfigs::<T>::insert(chain_id, (bounded_name, bounded_rpc_url, is_testnet));

        // Emit event
        Self::deposit_event(Event::ChainConfigurationUpdated(chain_id));

        Ok(())
    }

    // Removed legacy get_agent_nonce / increment_agent_nonce extrinsics (indices 11,12) – internal nonce management only.
    // Reintroduced as deprecated stubs so old in-flight transactions decode cleanly instead of panicking.
    #[pallet::weight(0)]
    #[pallet::call_index(11)]
    pub fn get_agent_nonce(
        origin: OriginFor<T>,
        _nft_id: NftId,
        _chain_id: u32,
    ) -> DispatchResult {
        ensure_none(origin)?;
        Err(Error::<T>::DeprecatedExtrinsic.into())
    }

    #[pallet::weight(0)]
    #[pallet::call_index(12)]
    pub fn increment_agent_nonce(
        origin: OriginFor<T>,
        _nft_id: NftId,
        _chain_id: u32,
    ) -> DispatchResult {
        ensure_none(origin)?;
        Err(Error::<T>::DeprecatedExtrinsic.into())
    }

    /// Get the status of a multi-chain transaction
    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::get_transaction_status())]
    #[pallet::call_index(13)]
    pub fn get_transaction_status(
        origin: OriginFor<T>,
        chain_id: u32,
        tx_hash: Vec<u8>,
    ) -> DispatchResult {
        let _who = ensure_signed(origin)?;

        // Validate chain is supported
        ensure!(
            Self::is_chain_supported(chain_id),
            Error::<T>::UnsupportedChain
        );

        let bounded_tx_hash: BoundedVec<u8, crate::types::MaxTxHashSize> = 
            tx_hash.try_into().map_err(|_| Error::<T>::InvalidTransactionData)?;

        // Check stored transaction status
        if let Some(status) = MultiChainTransactions::<T>::get(chain_id, &bounded_tx_hash) {
            log::info!("Transaction status: {:?}", status);
            // In a real implementation, you might want to emit an event or return the status
        } else {
            log::warn!("Transaction not found in storage");
            return Err(Error::<T>::InvalidTransactionData.into());
        }

        Ok(())
    }

    /// Record an FSA transaction submission (unsigned, produced by offchain worker)
    #[pallet::weight(10_000)]
    #[pallet::call_index(17)]
    pub fn submit_fsa_transaction_unsigned(
        origin: OriginFor<T>,
        payload: crate::payloads::SubmitFsaTransactionPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;
        let chain_id = payload.chain_id;
        let current_block = frame_system::Pallet::<T>::block_number();
        let max_wait_blocks = 300u32; // keep consistent with previous logic
        PendingTransactions::<T>::insert(chain_id, payload.tx_hash.clone(), (current_block, max_wait_blocks));
        MultiChainTransactions::<T>::insert(chain_id, payload.tx_hash.clone(), crate::types::TransactionStatus::Submitted);
        Self::deposit_event(Event::MultiChainTransactionSubmitted(chain_id, payload.tx_hash.to_vec()));
    // Directly remove the FSA request by request_id now that it's included in the payload
    FsaTransactionRequests::<T>::remove(&payload.request_id);
        Ok(())
    }
    /// Offchain worker marks a pending transaction as timed out (Failed) when exceeding deadline
    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::timeout_pending_transaction_unsigned())]
    #[pallet::call_index(19)]
    pub fn timeout_pending_transaction_unsigned(
        origin: OriginFor<T>,
        payload: crate::payloads::TimeoutPendingTransactionPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;
        // Ensure still pending
        if PendingTransactions::<T>::contains_key(payload.chain_id, &payload.tx_hash) {
            PendingTransactions::<T>::remove(payload.chain_id, &payload.tx_hash);
            MultiChainTransactions::<T>::insert(payload.chain_id, payload.tx_hash.clone(), crate::types::TransactionStatus::Failed);
            Self::deposit_event(Event::MultiChainTransactionFailed(payload.chain_id, payload.tx_hash.to_vec()));
        }
        Ok(())
    }

    /// Offchain worker marks a failed transaction
    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::fail_multi_chain_transaction_unsigned())]
    #[pallet::call_index(20)]
    pub fn fail_multi_chain_transaction_unsigned(
        origin: OriginFor<T>,
        payload: crate::payloads::FailMultiChainTransactionPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;
        // Ensure still pending
        let request_id = payload.request_id;

        if FsaTransactionRequests::<T>::contains_key(&request_id) {
            if let Some((_, chain_id, _)) = FsaTransactionRequests::<T>::get(&request_id) {
                FsaTransactionRequests::<T>::remove(&request_id);
                Self::deposit_event(Event::MultiChainTransactionFailed(chain_id, Vec::new()));
            }
        }
        Ok(())
    }

    /// Create a signing session specifically for a nonce gap filler (unsigned, offchain initiated)
    #[pallet::weight(<T as pallet::Config>::TssWeightInfo::create_signing_session_unsigned())]
    #[pallet::call_index(18)]
    pub fn create_gap_filler_signing_session_unsigned(
        origin: OriginFor<T>,
        payload: crate::payloads::GapFillerSigningSessionPayload<T>,
        _signature: T::Signature,
    ) -> DispatchResult {
        ensure_none(origin)?;
        // Convert nft_id U256 -> NftId
        let nft_id_bytes: Vec<u8> = payload.nft_id.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
        let nft_id = BoundedVec::try_from(nft_id_bytes).map_err(|_| Error::<T>::InvalidTransactionData)?;
        // Store a minimal empty transaction request for this filler if not already exists
        let filler_request_id = payload.request_id;
        if !FsaTransactionRequests::<T>::contains_key(&filler_request_id) {
            let data = payload.message.clone();
            FsaTransactionRequests::<T>::insert(filler_request_id, (nft_id.clone(), payload.chain_id, data));
        }
        // Reuse existing create_signing_session logic (private) by calling into pallet extrinsic path
        // We call internal version: ensure no in-progress duplicate for this request
        let message = payload.message.clone();
        // Create a signing session state
        let mut attempt = RequestRetryCount::<T>::get(filler_request_id);
        if attempt == 0 { attempt = 0; }
        let dkg_session_id = DkgSessions::<T>::iter().filter_map(|(sid, sess)| if sess.nft_id == nft_id { Some((sid, sess)) } else { None }).max_by_key(|(sid, _)| *sid).map(|(sid, _)| sid).ok_or(Error::<T>::DkgSessionNotFound)?;
        let dkg_session = DkgSessions::<T>::get(dkg_session_id).ok_or(Error::<T>::DkgSessionNotFound)?;
        ensure!(matches!(dkg_session.state, SessionState::DKGComplete), Error::<T>::DkgSessionNotFound);
        // Create signing session
        let signing_session = SigningSession {
            dkg_session_id,
            request_id: filler_request_id,
            nft_id: nft_id.clone(),
            message: message.clone(),
            state: SessionState::SigningInProgress,
            aggregated_sig: None,
        };
        let session_id = Self::get_next_session_id();
        SigningSessions::<T>::insert(session_id, signing_session);
        // Allocate target nonce explicitly if not already tracked
        let _ = Self::allocate_next_nonce_internal(&nft_id, payload.chain_id); // ignore errors (window etc.)
        SigningSessionExpiry::<T>::insert(session_id, frame_system::Pallet::<T>::block_number() + 300u32.into());
        Self::deposit_event(Event::SigningSessionCreated(session_id, dkg_session_id));
        Ok(())
    }
    // (Removed public nonce extrinsics; nonce flow handled internally via unsigned offchain submissions)

    }


    // pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"tss-iden";

    // #[pallet::inherent]
    // impl<T: Config> ProvideInherent for Pallet<T> {
    //     type Call = Call<T>;
    //     type Error = InherentError;
    //     const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

    //     fn create_inherent(data: &InherentData) -> Option<Self::Call> {

    //         None
    //     }
    //     fn is_inherent(call: &Self::Call) -> bool {
    //         // matches!(call, Call::submit_dkg_result { .. })
    //         false
    //     }
    // }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
        match call {
            // Handle inherent extrinsics
            Call::update_validators { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX)
                    .and_provides(call.encode())
                    .longevity(64)
                    .propagate(true)
                    .build();
            }
            Call::report_participant { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX)
                    .and_provides(call.encode())
                    .longevity(64)
                    .propagate(true)
                    .build();
            }
            Call::report_tss_offence { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX)
                    .and_provides(call.encode())
                    .longevity(64)
                    .propagate(true)
                    .build();
            }
            Call::create_signing_session_unsigned { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX)
                    .and_provides(call.encode())
                    .longevity(64)
                    .propagate(true)
                    .build();
            }
            Call::submit_dkg_result { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX)
                    .and_provides(call.encode())
                    .longevity(64)
                    .propagate(true)
                    .build();
            }
            Call::submit_signature_result { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX)
                    .and_provides(call.encode())
                    .longevity(64)
                    .propagate(true)
                    .build();
            }
            Call::update_last_opoc_request_id_unsigned { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX)
                    .and_provides(call.encode())
                    .longevity(64)
                    .propagate(true)
                    .build();
            }
            Call::submit_fsa_transaction_unsigned { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX)
                    .and_provides(call.encode())
                    .longevity(64)
                    .propagate(true)
                    .build();
            }
            Call::create_reshare_dkg_session_unsigned { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX)
                    .and_provides(call.encode())
                    .longevity(32)
                    .propagate(true)
                    .build();
            }
            Call::create_gap_filler_signing_session_unsigned { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX / 2) // lower than normal sessions
                    .and_provides(call.encode())
                    .longevity(32)
                    .propagate(true)
                    .build();
            }
            Call::timeout_pending_transaction_unsigned { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX / 4)
                    .and_provides(call.encode())
                    .longevity(16)
                    .propagate(true)
                    .build();
            }
            Call::fail_multi_chain_transaction_unsigned { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX / 4)
                    .and_provides(call.encode())
                    .longevity(16)
                    .propagate(true)
                    .build();
            }

            Call::complete_reshare_session_unsigned { .. } => {
                return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX / 4)
                    .and_provides(call.encode())
                    .longevity(16)
                    .propagate(true)
                    .build();
            }

            // Reject all other unsigned calls
            _ => {
                return InvalidTransaction::Call.into();
            }
        }
    }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    #[cfg(feature = "try-runtime")]
    fn try_state(_n: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
        // Nessuna verifica specifica: pallet non richiede controlli addizionali per lo stato.
        Ok(())
    }
    fn offchain_worker(n: BlockNumberFor<T>) {
        // Check pending transactions every block for real-time monitoring
        Self::check_pending_transactions_offchain().ok();

        // FSA offchain submission: detect signing sessions with aggregated signatures and
        // outstanding FsaTransactionRequests, submit to chain RPC and then emit unsigned tx.
        {
            let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
            if signer.can_sign() {
                for (session_id, session) in SigningSessions::<T>::iter() {
                    if session.aggregated_sig.is_none() { continue; }
                    if let Some((_, chain_id, tx_data_bounded)) = FsaTransactionRequests::<T>::get(&session.request_id) {
                        if let Some(signature) = &session.aggregated_sig {
                            let tx_bytes = tx_data_bounded.clone().into_inner();
                            if let Some(tx_hash) = Self::submit_signed_transaction(session_id, chain_id, &tx_bytes, signature) {
                                let _ = signer.send_unsigned_transaction(
                                    |acct| crate::payloads::SubmitFsaTransactionPayload::<T> {
                                        session_id,
                                        request_id: session.request_id,
                                        chain_id,
                                        tx_hash: tx_hash.clone(),
                                        nft_id: session.nft_id.clone(),
                                        public: acct.public.clone(),
                                    },
                                    |payload, signature| Call::submit_fsa_transaction_unsigned { payload, signature },
                                );
                            } else {
                                // We track this as failed using
                                let _ = signer.send_unsigned_transaction(
                                    |acct| crate::payloads::FailMultiChainTransactionPayload::<T> {
                                        request_id: session.request_id,
                                        public: acct.public.clone(),
                                    },
                                    |payload, signature| Call::fail_multi_chain_transaction_unsigned { payload, signature },
                                );

                                log::error!("[FSA] Failed to submit signed tx for session {} offchain", session_id);
                            }
                        }
                    }
                }
            } else {
                log::debug!("[FSA] No signer available for FSA submission");
            }
        }

        // We still only run heavier logic every 10 blocks, but OPOC processing must not depend on validator changes.
        if n % 10u32.into() == 0u32.into() {
            // Update ActiveValidators whenever the session validator set differs from stored state.
            let current_validators = pallet_session::Validators::<T>::get();
            let stored_validators = ActiveValidators::<T>::get();

            // Detect difference (order-insensitive) OR presence of any validator without an ID.
            use sp_std::collections::btree_set::BTreeSet;
            let curr_set: BTreeSet<_> = current_validators.iter().collect();
            let stored_set: BTreeSet<_> = stored_validators.iter().collect();
            let sets_differ = curr_set != stored_set;

            // Track validators missing IDs so that the extrinsic will assign them on-chain.
            let mut missing_id = false;
            for v in current_validators.iter() { if !ValidatorIds::<T>::contains_key(v) { missing_id = true; break; } }

            if sets_differ || missing_id {
                log::info!(
                    "[TSS] Detected validator set change (sets_differ: {}, missing_id: {}): stored_len={}, current_len={}",
                    sets_differ, missing_id, stored_validators.len(), current_validators.len()
                );
                let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
                if signer.can_sign() {
                    let all_validators = current_validators.clone();
                    let _res = signer.send_unsigned_transaction(
                        |acct| UpdateValidatorsPayload::<T> { validators: all_validators.clone(), public: acct.public.clone() },
                        |payload, signature| Call::update_validators { payload, signature },
                    );
                    // We rely on on-chain execution to prune removed validators. Log for debugging.
                } else {
                    log::error!("TSS: No accounts available to sign update_validators");
                }
            } else {
                log::debug!("[TSS] Validator set unchanged; no update_validators extrinsic sent");
            }

            // Always attempt to process OPOC requests on the cadence
            match Self::process_opoc_requests() {
                Ok((requests, last_id_u256)) => {
                    let mut max_request_id = U256::zero();
                    for (request_id, (nft_id_u256, chain_id, tx_bytes)) in requests.clone() {
                        let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
                        if !signer.can_sign() {
                            log::error!("TSS: No accounts available to sign create_signing_session");
                            break; 
                        }
                        let message = match BoundedVec::try_from(tx_bytes) { Ok(m) => m, Err(_) => { log::error!("TSS: Failed to convert tx bytes to BoundedVec"); continue; } };
                        // Duplicate detection via request_id only
                        let mut duplicate = false;
                        for (_sid, existing) in SigningSessions::<T>::iter() {
                            if existing.request_id == request_id && matches!(existing.state, SessionState::SigningInProgress) { duplicate = true; break; }
                        }
                        if duplicate { 
                            log::debug!("[TSS] Skipping unsigned create_signing_session because one already exists for request_id {:?}", request_id);
                            continue; 
                        }
                        let _ = signer.send_unsigned_transaction(
                            |acct| CreateSigningSessionPayload::<T> { request_id, nft_id: nft_id_u256, chain_id, message: message.clone(), public: acct.public.clone() },
                            |payload, signature| Call::create_signing_session_unsigned { payload, signature },
                        );
                        if request_id > max_request_id { max_request_id = request_id; }
                    }

                    if requests.is_empty() {
                        max_request_id = last_id_u256;
                    }

                    // After submitting all signing session creation extrinsics, submit a single extrinsic updating LastOpocRequestId to the highest processed id
                    if max_request_id > U256::zero() {
                        let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
                        if signer.can_sign() {
                            let _ = signer.send_unsigned_transaction(
                                |acct| UpdateLastOpocRequestIdPayload::<T> { last_request_id: last_id_u256.max(max_request_id), public: acct.public.clone() },
                                |payload, signature| Call::update_last_opoc_request_id_unsigned { payload, signature },
                            );
                        }
                    }
                }
                Err(e) => {
                    // Still persist a zero update if appropriate to prevent tight looping on errors? We skip.
                    log::debug!("TSS: No OPOC requests processed this interval: {:?}", e);
                }
            }
        }

        // Rest of your existing offchain worker logic
        let stored_validators = ActiveValidators::<T>::get();
        if stored_validators.len() > 0 {
            // After primary logic, perform nonce gap detection every 20 blocks to avoid spam
            if n % 20u32.into() == 0u32.into() {
                Self::detect_and_fill_nonce_gaps_offchain();
            }
            return;
        }
    }

    // Add on_initialize hook to handle validator initialization
    fn on_initialize(n: BlockNumberFor<T>) -> frame_support::weights::Weight {
        // Check if validator IDs have been initialized
        if NextValidatorId::<T>::get() == 0 {
            // Initialize with ID 1
            NextValidatorId::<T>::put(1);
        }

        // Check expired sessions 
        Pallet::<T>::check_expired_sessions(n).ok();

        // Process any pending TSS offences
        Pallet::<T>::process_pending_tss_offences().ok();

    // Expire stale signing sessions
        const MAX_EXPIRE_PER_BLOCK: u32 = 50; // limit weight
        let mut expired = 0u32;
        for (sid, expiry_block) in SigningSessionExpiry::<T>::iter() {
            if expired >= MAX_EXPIRE_PER_BLOCK { break; }
            if expiry_block <= n {
                if let Some(mut sess) = SigningSessions::<T>::get(sid) {
                    if matches!(sess.state, SessionState::SigningInProgress) && sess.aggregated_sig.is_none() {
                        sess.state = SessionState::SigningExpired; // mark as expired
                        SigningSessions::<T>::insert(sid, sess);
                        Self::deposit_event(Event::SigningExpired(sid));
                        // Keep the expiry entry for audit or remove it; remove to shrink storage.
                        SigningSessionExpiry::<T>::remove(sid);
                        // GC: clear partial ProposedSignatures votes for expired session
                        let _ = ProposedSignatures::<T>::clear_prefix(sid, u32::MAX, None);
                        expired += 1;
                    }
                } else {
                    SigningSessionExpiry::<T>::remove(sid); // cleanup dangling
                }
            }
        }

    // FSA processing moved to offchain worker (unsigned extrinsics); no on-chain direct call


        // Report count reset
        let previous_era = Pallet::<T>::previous_era();
        let current_era = Pallet::<T>::get_current_era().unwrap_or(0);


        // Check if the current era is different from the previous one
        if current_era != previous_era {
            // Reset report counts for all validators at the end of an era
            Pallet::<T>::reset_validator_report_counts().ok();
            
            // Handle validator changes at era end
            Pallet::<T>::handle_era_transition(current_era).ok();
            
            // Update the previous era to the current one
            PreviousEra::<T>::put(current_era);
        }
        
        // Return weight for this operation
        // We add additional weight for processing pending offences and FSA operations
        let pending_offences_count = PendingTssOffences::<T>::iter().count() as u64;
        let completed_signatures_count = SigningSessions::<T>::iter()
            .filter(|(_, session)| session.aggregated_sig.is_some())
            .count() as u64;
        let pending_transactions_count = PendingTransactions::<T>::iter().count() as u64;
        
        let base_weight = T::DbWeight::get().reads(5) + T::DbWeight::get().writes(3);
        
        // Add additional weight for each operation
        let total_operations = pending_offences_count + completed_signatures_count + pending_transactions_count;
        if total_operations > 0 {
            base_weight.saturating_add(
                T::DbWeight::get().reads(total_operations * 2) 
                .saturating_add(T::DbWeight::get().writes(total_operations))
            )
        } else {
            base_weight
        }
    }
    }
}

impl<T: Config> Pallet<T> {

    /// Mark that a reshare used an existing aggregated public key from `old_id` and
    /// finalize the `new_id` DKG as complete while marking `old_id` as superseded.
    /// This mirrors parts of `finalize_dkg_session` but avoids re-checking proposals since
    /// the aggregated key is preserved across resharing.
    pub fn complete_reshare_session(new_id: SessionId) -> DispatchResult {
        // Ensure new session exists
        let mut new_session = DkgSessions::<T>::get(new_id).ok_or(Error::<T>::DkgSessionNotFound)?;

        // Capture NFT id for lookup of prior completed sessions
        let nft_id = new_session.nft_id.clone();

        // Set new session state to complete
        new_session.state = SessionState::DKGComplete;
        DkgSessions::<T>::insert(new_id, new_session.clone());

        // Find the most recent completed DKG session for this NFT (other than new_id)
        let maybe_prev = DkgSessions::<T>::iter()
            .filter(|(id, s)| *id != new_id && s.nft_id == nft_id && s.state == SessionState::DKGComplete)
            .max_by_key(|(id, _)| *id)
            .map(|(id, _)| id);

        // If a previous aggregated key exists, copy it to the new session
        if let Some(prev_id) = maybe_prev {
            if let Some(agg) = AggregatedPublicKeys::<T>::get(prev_id) {
                AggregatedPublicKeys::<T>::insert(new_id, agg.clone());
            }
        }

        // Mark other completed sessions for same NFT as superseded
        if let Some(current_session) = DkgSessions::<T>::get(new_id) {
            for (other_id, mut other_session) in DkgSessions::<T>::iter() {
                if other_id != new_id
                    && other_session.nft_id == current_session.nft_id
                    && other_session.state == SessionState::DKGComplete
                {
                    other_session.state = SessionState::DKGSuperseded;
                    DkgSessions::<T>::insert(other_id, other_session);
                    Self::deposit_event(Event::DKGSuperseded(other_id));
                }
            }
        }

        // Emit completion event for new session with aggregated key if present
        if let Some(bounded) = AggregatedPublicKeys::<T>::get(new_id) {
            Self::deposit_event(Event::DKGCompleted(new_id, bounded));
        } 

        Ok(())
    }

    // ------------------- Internal Nonce Helpers -------------------
    fn allocate_next_nonce_internal(nft_id: &NftId, chain_id: u32) -> Result<u64, Error<T>> {
        ensure!(Self::is_chain_supported(chain_id), Error::<T>::UnsupportedChain);
        let mut result: Option<u64> = None;
        NonceStates::<T>::mutate(nft_id, chain_id, |state| {
            let next = state.last_allocated.map(|v| v + 1).unwrap_or(0);
            let window = match (state.last_accepted, state.last_allocated) {
                (Some(acc), Some(alloc)) => alloc.saturating_sub(acc),
                (None, Some(alloc)) => alloc + 1,
                _ => 0,
            };
            let max_window = <crate::types::MaxPendingNonces as Get<u32>>::get() as u64;
            if window >= max_window { return; }
            if !state.pending.iter().any(|p| p.nonce == next) {
                let entry = crate::types::PendingNonce { nonce: next, status: crate::types::PendingStatus::Allocated };
                if state.pending.try_push(entry).is_err() { return; }
            }
            state.last_allocated = Some(next);
            result = Some(next);
        });
        let nonce = result.ok_or(Error::<T>::PendingStorageFull)?;
        Self::deposit_event(Event::NonceAllocated(nft_id.clone(), chain_id, nonce));
        Ok(nonce)
    }

    /// Offchain: scan NonceStates and compare internal last_allocated with RPC account nonce; queue empty tx if gap persists.
    fn detect_and_fill_nonce_gaps_offchain() {
        use crate::multichain::MultiChainRpcClient;
    use ethereum_types::U256 as U256Core;
        // Iterate all (nft_id, chain_id) nonce states; this can be heavy -> early exit after limited operations
        const MAX_CHECKS: usize = 25; // safety cap per invocation
        let mut checked = 0usize;
        for (nft_id, chain_id, state) in NonceStates::<T>::iter() {
            if checked >= MAX_CHECKS { break; }
            checked += 1;
            let Some(last_alloc) = state.last_allocated else { continue; };
            // Derive 'from' address from nft_id for RPC query (reuse helper)
            let from_addr = crate::fsa::derive_from_address::<T>(nft_id.clone());
            let addr_hex = match from_addr { Some(s) => s, None => continue };
            // Fetch chain config + chain nonce
            let chain_cfg = if let Ok(cfg) = MultiChainRpcClient::get_chain_config(chain_id) { cfg } else { continue; };
            let chain_nonce = match MultiChainRpcClient::get_account_nonce(&chain_cfg, &addr_hex) { Ok(n) => n, Err(_) => continue };
            // If chain nonce already ahead or equal, no gap (internal last_alloc should never be < chain_nonce)
            if chain_nonce >= last_alloc + 1 { continue; }
            // chain reports lower -> gap; emit detection event via unsigned extrinsic? we only log and use local signer if available
            log::warn!("[nonce-gap] Detected gap for nft {:?} chain {} internal_last_alloc={} chain_nonce={} -> queuing filler", nft_id.clone(), chain_id, last_alloc, chain_nonce);
            // Attempt to send empty filler transaction(s) for each missing nonce up to last_alloc inclusive; limit to 3 per cycle
            let mut to_fill = Vec::new();
            let mut nonce_cursor = chain_nonce; // chain next nonce to use
            while nonce_cursor < last_alloc + 1 && to_fill.len() < 3 { // +1 because last_alloc was allocated but not on-chain
                to_fill.push(nonce_cursor);
                nonce_cursor += 1;
            }
            if to_fill.is_empty() { continue; }
            // Build minimal 0-value legacy transactions (could choose EIP-1559) with empty data
            let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
            if !signer.can_sign() { continue; }
            if signer.can_sign() {
                for nonce in to_fill {
                    if let Some(addr_hex_ref) = addr_hex.strip_prefix("0x") {
                        let mut to_addr = String::from("0x");
                        to_addr.push_str(addr_hex_ref);
                        let empty: [u8;0] = [];
                        // Build preimage to use as message so deterministic signature occurs
                        if let Ok(preimage) = crate::multichain::TransactionBuilder::build_ethereum_transaction(&to_addr, 0u64, &empty, 21_000, 1_000_000_000, nonce, chain_id) {
                            // Derive synthetic request id: keccak256("gap"||nft_bytes||chain_id||nonce)
                            use sp_io::hashing::keccak_256;
                            let mut seed: Vec<u8> = b"gap".to_vec();
                            seed.extend_from_slice(&nft_id.clone().into_inner());
                            seed.extend_from_slice(&chain_id.to_le_bytes());
                            seed.extend_from_slice(&nonce.to_le_bytes());
                            let hash = keccak_256(&seed);
                            let req_id = U256Core::from_big_endian(&hash);
                            // Avoid duplicate filler sessions
                            let mut exists = false;
                            for (_sid, sess) in SigningSessions::<T>::iter() { if sess.request_id == req_id { exists = true; break; } }
                            if exists { continue; }
                            // Convert nft_id bytes back to U256 for payload
                            let mut nft_bytes_arr = [0u8;32];
                            let raw = nft_id.clone().into_inner();
                            let copy_len = core::cmp::min(32, raw.len());
                            nft_bytes_arr[..copy_len].copy_from_slice(&raw[..copy_len]);
                            let nft_u256 = U256Core::from_little_endian(&nft_bytes_arr);
                            if let Ok(msg_bv) = BoundedVec::try_from(preimage.clone()) {
                                let _ = signer.send_unsigned_transaction(
                                    |acct| crate::payloads::GapFillerSigningSessionPayload::<T> { request_id: req_id, nft_id: nft_u256, chain_id, nonce, message: msg_bv.clone(), public: acct.public.clone() },
                                    |payload, signature| Call::create_gap_filler_signing_session_unsigned { payload, signature },
                                );
                                Self::deposit_event(Event::NonceGapFillerQueued(nft_id.clone(), chain_id, nonce));
                            }
                        }
                    }
                }
            }
            Self::deposit_event(Event::NonceGapDetected(nft_id.clone(), chain_id, last_alloc, chain_nonce));
        }
    }

    fn mark_nonce_accepted_internal(
        nft_id: &NftId,
        chain_id: u32,
        nonce: u64,
        tx_hash: &BoundedVec<u8, crate::types::MaxTxHashSize>
    ) -> Result<(), Error<T>> {
        ensure!(Self::is_chain_supported(chain_id), Error::<T>::UnsupportedChain);
        let mut advanced_to: Option<u64> = None;
        let mut found = false;
        NonceStates::<T>::mutate(nft_id, chain_id, |state| {
            for entry in state.pending.iter_mut() {
                if entry.nonce == nonce { entry.status = crate::types::PendingStatus::Accepted(tx_hash.clone()); found = true; break; }
            }
            if !found { return; }
            loop {
                let target = state.last_accepted.map(|v| v + 1).unwrap_or(0);
                let ok = state.pending.iter().find(|p| p.nonce == target && matches!(p.status, crate::types::PendingStatus::Accepted(_)) ).is_some();
                if ok { state.last_accepted = Some(target); advanced_to = state.last_accepted; } else { break; }
            }
            if let Some(acc) = state.last_accepted { state.pending.retain(|p| p.nonce > acc); }
        });
        ensure!(found, Error::<T>::NonceNotAllocated);
        Self::deposit_event(Event::NonceAccepted(nft_id.clone(), chain_id, nonce, tx_hash.clone().into_inner()));
        if let Some(acc) = advanced_to { Self::deposit_event(Event::NonceWindowPruned(nft_id.clone(), chain_id, acc)); }
        Ok(())
    }
    /// Multi-chain transaction submission function
    /// Submits a signed transaction to the specified blockchain network via Ankr RPC
    pub fn submit_multi_chain_transaction_to_chain(
        chain_id: u32,
        signed_transaction: &[u8],
    ) -> Result<crate::types::RpcResponse, &'static str> {
        use crate::fsa::submit_transaction_to_chain;
        
        log::info!("Submitting multi-chain transaction to chain ID: {}", chain_id);
        
        submit_transaction_to_chain(chain_id, signed_transaction)
            .map_err(|e| {
                log::error!("Failed to submit transaction: {:?}", e);
                "Failed to submit multi-chain transaction"
            })
    }

    /// Check the status of a transaction on a specific blockchain
    pub fn check_multi_chain_transaction_status_on_chain(
        chain_id: u32,
        tx_hash: &str,
    ) -> Result<crate::types::RpcResponse, &'static str> {
        use crate::fsa::check_transaction_status;
        
        log::info!("Checking transaction status for hash: {} on chain ID: {}", tx_hash, chain_id);
        
        check_transaction_status(chain_id, tx_hash)
            .map_err(|e| {
                log::error!("Failed to check transaction status: {:?}", e);
                "Failed to check transaction status"
            })
    }

    /// Get supported chain configurations
    pub fn get_supported_chains() -> Vec<(u32, &'static str)> {
        use crate::multichain::SupportedChain;
        
        vec![
            (SupportedChain::Ethereum.get_chain_id(), "Ethereum"),
            (SupportedChain::BinanceSmartChain.get_chain_id(), "Binance Smart Chain"),
            (SupportedChain::Polygon.get_chain_id(), "Polygon"),
            (SupportedChain::Avalanche.get_chain_id(), "Avalanche"),
            (SupportedChain::Arbitrum.get_chain_id(), "Arbitrum"),
            (SupportedChain::Optimism.get_chain_id(), "Optimism"),
            (SupportedChain::Fantom.get_chain_id(), "Fantom"),
            (SupportedChain::Base.get_chain_id(), "Base"),
        ]
    }

    /// Report TSS offence from client (used by runtime)
    pub fn report_tss_offence_from_client(
        session_id: SessionId,
        offence_type: TssOffenceType,
        offenders: Vec<[u8; 32]>,
    ) -> DispatchResult {
        log::info!("[TSS] Reporting offence from client: {:?} for session {} with {} offenders", 
            offence_type, session_id, offenders.len());

        let offenders_count = offenders.len() as u32;

        // Convert Vec<[u8; 32]> to Vec<T::AccountId>
        let account_offenders: Vec<T::AccountId> = offenders
            .into_iter()
            .map(|bytes| {
                use sp_core::crypto::AccountId32;
                // Convert [u8; 32] to AccountId32 and then to T::AccountId
                let account_id32 = AccountId32::from(bytes);
                T::AccountId::decode(&mut &account_id32.encode()[..]).unwrap_or_else(|_| {
                    // If decoding fails, create a placeholder AccountId
                    T::AccountId::decode(&mut &[0u8; 32][..]).unwrap()
                })
            })
            .collect();

        // Convert Vec to BoundedVec
        let bounded_offenders: BoundedVec<T::AccountId, T::MaxNumberOfShares> = account_offenders
            .try_into()
            .map_err(|_| Error::<T>::InvalidParticipantsCount)?;

        // Store the offence for processing
    // We don't know an on-chain reporter here; use zero AccountId placeholder (won't be used for rewards)
    // Fallback: select first offender as synthetic reporter if available; else abort
    let synthetic_reporter = bounded_offenders.get(0).cloned().ok_or(Error::<T>::InvalidParticipantsCount)?;
    PendingTssOffences::<T>::insert(session_id, (offence_type.clone(), synthetic_reporter, bounded_offenders));

        // Emit event
        Self::deposit_event(Event::OffenceReported(
            offence_type,
            session_id,
            offenders_count,
        ));

        Ok(())
    }

    /// Validate if a chain ID is supported
    pub fn is_chain_supported(chain_id: u32) -> bool {
        use crate::multichain::MultiChainRpcClient;
        
        MultiChainRpcClient::get_chain_config(chain_id).is_ok()
    }

    /// Build a transaction for a specific chain
    pub fn build_chain_transaction(
        chain_id: u32,
        to: &str,
        value: u64,
        data: &[u8],
        gas_limit: u64,
        gas_price: u64,
        nonce: u64,
    ) -> Result<Vec<u8>, &'static str> {
        use crate::multichain::TransactionBuilder;
        
        // Validate chain is supported
        if !Self::is_chain_supported(chain_id) {
            return Err("Unsupported chain ID");
        }

        log::info!("Building transaction for chain ID: {}", chain_id);
        
        // For now, we support Ethereum-compatible chains
        match chain_id {
            1 | 56 | 137 | 43114 | 42161 | 10 | 250 | 4386 | 8453 => {
                TransactionBuilder::build_ethereum_transaction(
                    to, value, data, gas_limit, gas_price, nonce, chain_id
                ).map_err(|_| "Failed to build transaction")
            }
            _ => Err("Chain not supported for transaction building"),
        }
    }

    /// Process any pending TSS offences stored in the PendingTssOffences storage
    pub fn process_pending_tss_offences() -> DispatchResult {
        let pending: Vec<(SessionId, (TssOffenceType, T::AccountId, BoundedVec<T::AccountId, T::MaxNumberOfShares>))> =
            PendingTssOffences::<T>::iter().collect();
        if pending.is_empty() { return Ok(()); }
        log::info!("[TSS] Processing {} pending offences", pending.len());

        for (session_id, (offence_type, reporter, offenders)) in pending.into_iter() {
            // Acquire DKG session for validator set size; skip if missing
            let maybe_session = DkgSessions::<T>::get(session_id);
            let validator_set_count = maybe_session.as_ref().map(|s| s.participants.len() as u32).unwrap_or(0);
            let session_index = pallet_session::Pallet::<T>::current_index();

            // Build identification tuples, filter duplicates & previously processed
            let mut id_tuples: Vec<pallet_session::historical::IdentificationTuple<T>> = Vec::new();
            for acc in offenders.into_inner().into_iter() {
                let flag_key = (acc.clone(), offence_type.encode());
                if ProcessedOffenderFlags::<T>::contains_key(session_id, flag_key.clone()) { continue; }
                // Use FullIdentificationOf converter to obtain exposure / identification
                if let Some(full) = <T as pallet_session::historical::Config>::FullIdentificationOf::convert(acc.clone()) {
                    id_tuples.push((acc.clone(), full));
                    ProcessedOffenderFlags::<T>::insert(session_id, flag_key, ());
                } else {
                    log::warn!("[TSS] Could not fetch full identification for offender (likely not a current validator)");
                }
            }
            if id_tuples.is_empty() {
                PendingTssOffences::<T>::remove(session_id);
                continue;
            }
            let offence = TssReportedOffence::<T> {
                offence_type: offence_type.clone(),
                session_index,
                validator_set_count,
                offenders: id_tuples.clone(),
            };
            // Report to staking offences pallet
            // Use the TSS pallet's OffenceReporter (disambiguate vs engine pallet)
            // if let Err(e) = <T as pallet::Config>::OffenceReporter::report_offence(vec![reporter.clone()], offence) {
            //     log::error!("[TSS] Failed to report offence to offences pallet: {:?}", e);
            // } else {
            //     // Emit per-offender slashed event (actual slashing managed by offences pallet / staking economic logic)
            //     for (acc, _) in id_tuples.into_iter() {
            // Only after block 530.000
 
                for (acc, _) in id_tuples.into_iter() {
                    Self::deposit_event(Event::ValidatorSlashed(acc, offence_type.clone(), session_id));
                }
   
            PendingTssOffences::<T>::remove(session_id);
        }
        Ok(())
    }

    /// Helper function to get pending transaction data for a request ID
    pub fn get_pending_transaction_data_by_request(request_id: &U256) -> Option<(NftId, u32, Vec<u8>)> {
        FsaTransactionRequests::<T>::get(request_id).map(|(nft_id, chain_id, bounded_data)| {
            (nft_id, chain_id, bounded_data.into_inner())
        })
    }

    /// Process completed signatures and submit transactions
    pub fn process_completed_signatures() -> DispatchResult {
        // Get all signing sessions with completed signatures
        let completed_sessions: Vec<(SessionId, SigningSession)> = SigningSessions::<T>::iter()
            .filter(|(_, session)| session.aggregated_sig.is_some())
            .collect();

        if completed_sessions.is_empty() {
            return Ok(());
        }

        log::info!("[FSA] Processing {} completed signatures for transaction submission", completed_sessions.len());

        for (session_id, session) in completed_sessions {
            let signature = match session.aggregated_sig {
                Some(sig) => sig,
                None => continue, // Should not happen due to filter, but safety check
            };
            // Get FSA transaction request data from the session's request_id (updated logic)
            if let Some((_, chain_id, tx_data_bounded)) = FsaTransactionRequests::<T>::get(&session.request_id) {
                let tx_data = tx_data_bounded.into_inner();
                if let Some(tx_hash) = Self::submit_signed_transaction(session_id, chain_id, &tx_data, &signature) {
                
                // Add to pending transactions for status tracking
                let current_block = frame_system::Pallet::<T>::block_number();
                let max_wait_blocks = 300u32; // Wait up to 15 minutes, assuming 3 seconds per block, 20 blocks per minute

                // tx_hash is already BoundedVec<u8, MaxTxHashSize>
                PendingTransactions::<T>::insert(chain_id, tx_hash.clone(), (current_block, max_wait_blocks));
                
                // Update multi-chain transaction status
                MultiChainTransactions::<T>::insert(chain_id, tx_hash.clone(), crate::types::TransactionStatus::Submitted);
                
                Self::deposit_event(Event::MultiChainTransactionSubmitted(chain_id, tx_hash.to_vec()));
                log::info!("[FSA] Transaction submitted for session {} on chain {}", session_id, chain_id);
                } else {
                    log::error!("[FSA] Failed to submit transaction for session {}", session_id);
                    // Keep the signature for retry on next block
                }
                
                // Clear processed FSA transaction requests for this session
                FsaTransactionRequests::<T>::remove(&session.request_id);
            }
        }

        Ok(())
    }

    /// Check pending transactions for confirmation status (OFFCHAIN WORKER VERSION)
    pub fn check_pending_transactions_offchain() -> Result<(), &'static str> {
        let current_block = frame_system::Pallet::<T>::block_number();
        let pending_txs: Vec<(u32, BoundedVec<u8, crate::types::MaxTxHashSize>, (BlockNumberFor<T>, u32))> = 
            PendingTransactions::<T>::iter().collect();

        if pending_txs.is_empty() {
            return Ok(());
        }

        log::info!("[OFFCHAIN] Checking {} pending transactions for confirmation", pending_txs.len());

        for (chain_id, tx_hash_bounded, (submission_block, max_wait_blocks)) in pending_txs {
            let blocks_waited = current_block.saturating_sub(submission_block);
            let tx_hash_bytes = tx_hash_bounded.as_slice();

            if blocks_waited.saturated_into::<u32>() > max_wait_blocks {
                // Transaction timed out
                log::warn!("[OFFCHAIN] Transaction on chain {} timed out after {} blocks", chain_id, blocks_waited.saturated_into::<u32>());
                // Submit unsigned tx to mark failure
                let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
                if signer.can_sign() {
                    let tx_hash_clone = tx_hash_bounded.clone();
                    let _ = signer.send_unsigned_transaction(
                        |acct| crate::payloads::TimeoutPendingTransactionPayload::<T> { chain_id, tx_hash: tx_hash_clone.clone(), public: acct.public.clone() },
                        |payload, signature| Call::timeout_pending_transaction_unsigned { payload, signature }
                    );
                }
                continue;
            }

            // Check transaction status on chain - convert to hex string
            let mut tx_hash_hex = sp_std::vec![0u8; tx_hash_bytes.len() * 2 + 2];
            tx_hash_hex[0] = b'0';
            tx_hash_hex[1] = b'x';
            for (i, byte) in tx_hash_bytes.iter().enumerate() {
                let hex_chars = [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f'];
                tx_hash_hex[2 + i * 2] = hex_chars[(byte >> 4) as usize];
                tx_hash_hex[2 + i * 2 + 1] = hex_chars[(byte & 0xf) as usize];
            }
            let tx_hash_str = core::str::from_utf8(&tx_hash_hex).unwrap_or("invalid_hash");
            
            // This is where we can actually make HTTP calls to check status
            match Self::check_transaction_status_on_chain_offchain(chain_id, tx_hash_str) {
                Some(status) => {
                    match status {
                        crate::types::TransactionStatus::Confirmed => {
                            log::info!("[OFFCHAIN] ✅ Transaction on chain {} confirmed: {}", chain_id, tx_hash_str);
                        }
                        crate::types::TransactionStatus::Failed => {
                            log::error!("[OFFCHAIN] ❌ Transaction on chain {} failed: {}", chain_id, tx_hash_str);
                        }
                        _ => {
                            log::debug!("[OFFCHAIN] ⏳ Transaction on chain {} still pending: {}", chain_id, tx_hash_str);
                        }
                    }
                }
                None => {
                    log::error!("[OFFCHAIN] ❌ Failed to check status for transaction on chain {}: {}", chain_id, tx_hash_str);
                }
            }
        }

        Ok(())
    }

    /// Check pending transactions for confirmation status (ON-CHAIN VERSION - DEPRECATED)
    pub fn check_pending_transactions() -> DispatchResult {
        let current_block = frame_system::Pallet::<T>::block_number();
        let pending_txs: Vec<(u32, BoundedVec<u8, crate::types::MaxTxHashSize>, (BlockNumberFor<T>, u32))> = 
            PendingTransactions::<T>::iter().collect();

        if pending_txs.is_empty() {
            return Ok(());
        }

        log::info!("[FSA] Checking {} pending transactions for confirmation", pending_txs.len());

        for (chain_id, tx_hash_bounded, (submission_block, max_wait_blocks)) in pending_txs {
            let blocks_waited = current_block.saturating_sub(submission_block);
            // Convert tx_hash_bounded to &str for logging
            let tx_hash_bytes = tx_hash_bounded.as_slice();

            if blocks_waited.saturated_into::<u32>() > max_wait_blocks {
                // Transaction timed out
                log::warn!("[FSA] Transaction on chain {} timed out after {} blocks", chain_id, blocks_waited.saturated_into::<u32>());
                
                PendingTransactions::<T>::remove(chain_id, &tx_hash_bounded);
                MultiChainTransactions::<T>::insert(chain_id, tx_hash_bounded.clone(), crate::types::TransactionStatus::Failed);
                Self::deposit_event(Event::MultiChainTransactionFailed(chain_id, tx_hash_bounded.to_vec()));
                continue;
            }

            // Build canonical hex hash string WITHOUT double-encoding.
            // Cases:
            //  * Stored value already ASCII: length 66 and starts with "0x" -> use directly
            //  * Stored value raw 32 bytes -> hex encode to 0x + 64 chars
            //  * Fallback: attempt UTF-8 interpret, else mark invalid.
            let tx_hash_str: sp_std::borrow::Cow<'_, str> = if tx_hash_bytes.len() == 66 && tx_hash_bytes.starts_with(b"0x") {
                // Already canonical ASCII.
                match core::str::from_utf8(&tx_hash_bytes) { Ok(s) => sp_std::borrow::Cow::Borrowed(s), Err(_) => sp_std::borrow::Cow::Owned(String::from("invalid_hash")) }
            } else if tx_hash_bytes.len() == 32 {
                // Raw 32 bytes -> encode
                let mut out = sp_std::vec![0u8; 66];
                out[0] = b'0'; out[1] = b'x';
                const HEX: &[u8;16] = b"0123456789abcdef";
                for (i, b) in tx_hash_bytes.iter().enumerate() {
                    out[2 + i*2] = HEX[(b >> 4) as usize];
                    out[2 + i*2 + 1] = HEX[(b & 0x0f) as usize];
                }
                // Avoid requiring ToString trait in no_std by using From<&str> for String
                sp_std::borrow::Cow::Owned(unsafe { core::str::from_utf8_unchecked(&out) }.into())
            } else {
                // Previously we re-hex-encoded ASCII here causing double encoding; log and try to use as-is.
                if tx_hash_bytes.starts_with(b"0x") {
                    log::warn!("[FSA] Unexpected tx hash length {} starting with 0x; using as-is to avoid double encoding", tx_hash_bytes.len());
                    match core::str::from_utf8(&tx_hash_bytes) { Ok(s) => sp_std::borrow::Cow::Borrowed(s), Err(_) => sp_std::borrow::Cow::Owned(String::from("invalid_hash")) }
                } else {
                    log::warn!("[FSA] Non-standard stored tx hash length {}; attempting UTF-8 parse", tx_hash_bytes.len());
                    match core::str::from_utf8(&tx_hash_bytes) { Ok(s) => sp_std::borrow::Cow::Borrowed(s), Err(_) => sp_std::borrow::Cow::Owned(String::from("invalid_hash")) }
                }
            };
            let tx_hash_str = &*tx_hash_str;
            match Self::check_transaction_status_on_chain(chain_id, tx_hash_str) {
                Some(status) => {
                    match status {
                        crate::types::TransactionStatus::Confirmed => {
                            log::info!("[FSA] Transaction on chain {} confirmed", chain_id);
                            
                            PendingTransactions::<T>::remove(chain_id, &tx_hash_bounded);
                            MultiChainTransactions::<T>::insert(chain_id, tx_hash_bounded.clone(), crate::types::TransactionStatus::Confirmed);
                            Self::deposit_event(Event::MultiChainTransactionConfirmed(chain_id, tx_hash_bounded.to_vec()));
                        }
                        crate::types::TransactionStatus::Failed => {
                            log::error!("[FSA] Transaction on chain {} failed", chain_id);
                            
                            PendingTransactions::<T>::remove(chain_id, &tx_hash_bounded);
                            MultiChainTransactions::<T>::insert(chain_id, tx_hash_bounded.clone(), crate::types::TransactionStatus::Failed);
                            Self::deposit_event(Event::MultiChainTransactionFailed(chain_id, tx_hash_bounded.to_vec()));
                        }
                        _ => {
                            // Still pending, keep checking
                            log::debug!("[FSA] Transaction on chain {} still pending", chain_id);
                        }
                    }
                }
                None => {
                    log::error!("[FSA] Failed to check status for transaction on chain {}", chain_id);
                    // Keep in pending for retry
                }
            }
        }

        Ok(())
    }

    /// Submit a signed transaction to the specified chain
    /// Returns the transaction hash on success
    fn submit_signed_transaction(
        session_id: SessionId,
        chain_id: u32,
        tx_data: &[u8],
        signature: &crate::types::Signature,
    ) -> Option<BoundedVec<u8, crate::types::MaxTxHashSize>> {
        use crate::multichain::TransactionBuilder;
        // Expect 65-byte secp256k1 signature: r(32)||s(32)||recid(1)
        let sig_bytes = signature.as_slice();
        if sig_bytes.len() != 65 { 
            log::error!("[FSA] Invalid signature length {} for session {}", sig_bytes.len(), session_id);
            return None; 
        }
        let r = &sig_bytes[0..32];
        let s = &sig_bytes[32..64];
        let recid = sig_bytes[64];

        // Helper to convert big-endian 32 bytes into U256 minimal quantity
        let be32_to_u256 = |bytes: &[u8]| -> U256 { U256::from_big_endian(bytes) };
        let r_u = be32_to_u256(r);
        let s_u = be32_to_u256(s);

        // Detect transaction type (legacy preimage vs EIP-1559 preimage) and finalize
        let signed_transaction: Vec<u8> = if tx_data.first() == Some(&0x02) {
            // EIP-1559 preimage: 0x02 || RLP(9 items)
            // We must decode fields to reconstruct finalize. Simpler: parse with rlp::Rlp
            let rlp_slice = &tx_data[1..];
            let rlp = rlp::Rlp::new(rlp_slice);
            if !rlp.is_list() || rlp.item_count().unwrap_or(0) != 9 {
                log::error!("[FSA] Invalid EIP-1559 preimage structure for session {}", session_id);
                return None;
            }
            let chain_id_rlp: U256 = rlp.val_at(0).unwrap_or_else(|_| U256::from(chain_id));
            let nonce: U256 = rlp.val_at(1).unwrap_or_else(|_| U256::zero());
            let max_priority: U256 = rlp.val_at(2).unwrap_or_else(|_| U256::zero());
            let max_fee: U256 = rlp.val_at(3).unwrap_or_else(|_| U256::zero());
            let gas_limit: U256 = rlp.val_at(4).unwrap_or_else(|_| U256::zero());
            let to: ethereum_types::H160 = rlp.val_at(5).unwrap_or_else(|_| ethereum_types::H160::zero());
            let value: U256 = rlp.val_at(6).unwrap_or_else(|_| U256::zero());
            let data_bytes: Vec<u8> = rlp.val_at(7).unwrap_or_default();
            // access list at index 8 ignored (must be empty list per current builder)
            TransactionBuilder::eip1559_finalize_raw(
                to,
                value,
                &data_bytes,
                gas_limit,
                max_fee,
                max_priority,
                nonce,
                chain_id_rlp.as_u64(),
                r_u,
                s_u,
                recid,
            )
        } else {
            // Legacy preimage RLP expected with 9 items where last two are zero
            let rlp = rlp::Rlp::new(tx_data);
            if !rlp.is_list() || rlp.item_count().unwrap_or(0) != 9 {
                log::error!("[FSA] Invalid legacy preimage structure for session {}", session_id);
                return None;
            }
            let nonce: U256 = rlp.val_at(0).unwrap_or_else(|_| U256::zero());
            let gas_price: U256 = rlp.val_at(1).unwrap_or_else(|_| U256::zero());
            let gas_limit: U256 = rlp.val_at(2).unwrap_or_else(|_| U256::zero());
            let to: ethereum_types::H160 = rlp.val_at(3).unwrap_or_else(|_| ethereum_types::H160::zero());
            let value: U256 = rlp.val_at(4).unwrap_or_else(|_| U256::zero());
            let data_bytes: Vec<u8> = rlp.val_at(5).unwrap_or_default();
            let chain_id_rlp: U256 = rlp.val_at(6).unwrap_or_else(|_| U256::from(chain_id));
            TransactionBuilder::legacy_finalize_raw(
                to,
                value,
                &data_bytes,
                gas_limit,
                gas_price,
                nonce,
                chain_id_rlp.as_u64(),
                r_u,
                s_u,
                recid,
            )
        };

        // Submit via FSA module using finalized raw tx
        match crate::fsa::submit_transaction_to_chain(chain_id, &signed_transaction) {
            Ok(response) => {
                match response.tx_hash {
                    Some(hash) => {
                        log::info!("[FSA] Transaction submitted successfully for session {}", session_id);
                        // Convert string tx_hash to BoundedVec<u8>
                        let tx_hash_bytes = hash.as_bytes();
                        match BoundedVec::try_from(tx_hash_bytes.to_vec()) {
                            Ok(bounded_hash) => {
                                // mark nonce accepted if allocated
                                if let Some((stored_chain, stored_nonce)) = SigningSessionNonces::<T>::get(session_id) {
                                    if stored_chain == chain_id {
                                        let session_opt = SigningSessions::<T>::get(session_id);
                                        if let Some(sess) = session_opt {
                                            let _ = Self::mark_nonce_accepted_internal(&sess.nft_id, chain_id, stored_nonce, &bounded_hash);
                                        }
                                    }
                                }
                                Some(bounded_hash)
                            },
                            Err(_) => {
                                log::error!("[FSA] Transaction hash too long for BoundedVec");
                                None
                            }
                        }
                    },
                    None => {
                        log::error!("[FSA] Transaction submitted but no hash returned for session {}", session_id);
                        None
                    }
                }
            }
            Err(e) => {
                log::error!("[FSA] Transaction submission failed for session {}: {:?}", session_id, e);
                None
            }
        }
    }

    /// Check transaction status on a specific chain (OFFCHAIN WORKER VERSION)  
    fn check_transaction_status_on_chain_offchain(
        chain_id: u32,
        tx_hash: &str,
    ) -> Option<crate::types::TransactionStatus> {
        // Get chain configuration
        let chain_config = match crate::multichain::MultiChainRpcClient::get_chain_config(chain_id) {
            Ok(config) => config,
            Err(e) => {
                log::error!("[OFFCHAIN] Failed to get chain config for chain {}: {}", chain_id, e);
                return None;
            }
        };

        // Make the actual HTTP call to check transaction status
        match crate::multichain::MultiChainRpcClient::get_transaction_receipt(&chain_config, tx_hash) {
            Ok(response) => {
                log::info!("[OFFCHAIN] Transaction status response: {:?}", response.status);
                Some(response.status)
            }
            Err(e) => {
                log::error!("[OFFCHAIN] Failed to check transaction status: {}", e);
                None
            }
        }
    }

    /// Check transaction status on a specific chain (ON-CHAIN VERSION - DEPRECATED)
    fn check_transaction_status_on_chain(
        chain_id: u32,
        tx_hash: &str,
    ) -> Option<crate::types::TransactionStatus> {
        match crate::fsa::check_transaction_status(chain_id, tx_hash) {
            Ok(response) => Some(response.status),
            Err(e) => {
                log::error!("[FSA] Failed to check transaction status: {:?}", e);
                None
            }
        }
    }
}


sp_api::decl_runtime_apis! {
    pub trait TssApi {
        fn get_dkg_session_threshold(id: SessionId) -> u32;
        fn get_dkg_session_participants(id: SessionId) -> Vec<[u8; 32]>;
        fn get_dkg_session_participant_index(id: SessionId, account_id: [u8; 32]) -> u32;
        fn get_dkg_session_participants_count(id: SessionId) -> u16;
        fn get_dkg_session_old_participants(id: SessionId) -> Vec<[u8; 32]>;
        fn get_signing_session_message(id: SessionId) -> Vec<u8>;

        fn get_validator_id(account_id: [u8; 32]) -> Option<u32>;
        fn get_validator_by_id(id: u32) -> Option<[u8; 32]>;
        fn get_all_validator_ids() -> Vec<(u32, [u8; 32])>;

        fn report_participants(id: SessionId, reported_participants: Vec<[u8; 32]>);
        fn submit_dkg_result(
            session_id: SessionId,
            aggregated_key: Vec<u8>,
        );
        fn complete_reshare_session(session_id: SessionId);

        /// Report TSS offence from runtime API
        fn report_tss_offence(
            session_id: SessionId,
            offence_type: u8, // Encoded TssOffenceType
            offenders: Vec<[u8; 32]>,
        );
    }
}

impl<T: Config> uomi_primitives::TssInterface<T> for Pallet<T> {
    fn create_agent_wallet(nft_id: U256, threshold: u8) -> frame_support::pallet_prelude::DispatchResult {
        log::info!("TSS: Creating wallet for agent {}", nft_id);

        ensure!(threshold >= 50, frame_support::pallet_prelude::DispatchError::Other("Threshold must be at least 50%"));
        ensure!(threshold <= 100, frame_support::pallet_prelude::DispatchError::Other("Threshold must be at most 100%"));

        // Convert nft_id to BoundedVec
        let nft_id_bytes: Vec<u8> = nft_id.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
        let nft_id: crate::types::NftId = BoundedVec::try_from(nft_id_bytes)
            .map_err(|_| frame_support::pallet_prelude::DispatchError::Other("Invalid NFT ID"))?;
        // use none origin to avoid permission checks
        let origin = frame_system::RawOrigin::None.into();
        Pallet::<T>::create_dkg_session(
            origin,
            nft_id,
            80,
        )?;
        
        Ok(())
    }
    
    fn agent_wallet_exists(nft_id: U256) -> bool {
        log::info!("TSS: Checking if wallet exists for agent {}", nft_id);

        // Convert nft_id to BoundedVec
        let nft_id_bytes: Vec<u8> = nft_id.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
        let nft_id: crate::types::NftId = BoundedVec::try_from(nft_id_bytes)
            .map_err(|_| frame_support::pallet_prelude::DispatchError::Other("Invalid NFT ID"))
            .unwrap();

        // Check if the ProposedPublicKeys storage has any keys for this nft_id
        let exists = ProposedPublicKeys::<T>::iter_prefix(nft_id.clone()).next().is_some();
        log::info!("TSS: Wallet exists for agent {:?}: {}", nft_id, exists);
        exists
    }
    
    fn get_agent_wallet_address(nft_id: U256) -> Option<sp_core::H160> {
        log::info!("TSS: Getting wallet address for agent {}", nft_id);

        // Convert nft_id to BoundedVec
        let nft_id_bytes: Vec<u8> = nft_id.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
        let nft_id: crate::types::NftId = BoundedVec::try_from(nft_id_bytes)
            .map_err(|_| frame_support::pallet_prelude::DispatchError::Other("Invalid NFT ID"))
            .unwrap();

        // Use ProposedPublicKeys to get the address. ProposedPublicKeys key is a tuple of (nft_id, validator_id), so we need to take the value that has most votes
        let mut proposed_keys = ProposedPublicKeys::<T>::iter_prefix(nft_id)
            .map(|(_validator_id, key)| key)
            .collect::<Vec<crate::types::PublicKey>>();
        proposed_keys.sort_by(|a, b| a.len().cmp(&b.len()));
        if let Some(key) = proposed_keys.last() {
            // Decode the key to H160
            if let Ok(address) = sp_core::H160::decode(&mut &key[..]) {
                return Some(address);
            }
        }
        // log::warn!("TSS: No wallet address found for agent {:?}", nft_id);
        

        None
    }
}

