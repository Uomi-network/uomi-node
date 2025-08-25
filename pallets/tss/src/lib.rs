#![cfg_attr(not(feature = "std"), no_std)]
use sp_runtime::KeyTypeId;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

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
use sp_runtime::traits::{Saturating, SaturatedConversion};
use frame_system::offchain::SigningTypes;

pub use pallet::*;
use sp_std::vec;
use sp_std::vec::Vec;
use types::{SessionId, NftId};
pub use payloads::*;
pub use errors::*;
pub use utils::*;


/// A struct for the payload of the ReportTssOffence call
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
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
#[derive(RuntimeDebug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
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

/// TSS offence for slashing validators
#[derive(RuntimeDebug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct TssOffence<T: Config> {
    /// Type of offence
    pub offence_type: TssOffenceType,
    /// Session where the offence occurred
    pub session_id: SessionId,
    /// Session index for staking
    pub session_index: SessionIndex,
    /// Number of validators in the session
    pub validator_set_count: u32,
    /// The offending validator and their full identification
    pub offenders: Vec<(T::AccountId, <T as pallet_session::historical::Config>::FullIdentification)>,
}

impl<T: Config> Offence<T::AccountId> for TssOffence<T> {
    const ID: [u8; 16] = *b"tss:offence_____";
    type TimeSlot = SessionIndex;

    fn offenders(&self) -> Vec<T::AccountId> {
    self.offenders.iter().map(|(id, _)| id.clone()).collect()
    }

    fn session_index(&self) -> SessionIndex {
    self.session_index
    }

    fn validator_set_count(&self) -> u32 {
    self.validator_set_count
    }

    fn time_slot(&self) -> Self::TimeSlot {
    self.session_index
    }

    fn slash_fraction(&self, _offenders_count: u32) -> Perbill {
    match self.offence_type {
        TssOffenceType::DkgNonParticipation => Perbill::from_percent(1),
        TssOffenceType::SigningNonParticipation => Perbill::from_percent(1),
        TssOffenceType::InvalidCryptographicData => Perbill::from_percent(2),
        TssOffenceType::UnresponsiveBehavior => Perbill::from_percent(1),
    }
    }
}





#[frame_support::pallet]
pub mod pallet {

    use frame_system::offchain::{AppCrypto, CreateSignedTransaction};
    use sp_runtime::traits::IdentifyAccount;

    use crate::types::{MaxMessageSize, NftId, PublicKey, Signature};

    use super::*;
    
    // Re-export Verifier to make it accessible from pallet module
    pub use crate::utils::Verifier;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[derive(RuntimeDebug, Clone)]
    pub struct MaliciousBehaviourOffence<T: Config> {
    /// The session index in which the offence occurred.
    pub session_index: SessionIndex,
    /// The size of the validator set at the time of the offence.
    pub validator_set_count: u32,
    /// The offender's validator ID.
    pub offender: pallet_session::historical::IdentificationTuple<T>,
    }


    // Implementazione per Offence
    impl<T: Config> Offence<pallet_session::historical::IdentificationTuple<T>> for MaliciousBehaviourOffence<T> 
    where
    T: pallet_session::historical::Config,
    T: pallet_session::Config<ValidatorId = <T as frame_system::Config>::AccountId>,
    {
    const ID: [u8; 16] = *b"tss:offence_____";
    type TimeSlot = SessionIndex;
    
    fn offenders(&self) -> Vec<pallet_session::historical::IdentificationTuple<T>> {
        vec![self.offender.clone()]
    }
    
    fn session_index(&self) -> SessionIndex {
        self.session_index
    }
    
    fn validator_set_count(&self) -> u32 {
        self.validator_set_count
    }
    
    fn time_slot(&self) -> Self::TimeSlot {
        self.session_index
    }
    
    fn slash_fraction(&self, _offenders_count: u32) -> Perbill {
        // Ritorna 5% slash indipendentemente dal numero di offenders
        Perbill::from_percent(5)
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
        <Self as frame_system::Config>::AccountId,
        pallet_session::historical::IdentificationTuple<Self>,
        MaliciousBehaviourOffence<Self>
    >;
    }


    #[derive(Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq, Clone, Copy, PartialOrd)]
    pub enum SessionState {
    DKGCreated,
    DKGInProgress,
    DKGComplete,
    DKGFailed,
    SigningInProgress,
    SigningComplete,
    }

    #[derive(Encode, Decode, MaxEncodedLen, Debug, PartialEq, Eq, Clone, TypeInfo)] // IMPORTANT: Keep these derives
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

    #[derive(Encode, Decode, MaxEncodedLen, Debug, PartialEq, Eq, Clone, TypeInfo)]
    pub struct SigningSession {
    pub dkg_session_id: SessionId,
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
    pub type LastOpocRequestId<T: Config> = StorageValue<_, u32, ValueQuery>;

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
    (TssOffenceType, BoundedVec<T::AccountId, T::MaxNumberOfShares>),
    OptionQuery,
    >;

    // A storage to store temporarily proposed public keys generated from the DKG process associated with the session ID and validator ID
    #[pallet::storage]
    #[pallet::getter(fn proposed_public_keys)]
    pub type ProposedPublicKeys<T: Config> =
    StorageDoubleMap<_, Blake2_128Concat, NftId, Blake2_128Concat, u32, PublicKey, OptionQuery>;

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

    /// Storage for mapping NFT IDs to pending FSA transaction data
    /// Maps nft_id -> (chain_id, transaction_data)
    #[pallet::storage]
    #[pallet::getter(fn fsa_transaction_requests)]
    pub type FsaTransactionRequests<T: Config> =
    StorageMap<_, Blake2_128Concat, NftId, (u32, BoundedVec<u8, crate::types::MaxMessageSize>), OptionQuery>;


    /// Counter for generating unique request IDs
    #[pallet::storage]
    #[pallet::getter(fn next_request_id)]
    pub type NextRequestId<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Storage for tracking transaction nonces per chain per agent
    /// Maps (agent_nft_id, chain_id) -> nonce
    #[pallet::storage]
    #[pallet::getter(fn agent_nonces)]
    pub type AgentNonces<T: Config> =
    StorageDoubleMap<_, Blake2_128Concat, NftId, Blake2_128Concat, u32, u64, ValueQuery>;

    

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
    /// A new TSS key has been set.
    DKGSessionCreated(SessionId),
    DKGReshareSessionCreated(SessionId),
    SigningSessionCreated(SessionId, SessionId), // Signing session ID, DKG session ID
    DKGCompleted(SessionId, PublicKey),          // Aggregated public key
    SigningCompleted(SessionId, Signature),      // Final aggregated signature
    SignatureSubmitted(SessionId),               // When signature is stored
    ValidatorIdAssigned(T::AccountId, u32),      // Validator account, ID
    DKGFailed(SessionId),                        // DKG session failed
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
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
    #[pallet::weight(frame_support::weights::Weight::from_parts(10_000, 0))]
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

        let threshold = T::MinimumValidatorThreshold::get(); // percentage of validators needed to sign
        let required_validators = (total_validators * threshold) / 100;

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

    #[pallet::weight(frame_support::weights::Weight::from_parts(10_000, 0))]
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

    #[pallet::weight(frame_support::weights::Weight::from_parts(10_000, 0))]
    #[pallet::call_index(2)]
    pub fn create_signing_session(
        _origin: OriginFor<T>,
        nft_id: NftId,
        message: BoundedVec<u8, MaxMessageSize>,
    ) -> DispatchResult {
        // Find the DKG session with this NFT ID
        let mut dkg_session_id = None;
        for (id, session) in DkgSessions::<T>::iter() {
            if session.nft_id == nft_id {
                dkg_session_id = Some(id);
                break;
            }
        }

        let dkg_session_id = dkg_session_id.ok_or(Error::<T>::DkgSessionNotFound)?;

        // Ensure the DKG session is in the correct state
        let dkg_session =
            Self::get_dkg_session(dkg_session_id).ok_or(Error::<T>::DkgSessionNotFound)?;
        ensure!(
            dkg_session.state == SessionState::DKGComplete,
            Error::<T>::DkgSessionNotReady
        );

        // Create new Signing session
        let session = SigningSession {
            dkg_session_id,
            nft_id,
            message,
            aggregated_sig: None,
            state: SessionState::SigningInProgress,
        };

        // Generate session ID
        let session_id = Self::get_next_session_id();

        // Store the session
        SigningSessions::<T>::insert(session_id, session);

        // Emit event with both session IDs
        Self::deposit_event(Event::SigningSessionCreated(session_id, dkg_session_id));

        Ok(())
    }

    #[pallet::weight(10_000)]
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

        Self::create_signing_session(
            frame_system::RawOrigin::None.into(),
            nft_id,
            payload.message,
        )
    }

    #[pallet::weight(frame_support::weights::Weight::from_parts(10_000, 0))]
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
        
        for (_validator_id, key) in ProposedPublicKeys::<T>::iter_prefix(nft_id) {
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

            // Emit event
            Self::deposit_event(Event::DKGCompleted(session_id, aggregated_key));
        }
        Ok(())
    }

    #[pallet::weight(frame_support::weights::Weight::from_parts(10_000, 0))]
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
        Self::deposit_event(Event::DKGCompleted(session_id, bounded));
        Ok(())
    }

    #[pallet::weight(frame_support::weights::Weight::from_parts(10_000, 0))]
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
        SigningSessions::<T>::insert(session_id, session.clone());

        // Signature is already stored in session.aggregated_sig for FSA processing
        log::info!("Completed signature for session {} ready for transaction submission", session_id);

        Self::deposit_event(Event::SigningCompleted(session_id, signature));
        Ok(())
    }

    #[pallet::weight(frame_support::weights::Weight::from_parts(10_000, 0))]
    #[pallet::call_index(5)]
    pub fn create_reshare_dkg_session(
        origin: OriginFor<T>,
        nft_id: NftId,
        threshold: u32,
        old_participants: BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>,
    ) -> DispatchResult {
        let _who = ensure_signed(origin)?;

        ensure!(threshold > 0, Error::<T>::InvalidThreshold);

        // threshold needs to be an integer value between 50 and 100%
        ensure!(threshold <= 100, Error::<T>::InvalidThreshold);
        ensure!(threshold >= 50, Error::<T>::InvalidThreshold);

        // Create new reshare DKG session
        let session = DKGSession {
            nft_id,
            participants: BoundedVec::try_from(
                pallet_staking::Validators::<T>::iter()
                    .map(|(account_id, _)| account_id)
                    .collect::<Vec<T::AccountId>>(),
            )
            .unwrap(),
            threshold,
            state: SessionState::DKGCreated,
            old_participants: Some(old_participants),
            deadline: frame_system::Pallet::<T>::block_number() + 100u32.into(),
        };

        // Generate random session ID
        let session_id = Self::get_next_session_id();

        // Store the session
        DkgSessions::<T>::insert(session_id, session);
        Self::deposit_event(Event::DKGReshareSessionCreated(session_id));
        Ok(())
    }

    #[pallet::weight(frame_support::weights::Weight::from_parts(10_000, 0))]
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
    #[pallet::weight(frame_support::weights::Weight::from_parts(10_000, 0))]
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
        
        // Store the offence to be processed during on_initialize
        // PendingTssOffences::<T>::insert(
        //     payload.session_id, 
        //     (payload.offence_type.clone(), payload.offenders.clone())
        // );
        
        // Log the pending offence
        // log::info!(
        //     "[TSS] Pending offence recorded: {:?} for session {} with {} offenders", 
        //     payload.offence_type,
        //     payload.session_id,
        //     payload.offenders.len()
        // );
        
        Ok(())
    }

    /// Submit a signed transaction to a specific blockchain network
    #[pallet::weight(10_000)]
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
    #[pallet::weight(10_000)]
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

    /// Get the current nonce for an agent on a specific chain
    #[pallet::weight(10_000)]
    #[pallet::call_index(11)]
    pub fn get_agent_nonce(
        origin: OriginFor<T>,
        nft_id: NftId,
        chain_id: u32,
    ) -> DispatchResult {
        let _who = ensure_signed(origin)?;

        // Validate chain is supported
        ensure!(
            Self::is_chain_supported(chain_id),
            Error::<T>::UnsupportedChain
        );

        let _current_nonce = AgentNonces::<T>::get(&nft_id, chain_id);
        
        // In a real implementation, this would return the nonce
        // For now, we just validate the request
        Ok(())
    }

    /// Increment the nonce for an agent on a specific chain
    #[pallet::weight(10_000)]
    #[pallet::call_index(12)]
    pub fn increment_agent_nonce(
        origin: OriginFor<T>,
        nft_id: NftId,
        chain_id: u32,
    ) -> DispatchResult {
        let _who = ensure_signed(origin)?;

        // Validate chain is supported
        ensure!(
            Self::is_chain_supported(chain_id),
            Error::<T>::UnsupportedChain
        );

        // Increment nonce
        AgentNonces::<T>::mutate(&nft_id, chain_id, |nonce| *nonce += 1);

        Ok(())
    }

    /// Get the status of a multi-chain transaction
    #[pallet::weight(10_000)]
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

            // Reject all other unsigned calls
            _ => {
                return InvalidTransaction::Call.into();
            }
        }
    }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn offchain_worker(n: BlockNumberFor<T>) {
        // Check pending transactions every block for real-time monitoring
        Self::check_pending_transactions_offchain().ok();

        // Check for new validators every 10 blocks
        if n % 10u32.into() != 0u32.into() {
            return;
        }

        // Get current validators from session pallet
        let current_validators = pallet_session::Validators::<T>::get();
        // Check if there are any new validators that need IDs
        let mut new_validators = Vec::new();
        for validator in current_validators.iter() {
            if !ValidatorIds::<T>::contains_key(validator) {
                new_validators.push(validator.clone());
            }
        }

        if !new_validators.is_empty() {
            let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();

            if !signer.can_sign() {
                log::error!("TSS: No accounts available to sign update_validators");
                return;
            }

            // Include both existing and new validators in the update
            let all_validators = current_validators;

            // Send unsigned transaction with signed payload
            let _ = signer.send_unsigned_transaction(
                |acct| UpdateValidatorsPayload::<T> {
                    validators: all_validators.clone(),
                    public: acct.public.clone(),
                },
                |payload, signature| Call::update_validators { payload, signature },
            );



            // Process OPOC requests
            match Self::process_opoc_requests() {
                Ok((requests, _last_request_id)) => {
                    // loop the requests and invoke a transaction for each. THe function to call is create_signing_session
                    for (request_id, request) in requests {
                        let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
                        if !signer.can_sign() {
                            log::error!("TSS: No accounts available to sign create_signing_session");
                            return; 
                        }

                        // Store FSA transaction request data for later use
                        // Convert U256 request_id to NftId for storage
                        let nft_id_bytes: Vec<u8> = request_id.0.iter().flat_map(|&x| x.to_le_bytes()).collect();
                        if let Ok(nft_id) = BoundedVec::try_from(nft_id_bytes) {
                            // Parse the request data to extract actual chain_id and transaction data
                            // Try to use the FSA processing function to parse and extract chain_id and data
                            match Self::process_single_request(request_id.saturated_into()) {
                                Ok(Some((chain_id, tx_data))) => {
                                    // Successfully parsed FSA request with proper chain_id and transaction data
                                    if let Ok(bounded_data) = BoundedVec::try_from(tx_data) {
                                        FsaTransactionRequests::<T>::insert(&nft_id, (chain_id, bounded_data));
                                        log::info!("TSS: Stored parsed FSA transaction request for chain {} and NFT ID: {:?}", chain_id, nft_id);
                                    }
                                },
                                _ => {
                                    // Fallback: if parsing fails, treat the entire request.1 as transaction data with chain_id from request.0
                                    if let Ok(bounded_data) = BoundedVec::try_from(request.1.clone()) {
                                        FsaTransactionRequests::<T>::insert(&nft_id, (request.0, bounded_data));
                                        log::info!("TSS: Stored raw FSA transaction request for chain {} and NFT ID: {:?}", request.0, nft_id);
                                    }
                                }
                            }
                        }

                        // Convert Vec<u8> to BoundedVec<u8, MaxMessageSize>
                        let message = match BoundedVec::try_from(request.1) {
                            Ok(msg) => msg,
                            Err(_) => {
                                log::error!("TSS: Failed to convert message to BoundedVec");
                                continue;
                            }
                        };

                        let _ = signer.send_unsigned_transaction(
                            |acct| CreateSigningSessionPayload::<T> {
                                nft_id: request_id,
                                message: message.clone(),
                                public: acct.public.clone(),
                            },
                            |payload, signature| Call::create_signing_session_unsigned { payload, signature },
                        );

                    }
                }
                Err(e) => {
                    log::error!("TSS: Failed to process OPOC requests: {:?}", e);
                }
            }
        

        }

        // Rest of your existing offchain worker logic
        let stored_validators = ActiveValidators::<T>::get();
        if stored_validators.len() > 0 {
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

        // FSA: Process completed signatures and submit transactions
        Pallet::<T>::process_completed_signatures().ok();


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
        PendingTssOffences::<T>::insert(session_id, (offence_type.clone(), bounded_offenders));

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
            1 | 56 | 137 | 43114 | 42161 | 10 | 250 => {
                TransactionBuilder::build_ethereum_transaction(
                    to, value, data, gas_limit, gas_price, nonce, chain_id
                ).map_err(|_| "Failed to build transaction")
            }
            _ => Err("Chain not supported for transaction building"),
        }
    }

    /// Process any pending TSS offences stored in the PendingTssOffences storage
    pub fn process_pending_tss_offences() -> DispatchResult {
        let offences: Vec<(SessionId, (TssOffenceType, BoundedVec<T::AccountId, T::MaxNumberOfShares>))> = 
            PendingTssOffences::<T>::iter().collect();
        
        if offences.is_empty() {
            return Ok(());
        }
        
        log::info!("[TSS] Processing {} pending offences", offences.len());
        
        for (session_id, (offence_type, offenders)) in offences {
            // For now, just log the offence - the actual processing can be implemented later
            log::info!("[TSS] Processing offence {:?} for session {} with {} offenders", 
                offence_type, session_id, offenders.len());
            
            // Remove the processed offence
            PendingTssOffences::<T>::remove(session_id);
        }
        
        Ok(())
    }

    /// Helper function to get pending transaction data for an NFT ID
    pub fn get_pending_transaction_data(nft_id: &NftId) -> Option<(u32, Vec<u8>)> {
        FsaTransactionRequests::<T>::get(nft_id).map(|(chain_id, bounded_data)| {
            (chain_id, bounded_data.into_inner())
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
            
            // Get FSA transaction request data from the session's NFT ID
            if let Some((chain_id, tx_data_bounded)) = FsaTransactionRequests::<T>::get(&session.nft_id) {
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
                FsaTransactionRequests::<T>::remove(&session.nft_id);
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
                
                // Remove from pending and update status (this will be done via unsigned transaction)
                // For now, just log the timeout
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
        // Combine transaction data with signature to create final signed transaction
        let mut signed_transaction = tx_data.to_vec();
        signed_transaction.extend_from_slice(signature);

        // Submit via FSA module
        match crate::fsa::submit_transaction_to_chain(chain_id, &signed_transaction) {
            Ok(response) => {
                match response.tx_hash {
                    Some(hash) => {
                        log::info!("[FSA] Transaction submitted successfully for session {}", session_id);
                        // Convert string tx_hash to BoundedVec<u8>
                        let tx_hash_bytes = hash.as_bytes();
                        match BoundedVec::try_from(tx_hash_bytes.to_vec()) {
                            Ok(bounded_hash) => Some(bounded_hash),
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

        /// Report TSS offence from runtime API
        fn report_tss_offence(
            session_id: SessionId,
            offence_type: u8, // Encoded TssOffenceType
            offenders: Vec<[u8; 32]>,
        );
    }
}

impl<T: Config> uomi_primitives::TssInterface<T> for Pallet<T> {
    fn create_agent_wallet(nft_id: sp_core::U256, threshold: u8) -> frame_support::pallet_prelude::DispatchResult {
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
    
    fn agent_wallet_exists(nft_id: sp_core::U256) -> bool {
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
    
    fn get_agent_wallet_address(nft_id: sp_core::U256) -> Option<sp_core::H160> {
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

