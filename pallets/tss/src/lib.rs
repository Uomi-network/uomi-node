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

use core::fmt::Debug;
use frame_support::pallet_prelude::*;
use sp_std::prelude::*;
pub mod types;
use frame_support::BoundedVec;

use frame_support::inherent::IsFatalError;
use frame_system::offchain::SendUnsignedTransaction;
use frame_system::offchain::{SignedPayload, Signer};
use frame_system::pallet_prelude::{BlockNumberFor, OriginFor};
use frame_system::{ensure_none, ensure_signed};
use scale_info::TypeInfo;

pub use pallet::*;
use sp_std::vec;
use sp_std::vec::Vec;
use types::SessionId;
pub use payloads::*;

// Inherent error definitions:
#[derive(Encode)]
#[cfg_attr(feature = "std", derive(Debug, Decode))]
pub enum InherentError {
    // Define your specific errors here
    InvalidInherentValue,
}

impl IsFatalError for InherentError {
    fn is_fatal_error(&self) -> bool {
        match self {
            InherentError::InvalidInherentValue => true,
        }
    }
}


pub const CRYPTO_KEY_TYPE: KeyTypeId = KeyTypeId(*b"tss-");


#[frame_support::pallet]
pub mod pallet {

    use frame_system::offchain::{AppCrypto, CreateSignedTransaction};
    use sp_runtime::traits::{IdentifyAccount, Verify};

    use crate::types::{MaxMessageSize, NftId, PublicKey, Signature};

    use super::*;
    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config:
        frame_system::Config
        + TypeInfo
        + frame_system::offchain::SigningTypes
        + Debug
        + pallet_uomi_engine::pallet::Config
        + pallet_session::Config<ValidatorId = <Self as frame_system::Config>::AccountId>
        + CreateSignedTransaction<Call<Self>>
    {
        // Events emitted by the pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        #[pallet::constant]
        type MaxNumberOfShares: Get<u32>;
        type SignatureVerifier: SignatureVerification<PublicKey>;

        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

        #[pallet::constant]
        type MinimumValidatorThreshold: Get<u32>;
    }

    pub trait SignatureVerification<PublicKey> {
        fn verify(key: &PublicKey, message: &[u8], sig: &Signature) -> bool;
    }

    pub struct Verifier {}
    impl SignatureVerification<PublicKey> for Verifier {
        fn verify(key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
            // Convert PublicKey to [u8; 33] for ECDSA public key
            let pubkey_bytes: [u8; 33] = match key.as_slice().try_into() {
                Ok(bytes) => bytes,
                Err(_) => return false, // Public key must be exactly 33 bytes
            };
            let pubkey = sp_core::ecdsa::Public(pubkey_bytes);

            // Convert Signature to [u8; 65] for ECDSA signature
            let signature_bytes: [u8; 65] = match sig.as_slice().try_into() {
                Ok(bytes) => bytes,
                Err(_) => return false, // Signature must be exactly 65 bytes
            };
            let signature = sp_core::ecdsa::Signature(signature_bytes);

            // Verify the signature; it hashes the message internally with blake2_256
            signature.verify(message, &pubkey)
        }
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
        
        /// Multi-chain transaction events
        MultiChainTransactionSubmitted(u32, Vec<u8>), // Chain ID, Transaction hash
        MultiChainTransactionConfirmed(u32, Vec<u8>), // Chain ID, Transaction hash
        MultiChainTransactionFailed(u32, Vec<u8>),    // Chain ID, Transaction hash
        ChainConfigurationUpdated(u32),               // Chain ID updated
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
        #[pallet::weight(10_000)]
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

        #[pallet::weight(10_000)]
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

        #[pallet::weight(10_000)]
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

        #[pallet::call_index(3)]
        #[pallet::weight(10_000)]
        pub fn submit_dkg_result(
            origin: OriginFor<T>,
            payload: SubmitDKGResultPayload<T>,
            _signature: T::Signature,
        ) -> DispatchResult {
            ensure_none(origin)?;


            let who = payload.public().into_account();
            let session_id = payload.session_id;
            let aggregated_key = payload.public_key;


            let mut session =
                DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

            ensure!(
                session.state <= SessionState::DKGInProgress,
                Error::<T>::InvalidSessionState
            );

            // Get the NFT ID from the session
            let nft_id = session.nft_id.clone();

            // Check if the validator was involved in the DKG session
            let validator_id = ValidatorIds::<T>::get(who.clone()).ok_or(Error::<T>::UnauthorizedParticipation)?;
            ensure!(
                session.participants.contains(&who),
                Error::<T>::UnauthorizedParticipation
            );

            // Add the vote to the proposed public keys
            ProposedPublicKeys::<T>::insert(nft_id.clone(), validator_id, aggregated_key.clone());

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

        #[pallet::call_index(4)]
        #[pallet::weight(10_000)]
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
            SigningSessions::<T>::insert(session_id, session);

            Self::deposit_event(Event::SigningCompleted(session_id, signature));
            Ok(())
        }

        #[pallet::weight(10_000)]
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

        #[pallet::weight(10_000)]
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

        /// Submit a signed transaction to a specific blockchain network
        #[pallet::weight(10_000)]
        #[pallet::call_index(8)]
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
        #[pallet::call_index(9)]
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
        #[pallet::call_index(10)]
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
        #[pallet::call_index(11)]
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
    }
    fn verify_signature<T: Config>(key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
        T::SignatureVerifier::verify(key, message, sig)
    }

    impl<T: Config> Pallet<T> {
        pub fn get_next_session_id() -> SessionId {
            let session_id = Self::next_session_id();
            NextSessionId::<T>::put(session_id + 1);

            session_id
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
                Call::create_signing_session_unsigned { .. } => {
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
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            // Check if validator IDs have been initialized
            if NextValidatorId::<T>::get() == 0 {
                // Initialize with ID 1
                NextValidatorId::<T>::put(1);
            }

            // Check expired sessions 
            Pallet::<T>::check_expired_sessions(n).ok();

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

            // Return weight for this operation (including potential DKG regeneration)
            T::DbWeight::get().reads(3) + T::DbWeight::get().writes(3)
        }
    }

    impl<T: Config> Pallet<T> {

        pub fn check_expired_sessions(n: BlockNumberFor<T>) -> DispatchResult {
            // Fetch all the sessions in progress and verify if they are still valid or deadline has passed
            let mut sessions_to_remove = Vec::new();
            for (session_id, session) in DkgSessions::<T>::iter() {
                // Check if the session is in progress and if the deadline has passed
                if session.state <= SessionState::DKGInProgress {
                    let deadline = session.deadline;
                    if n >= deadline {
                        sessions_to_remove.push(session_id);
                    }
                }
            }
            
            for session_id in sessions_to_remove {
                Pallet::<T>::update_report_count(session_id).ok();
                Pallet::<T>::deposit_event(Event::DKGFailed(session_id));
                DkgSessions::<T>::remove(session_id);
            }

            Ok(())
        }
        pub fn update_report_count(session_id: SessionId) -> DispatchResult {
            // Get the session
            let session =
                DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

            // First set the session state to DKGFailed
            DkgSessions::<T>::mutate(session_id, |session| {
                if let Some(s) = session {
                    s.state = SessionState::DKGFailed;
                }
            });

            // Get the total number of participants in the session
            let total_participants = session.participants.len();

            // Iterate over all reported participants for this session
            for (_reporter, reported_list) in ReportedParticipants::<T>::iter_prefix(session_id) {
                // Iterate over each reported participant
                for reported_participant in reported_list.iter() {
                    // Count how many times this participant has been reported
                    let mut report_count = 0;
                    for (_, inner_reported_list) in
                        ReportedParticipants::<T>::iter_prefix(session_id)
                    {
                        if inner_reported_list.contains(reported_participant) {
                            report_count += 1;
                        }
                    }

                    // Calculate the threshold for reporting (2/3 of total participants)
                    let reporting_threshold = (total_participants * 2) / 3;

                    // Check if the participant has been reported by more than 2/3 of the participants
                    if report_count == reporting_threshold {
                        // Increment the report count for this participant
                        let current_count = ParticipantReportCount::<T>::get(reported_participant);
                        ParticipantReportCount::<T>::insert(
                            reported_participant,
                            current_count + 1,
                        );
                    }
                }
            }
            Ok(())
        }

        pub fn initialize_validator_ids() -> DispatchResult {
            // Get all validators from pallet_staking
            let validators: Vec<T::AccountId> = ActiveValidators::<T>::get().to_vec();

            let mut next_id = NextValidatorId::<T>::get();

            // Assign IDs to validators that don't have one yet
            for validator in validators {
                if !ValidatorIds::<T>::contains_key(&validator) {
                    ValidatorIds::<T>::insert(&validator, next_id);
                    IdToValidator::<T>::insert(next_id, validator.clone());
                    Self::deposit_event(Event::ValidatorIdAssigned(validator, next_id));
                    next_id += 1;
                }
            }

            // Update the next validator ID
            NextValidatorId::<T>::put(next_id);

            Ok(())
        }

        // Add this function to assign an ID to a new validator
        pub fn assign_validator_id(validator: T::AccountId) -> DispatchResult {
            // Check if the validator already has an ID
            if ValidatorIds::<T>::contains_key(&validator) {
                return Ok(());
            }

            // Get the next ID
            let next_id = Self::next_validator_id();

            // Assign the ID
            ValidatorIds::<T>::insert(&validator, next_id);
            IdToValidator::<T>::insert(next_id, validator.clone());

            // Increment the next ID
            NextValidatorId::<T>::put(next_id + 1);

            // Emit event, maybe the client can use it?
            Self::deposit_event(Event::ValidatorIdAssigned(validator, next_id));

            Ok(())
        }

        // Helper public function used in runtime impl.
        pub fn get_validator_id(validator: &T::AccountId) -> Option<u32> {
            ValidatorIds::<T>::get(validator)
        }

        // Helper public function used in runtime impl.
        pub fn get_validator_from_id(id: u32) -> Option<T::AccountId> {
            IdToValidator::<T>::get(id)
        }

        // A function that returns those validators that have been reported more then 3 times:
        pub fn get_slashed_validators() -> Vec<T::AccountId> {
            let mut slashed_validators = Vec::new();
            for (validator, report_count) in ParticipantReportCount::<T>::iter() {
                if report_count > 0 {
                    slashed_validators.push(validator);
                }
            }
            slashed_validators
        }

        /// Reset report counts for all validators at the end of an era
        pub fn reset_validator_report_counts() -> DispatchResult {
            log::info!("[TSS] Resetting validator report counts at era end");
            
            // Get all validators with report counts
            let reported_validators: Vec<(T::AccountId, u32)> = ParticipantReportCount::<T>::iter()
                .filter(|(_, count)| *count > 0)
                .collect();
            
            // Log detailed information about validators being reset
            if !reported_validators.is_empty() {
                log::info!(
                    "[TSS] Resetting report counts for {} validators",
                    reported_validators.len()
                );
                
                for (validator, count) in reported_validators.iter() {
                    log::info!(
                        "[TSS] Resetting validator {:?} with report count {}",
                        validator,
                        count
                    );
                    ParticipantReportCount::<T>::insert(validator, 0);
                }
            } else {
                log::info!("[TSS] No validators with positive report counts to reset");
            }
            
            Ok(())
        }

        pub fn report_participants(id: SessionId, reported_participants: Vec<[u8; 32]>) {
            log::info!(
                "[TSS] Reporting participants... {:?}",
                reported_participants
            );
            // Create a transaction to submit
            let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();

            if !signer.can_sign() {
                log::error!("TSS: No accounts available to sign report_participant");
                return;
            }
            let reported_participants_bounded = BoundedVec::try_from(
                reported_participants
                    .iter()
                    .map(|x| T::AccountId::decode(&mut &x[..]).unwrap())
                    .collect::<Vec<T::AccountId>>(),
            )
            .unwrap();
            log::info!("[TSS] Sending.... {:?}", reported_participants_bounded);

            // Send unsigned transaction with signed payload
            let _ = signer.send_unsigned_transaction(
                |acct| ReportParticipantsPayload::<T> {
                    session_id: id,
                    reported_participants: reported_participants_bounded.clone(),
                    public: acct.public.clone(),
                },
                |payload, signature| Call::report_participant { payload, signature },
            );
            log::info!("[TSS] Reported participants");
        }

        // cast_vote_on_dkg_result is called by each validator and created. This function will sign the payload
        // and call submit_dkg_result with the signature
        pub fn cast_vote_on_dkg_result(
            session_id: SessionId,
            aggregated_key: Vec<u8>,
        ) -> DispatchResult {
            let aggregated_key = BoundedVec::try_from(aggregated_key)
                .map_err(|_| Error::<T>::InvalidParticipantsCount)?;
            
            // Check if the session exists
            let session =
                DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

            // Check if the session is in progress
            ensure!(
                session.state == SessionState::DKGInProgress,
                Error::<T>::InvalidSessionState
            );

            // Create a transaction to submit
            let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();

            if !signer.can_sign() {
                log::error!("TSS: No accounts available to sign cast_vote_on_dkg_result");
                return Err(Error::<T>::KeyUpdateFailed.into());
            }

            // Send unsigned transaction with signed payload
            let _ = signer.send_unsigned_transaction(
                |acct| SubmitDKGResultPayload::<T> {
                    session_id,
                    public_key: aggregated_key.clone(),
                    public: acct.public.clone(),
                },
                |payload, signature| Call::submit_dkg_result { payload, signature },
            );

            Ok(())
        }

        pub fn finalize_dkg_session(
            session_id: SessionId,
            aggregated_key: Vec<u8>,
        ) -> DispatchResult {

            let aggregated_key = BoundedVec::try_from(aggregated_key)
                .map_err(|_| Error::<T>::InvalidParticipantsCount)?;
            
            // Check if the session exists and is in the correct state
            let session =
                DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

            ensure!(
                session.state == SessionState::DKGInProgress,
                Error::<T>::InvalidSessionState
            );

            // Update the session state to DKGComplete
            DkgSessions::<T>::mutate(session_id, |session| {
                if let Some(s) = session {
                    s.state = SessionState::DKGComplete;
                }
            });

            // Store the aggregated public key
            AggregatedPublicKeys::<T>::insert(session_id, aggregated_key.clone());

            // Emit event with the session ID and aggregated key
            Self::deposit_event(Event::DKGCompleted(session_id, aggregated_key));

            Ok(())
        }

        // Within your pallet's dispatchable function or helper method
        fn get_current_era() -> Option<u32> {
            // Access the current era from the Staking pallet
            pallet_staking::CurrentEra::<T>::get()
        }

        /// Handle era transition: check for validator changes and trigger DKG reshare if needed
        pub fn handle_era_transition(current_era: u32) -> DispatchResult {
            log::debug!("TSS: Handling era transition to era {}", current_era);
            
            // Get current and previous validator sets
            let current_validators = ActiveValidators::<T>::get();
            let previous_validators = PreviousEraValidators::<T>::get();
            
            // Compare validator sets to detect changes
            let validators_changed = current_validators.len() != previous_validators.len() ||
                !current_validators.iter().all(|v| previous_validators.contains(v));
            
            if validators_changed {
                log::info!("TSS: Validator set changed at era {}, triggering DKG reshare", current_era);
                
                // Check if we have an existing TSS key that requires resharing
                let has_existing_key = !TSSKey::<T>::get().is_empty();

                if has_existing_key && !previous_validators.is_empty() {
                    // Create reshare DKG session for the validator set change
                    Self::create_reshare_session_for_validator_change(&previous_validators)?;
                    log::info!("TSS: Reshare DKG session created for validator set change");
                } else {
                    log::info!("TSS: No existing TSS key or no previous validators, skipping reshare");
                }
            } else {
                log::debug!("TSS: No validator set changes detected at era {}", current_era);
            }
            
            // Update stored validator set for next era comparison
            PreviousEraValidators::<T>::put(current_validators);
            
            Ok(())
        }

        /// Create a reshare DKG session for validator set changes
        fn create_reshare_session_for_validator_change(
            old_participants: &BoundedVec<T::AccountId, <T as Config>::MaxNumberOfShares>
        ) -> DispatchResult {
            // For validator set changes, we need to reshare ALL existing agent keys
            // Find all active DKG sessions that have completed and need resharing
            let mut reshare_created = false;
            
            for (_session_id, session) in DkgSessions::<T>::iter() {
                if session.state == SessionState::DKGComplete {
                    // Create a reshare session for this specific agent/NFT
                    let threshold = session.threshold;
                    let origin = frame_system::RawOrigin::None.into();
                    
                    if let Err(e) = Self::create_reshare_dkg_session(
                        origin,
                        session.nft_id.clone(),
                        threshold,
                        old_participants.clone(),
                    ) {
                        log::error!("TSS: Failed to create reshare session for NFT {:?}: {:?}", session.nft_id, e);
                    } else {
                        log::info!("TSS: Created reshare session for NFT {:?}", session.nft_id);
                        reshare_created = true;
                    }
                }
            }
            
            if !reshare_created {
                log::warn!("TSS: No completed DKG sessions found to reshare during validator set change");
            }
            
            Ok(())
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
                Ok(TransactionBuilder::build_ethereum_transaction(
                    to, value, data, gas_limit, gas_price, nonce, chain_id
                ))
            }
            _ => Err("Chain not supported for transaction building"),
        }
    }
}
