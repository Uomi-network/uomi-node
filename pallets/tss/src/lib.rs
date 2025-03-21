#![cfg_attr(not(feature = "std"), no_std)]
use scale_info::prelude::*;
use sp_runtime::KeyTypeId;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use core::fmt::Debug;
use frame_support::pallet_prelude::*;
use sp_std::prelude::*;
pub mod types;

use frame_support::inherent::{InherentIdentifier, IsFatalError};
use frame_system::offchain::SendUnsignedTransaction;
use frame_system::offchain::{SignedPayload, Signer, SigningTypes};
use frame_system::pallet_prelude::{BlockNumberFor, OriginFor};
use frame_system::{ensure_none, ensure_signed};
use scale_info::TypeInfo;

pub use pallet::*;
use sp_std::vec;
use sp_std::vec::Vec;
use types::{Key, SessionId};



#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
pub struct EmptyInherent;

// Prima delle implementazioni del pallet, aggiungi:
#[derive(Encode)]
#[cfg_attr(feature = "std", derive(Debug, Decode))]
pub enum InherentError {
    // Definisci qui i tuoi errori specifici
    InvalidInherentValue,
}

impl IsFatalError for InherentError {
    fn is_fatal_error(&self) -> bool {
        match self {
            InherentError::InvalidInherentValue => true,
        }
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct UpdateValidatorsPayload<T: Config> {
    validators: Vec<T::AccountId>,
    public: T::Public,
}

impl<T: SigningTypes + Config> SignedPayload<T> for UpdateValidatorsPayload<T> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

pub const CRYPTO_KEY_TYPE: KeyTypeId = KeyTypeId(*b"tss-");

//////////////////////////////////////////////////////////////////////////////////
// CRYPTO MODULE /////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
pub mod crypto {
    use crate::CRYPTO_KEY_TYPE;
    use sp_core::sr25519::Signature as Sr25519Signature;
    use sp_runtime::app_crypto::{ app_crypto, sr25519 };
    use sp_runtime::{ traits::Verify, MultiSignature, MultiSigner };


    app_crypto!(sr25519, CRYPTO_KEY_TYPE);

    pub struct AuthId;

    // implemented for ocw-runtime
    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for AuthId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }

    // implemented for mock runtime in test
    impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
    for AuthId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::sr25519::Signature;
        type GenericPublic = sp_core::sr25519::Public;
    }
}


#[frame_support::pallet]
pub mod pallet {

    use frame_system::offchain::{AppCrypto, CreateSignedTransaction};
    use sp_runtime::traits::Verify;

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
        + CreateSignedTransaction<Call<Self>>
    {
        // Events emitted by the pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        #[pallet::constant]
        type MaxNumberOfShares: Get<u32>;
        type SignatureVerifier: SignatureVerification<PublicKey>;

        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
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

    #[derive(Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SessionState {
        DKGCreated,
        DKGInProgress,
        DKGComplete,
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

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new TSS key has been set.
        DKGSessionCreated(SessionId),
        DKGReshareSessionCreated(SessionId),
        SigningSessionCreated(SessionId, SessionId), // Signing session ID, DKG session ID
        DKGCompleted(SessionId, PublicKey),                // Aggregated public key
        SigningCompleted(SessionId, Signature),      // Final aggregated signature
        SignatureSubmitted(SessionId),               // When signature is stored
        ValidatorIdAssigned(T::AccountId, u32),      // Validator account, ID
    }

    #[pallet::error]
    pub enum Error<T> {
        KeyUpdateFailed,
        DuplicateParticipant,
        InvalidParticipantsCount,
        InvalidThreshold,
        DkgSessionNotFound,
        DkgSessionNotReady,
        InvalidSignature,
        UnauthorizedParticipation,
        AggregatedKeyAlreadySubmitted,
        StaleDkgSession,
        InvalidSessionState,
        SigningSessionNotFound,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(10_000)]
        #[pallet::call_index(0)]
        pub fn create_dkg_session(
            origin: OriginFor<T>,
            nft_id: NftId,
            threshold: u32,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            ensure!(threshold > 0, Error::<T>::InvalidThreshold);

            // threshold needs to be an integer value between 50 and 100%
            ensure!(threshold <= 100, Error::<T>::InvalidThreshold);
            ensure!(threshold >= 50, Error::<T>::InvalidThreshold);

            // Create new DKG session
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
                old_participants: None,
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
            origin: OriginFor<T>,
            nft_id: NftId,
            message: BoundedVec<u8, MaxMessageSize>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

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
            // ensure!(
            //     dkg_session.state == SessionState::DKGComplete,
            //     Error::<T>::DkgSessionNotReady
            // );

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

        #[pallet::call_index(3)]
        #[pallet::weight(10_000)]
        pub fn submit_dkg_result(
            origin: OriginFor<T>,
            session_id: SessionId,
            aggregated_key: PublicKey,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut session =
                DkgSessions::<T>::get(session_id).ok_or(Error::<T>::DkgSessionNotFound)?;

            // Verify submitter was part of DKG session
            ensure!(
                session.participants.contains(&who),
                Error::<T>::UnauthorizedParticipation
            );

            // Store aggregated key
            AggregatedPublicKeys::<T>::insert(session_id, aggregated_key.clone());
            session.state = SessionState::DKGComplete;
            DkgSessions::<T>::insert(session_id, session);

            // Update TSS key if this is the latest session.
            TSSKey::<T>::put(aggregated_key.clone());

            Self::deposit_event(Event::DKGCompleted(session_id, aggregated_key));
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
            };

            // Generate random session ID
            let session_id = Self::get_next_session_id();

            // Store the session
            DkgSessions::<T>::insert(session_id, session);
            Self::deposit_event(Event::DKGReshareSessionCreated(session_id));
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

    pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"tss-iden";

    // #[pallet::inherent]
    // impl<T: Config> ProvideInherent for Pallet<T> {
    //     type Call = Call<T>;
    //     type Error = InherentError;
    //     const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

    //     fn create_inherent(_data: &InherentData) -> Option<Self::Call> {
    //         let current_block_number = frame_system::Pallet::<T>::block_number().into();
    // //         log::info!("IPFS: Creating inherent data for block number: {:?}", current_block_number);

    //         let operations = match Self::ipfs_operations(current_block_number) {
    //             Ok(operations) => { operations }
    //             Err(error) => {
    // //                 log::info!("IPFS: Failed to run ipfs_operations. error: {:?}", error);
    //                 return None;
    //             }
    //         };

    //         Some(Call::set_inherent_data {
    //             operations,
    //         })
    //     }

    //     fn is_inherent(call: &Self::Call) -> bool {
    //         matches!(call, Call::set_inherent_data { .. })
    //     }

    // }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            // log::info!("[TSS] Validating unsigned");
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

            // Get current validators from staking pallet
            let current_validators: Vec<T::AccountId> = pallet_staking::Validators::<T>::iter()
                .map(|(account_id, _)| account_id)
                .collect();
            // Check if there are any new validators that need IDs
            let mut new_validators = Vec::new();
            for validator in current_validators.iter() {
                if !ValidatorIds::<T>::contains_key(validator) {
                    new_validators.push(validator.clone());
                }
            }
            
            if !new_validators.is_empty() {
                log::info!(
                    "[TSS] Found {} new validators that need IDs",
                    new_validators.len()
                );

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
            }

            // Rest of your existing offchain worker logic
            let stored_validators = ActiveValidators::<T>::get();
            if stored_validators.len() > 0 {
                return;
            }

            // If no active validators are set, initialize them
            log::info!("[TSS] Setting new validators at block {:?}", n);
        }

        // Add on_initialize hook to handle validator initialization
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            // Check if validator IDs have been initialized
            if NextValidatorId::<T>::get() == 0 {
                // Initialize with ID 1
                NextValidatorId::<T>::put(1);
            }

            // Return weight for this operation (minimal)
            T::DbWeight::get().reads(1) + T::DbWeight::get().writes(1)
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn initialize_validator_ids() -> DispatchResult {
            // Get all validators from pallet_staking
            let validators: Vec<T::AccountId> = pallet_staking::Validators::<T>::iter()
                .map(|(account_id, _)| account_id)
                .collect();

            let mut next_id = 1u32; // Start IDs from 1

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
            log::info!("[TSS] Validator ID assigned: {:?}", validator);
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
    }
}


sp_api::decl_runtime_apis! {
    pub trait TssApi {
        fn get_dkg_session_threshold(id: SessionId) -> u32;
        fn get_dkg_session_participants(id: SessionId) -> Vec<[u8; 32]>;
        fn get_dkg_session_participant_index(id: SessionId, account_id: [u8; 32]) -> u32;
        fn get_dkg_session_participants_count(id: SessionId) -> u16;
        fn get_dkg_session_old_participants(id: SessionId) -> Vec<[u8; 32]>;
        fn get_signing_session_message(id: SessionId) -> Vec<[u8; 32]>;

        fn get_validator_id(account_id: [u8; 32]) -> Option<u32>;
        fn get_validator_by_id(id: u32) -> Option<[u8; 32]>;
        fn get_all_validator_ids() -> Vec<(u32, [u8; 32])>;
    }
}


