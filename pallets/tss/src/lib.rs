#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use core::fmt::Debug;
use frame_support::pallet_prelude::*;
pub mod types;

use frame_support::inherent::{InherentData, InherentIdentifier, IsFatalError, ProvideInherent};
use frame_system::ensure_signed;
use frame_system::offchain::{AppCrypto, SignedPayload, Signer, SigningTypes};
use frame_system::pallet_prelude::{BlockNumberFor, OriginFor};
use pallet_uomi_engine::crypto::Public;
use scale_info::TypeInfo;
use sp_runtime::offchain::storage::StorageValueRef;
use sp_std::vec;
use sp_std::vec::Vec;
use types::{Key, MaxMessageSize, PublicKey, SessionId, Share, Signature};
use frame_system::offchain::SendUnsignedTransaction;
pub use pallet::*;
use pallet_staking::Validators;


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
    public: T::Public
}

impl<T: SigningTypes + Config> SignedPayload<T> for UpdateValidatorsPayload<T> {
    fn public(&self) -> T::Public {
        self.public.clone()
    }
}

#[frame_support::pallet]
pub mod pallet {

    use frame_system::offchain::CreateSignedTransaction;

    use crate::types::NftId;

    use super::*;
    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config:
        frame_system::Config + TypeInfo + frame_system::offchain::SigningTypes + Debug +
        pallet_uomi_engine::pallet::Config +
        CreateSignedTransaction<Call<Self>> 

    {
        // Events emitted by the pallet.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        #[pallet::constant]
        type MaxNumberOfShares: Get<u32>;

        // type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
        
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
    }

    #[pallet::storage]
    #[pallet::getter(fn get_tss_key)]
    pub type TSSKey<T: Config> = StorageValue<_, Key, ValueQuery>;

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

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new TSS key has been set.
        DKGSessionCreated(SessionId),
        SigningSessionCreated(SessionId)
    }



    #[pallet::error]
    pub enum Error<T> {
        KeyUpdateFailed,
        DuplicateParticipant,
        InvalidParticipantsCount,
        InvalidThreshold,
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

            // Create new DKG session
            let session = DKGSession {
                nft_id,
                participants: BoundedVec::try_from(pallet_staking::Validators::<T>::iter().map(|(account_id, _)| account_id).collect::<Vec<T::AccountId>>()).unwrap(),
                threshold,
                state: SessionState::DKGCreated,
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
            ensure_signed(origin)?;

            let new_validators = payload.validators;
            ActiveValidators::<T>::put(BoundedVec::try_from(new_validators.clone()).unwrap());

            // log::info!("[TSS] Stored new validators");

            // Self::deposit_event(Event::ValidatorsUpdated(new_validators));
            Ok(())
        }
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
                    // log::info!("[TSS] We like this");

                    return ValidTransaction::with_tag_prefix("TssPallet")
                    .priority(TransactionPriority::MAX)
                    .and_provides(INHERENT_IDENTIFIER)
                    .longevity(64)
                    .propagate(true)
                    .build()},

                // Reject all other unsigned calls
                _ => {
                    // log::info!("[TSS] We DO NOT like this");
                    return InvalidTransaction::Call.into()
                },
            }
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(n: BlockNumberFor<T>) {

            // log::info!("[TSS] Block number {:?}", n);

            if n % 10u32.into() != 0u32.into() {
                return;
            }

            // log::info!("[TSS] Checking if there's need for new set of validators {:?}", n);

            let signer = Signer::<T, T::AuthorityId>::all_accounts();

            if !signer.can_sign() {
                log::error!("TSS: No accounts available to sign update_validators");
                return;
            }

            let new_validators: sp_std::vec::Vec<T::AccountId> = pallet_uomi_engine::Pallet::<T>::get_active_validators();

            let stored_validators = ActiveValidators::<T>::get();
            // log::info!("[TSS] Current validators lentgh {:?}, while new validators length {:?}", stored_validators.len(), new_validators.len());

            if stored_validators.len() > 0 {
                return;
            }

            // log::info!("[TSS] Setting new validators {:?}", n);


            // //send unsigned transaction with signed payload
            // let _ = signer.send_unsigned_transaction(
            //     |acct| UpdateValidatorsPayload::<T> {
            //         validators: new_validators.clone(),
            //         public: acct.public.clone(),
            //     },
            //     |payload, signature| Call::update_validators { payload, signature }
            // );
        }
    }
}

sp_api::decl_runtime_apis! {
    pub trait TssApi {
        fn get_dkg_session_threshold(id:SessionId) -> u32;
        fn get_dkg_session_participants(id:SessionId) -> Vec<[u8; 32]>;
        fn get_dkg_session_participant_index(id:SessionId, account_id: [u8; 32]) -> u32;
        fn get_dkg_session_participants_count(id:SessionId) -> u16;
    }
}
